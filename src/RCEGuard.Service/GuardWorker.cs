using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting.WindowsServices;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service;

/// <summary>
/// The guard loop: subscribes to the Sysmon log, evaluates every new event and acts on the findings.
/// Events are handled one at a time in log order, because the rule engine keeps state. The position
/// of the last handled event is saved, so that after a restart the events written in the meantime
/// are read first.
/// </summary>
public sealed class GuardWorker : BackgroundService
{
    private static readonly TimeSpan HostRefreshInterval = TimeSpan.FromMinutes(10);

    /// <summary>The position is saved at once after a finding, otherwise at most this often.</summary>
    private static readonly TimeSpan PositionSaveInterval = TimeSpan.FromSeconds(1);

    private readonly ServiceOptions options;
    private readonly ILogger<GuardWorker> logger;
    private readonly IHostApplicationLifetime lifetime;
    private readonly Channel<LogEntry> events = Channel.CreateUnbounded<LogEntry>(new UnboundedChannelOptions { SingleReader = true });
    private FindingDebouncer debouncer = new(TimeSpan.Zero);
    private bool positionSaveFailed;

    /// <summary>Creates the worker.</summary>
    public GuardWorker(ServiceOptions options, ILogger<GuardWorker> logger, IHostApplicationLifetime lifetime)
    {
        this.options = options;
        this.logger = logger;
        this.lifetime = lifetime;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RunAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            // Fail loudly: a guard that silently watches nothing is worse than one that is not running.
            if (ex is ChannelClosedException { InnerException: { } cause })
            {
                ex = cause;
            }

            logger.LogCritical("RCEGuard cannot run: {Reason}", Explain(ex));
            if (WindowsServiceHelpers.IsWindowsService())
            {
                // Ending the process without reporting "stopped" is what Windows counts as a failure:
                // only then do the recovery actions of the service (restart) apply.
                Environment.Exit(1);
            }

            Environment.ExitCode = 1;
            lifetime.StopApplication();
        }
    }

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        var config = options.LoadConfig(out var configSource);
        // A replay is about old events: their pids mean nothing any more, so it never terminates anything.
        var killEnabled = config.KillEnabled && !options.DryRun && options.ReplayPath is null;
        var engine = new RuleEngine(config, Environment.SystemDirectory);
        var killer = new ProcessKiller(dryRun: !killEnabled);
        debouncer = new FindingDebouncer(TimeSpan.FromSeconds(config.RepeatWindowSeconds));
        using var store = new FindingStore(Path.Combine(options.DataDirectory, "findings.db"));

        foreach (var profile in config.Profiles)
        {
            logger.LogInformation(
                "Watching '{Name}': {Client} ({Count} allowed remote entries, {Hosts} host names)",
                profile.Name, profile.ClientPath, profile.AllowedRemote.Count, profile.AllowedHostnames.Count);
        }

        logger.LogInformation("Configuration from {Source}; terminating processes is {State}", configSource, killEnabled ? "ON" : "OFF (dry run)");

        if (options.ReplayPath is not null)
        {
            Replay(options.ReplayPath, engine, store);
            lifetime.StopApplication();
            return;
        }

        // Fail closed: the watcher itself accepts a missing or unreadable log and then just delivers nothing.
        // Asking for the log's properties and reading its ends throws in both cases.
        using (var session = new EventLogSession())
        {
            _ = session.GetLogInformation(options.LogName, PathType.LogName);
        }

        var positionFile = new LogPositionFile(Path.Combine(options.DataDirectory, ServiceOptions.PositionFileName));
        var plan = PlanResume(positionFile, out var newestAtStart);

        // The host names must be known before old events are evaluated, or their connections would all look unknown.
        await RefreshHostsAsync(config, engine, stoppingToken);
        var nextHostRefresh = DateTimeOffset.UtcNow + HostRefreshInterval;

        using var tail = new EventLogTail(
            options.LogName,
            plan.StartAfterRecordId,
            entry => events.Writer.TryWrite(entry),
            // The subscription is broken (log removed, Sysmon uninstalled, access lost). Closing the
            // channel with the error ends the guard loop instead of leaving it waiting for nothing.
            error => events.Writer.TryComplete(error));
        tail.Start();
        logger.LogInformation("Subscribed to {Log}; waiting for events", options.LogName);

        LogPosition? unsaved = null;
        var sinceSave = Stopwatch.StartNew();
        var catchingUp = plan.Pending > 0;
        var caughtUpFindings = 0;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                if (DateTimeOffset.UtcNow >= nextHostRefresh)
                {
                    await RefreshHostsAsync(config, engine, stoppingToken);
                    nextHostRefresh = DateTimeOffset.UtcNow + HostRefreshInterval;
                }

                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                wait.CancelAfter(unsaved is null ? TimeSpan.FromSeconds(30) : PositionSaveInterval);
                LogEntry entry;
                try
                {
                    entry = await events.Reader.ReadAsync(wait.Token);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    // Only woke up to save the position or to check the host refresh.
                    SavePosition(positionFile, ref unsaved, sinceSave);
                    continue;
                }

                var late = catchingUp && entry.Position.RecordId <= newestAtStart;
                var findings = Handle(entry.Xml, engine, killer, store, late);
                unsaved = entry.Position;
                if (findings > 0 || sinceSave.Elapsed >= PositionSaveInterval)
                {
                    // After a finding at once: read a second time, the event would be reported and acted on again.
                    SavePosition(positionFile, ref unsaved, sinceSave);
                }

                if (catchingUp)
                {
                    caughtUpFindings += late ? findings : 0;
                    if (entry.Position.RecordId >= newestAtStart)
                    {
                        catchingUp = false;
                        logger.LogInformation(
                            "Caught up with the Sysmon log: {Count} events from the time RCEGuard was not running, {Findings} findings",
                            plan.Pending, caughtUpFindings);
                    }
                }
            }
        }
        finally
        {
            SavePosition(positionFile, ref unsaved, sinceSave);
        }
    }

    /// <summary>Decides where reading continues and says so in the log.</summary>
    private ResumePlan PlanResume(LogPositionFile positionFile, out long newestAtStart)
    {
        var saved = positionFile.Load(out var problem);
        if (problem is not null)
        {
            logger.LogWarning("The saved position in the Sysmon log ({Path}) cannot be read and is ignored: {Reason}", positionFile.Path, problem);
        }

        var range = EventLogTail.Range(options.LogName);
        var timeOfSaved = saved is null ? null : EventLogTail.TimeOf(options.LogName, saved.RecordId);
        var plan = LogResume.Decide(saved, range?.Oldest, range?.Newest, timeOfSaved);
        newestAtStart = range?.Newest.RecordId ?? 0;

        switch (plan.Kind)
        {
            case ResumeKind.FirstStart:
                logger.LogInformation("No saved position in the Sysmon log: reading from now on");
                if (range is { } known)
                {
                    // Without it a guard that stops before the first event would start from scratch again.
                    LogPosition? first = known.Newest;
                    SavePosition(positionFile, ref first, Stopwatch.StartNew());
                }

                break;
            case ResumeKind.Resume when plan.Pending == 0:
                logger.LogInformation("Continuing in the Sysmon log after record {Record}; nothing was written in the meantime", plan.StartAfterRecordId);
                break;
            case ResumeKind.Resume:
                logger.LogWarning(
                    "Continuing in the Sysmon log after record {Record}: {Pending} events were written while RCEGuard was not running and are read now",
                    plan.StartAfterRecordId, plan.Pending);
                break;
            case ResumeKind.LogReplaced:
                logger.LogWarning(
                    "The Sysmon log was cleared or replaced since RCEGuard last ran: reading all {Pending} events in it", plan.Pending);
                break;
            case ResumeKind.Overwritten:
                logger.LogWarning(
                    "{Lost} events were overwritten in the Sysmon log before RCEGuard could read them; reading the {Pending} that are left",
                    plan.Lost, plan.Pending);
                break;
        }

        return plan;
    }

    private void SavePosition(LogPositionFile positionFile, ref LogPosition? unsaved, Stopwatch sinceSave)
    {
        if (unsaved is null)
        {
            return;
        }

        try
        {
            positionFile.Save(unsaved);
            unsaved = null;
            sinceSave.Restart();
            positionSaveFailed = false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not fatal: the guard keeps working, it just could not note where it is. Tried again with the next event.
            sinceSave.Restart();
            if (!positionSaveFailed)
            {
                positionSaveFailed = true;
                logger.LogWarning(
                    "The position in the Sysmon log could not be saved to {Path}: {Reason}. After a restart, events may be read twice or missed",
                    positionFile.Path, ex.Message);
            }
        }
    }

    private void Replay(string path, RuleEngine engine, FindingStore store)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Events file not found: {path}");
        }

        var count = 0;
        foreach (var element in System.Xml.Linq.XDocument.Load(path).Root?.Elements() ?? [])
        {
            // No killer: the pids of old events belong to other programs by now, so they are not even looked up.
            Handle(element.ToString(System.Xml.Linq.SaveOptions.DisableFormatting), engine, killer: null, store, late: false);
            count++;
        }

        logger.LogInformation("Replayed {Count} events from {Path}", count, path);
    }

    /// <summary>Evaluates one event and acts on its findings.</summary>
    /// <param name="late">The event was written while the guard was not running.</param>
    /// <returns>The number of findings that were reported.</returns>
    private int Handle(string xml, RuleEngine engine, ProcessKiller? killer, FindingStore store, bool late)
    {
        if (!SysmonEventParser.TryParse(xml, out var sysmonEvent, out var error))
        {
            logger.LogWarning("Skipped an event that could not be read: {Reason}", error);
            return 0;
        }

        var reported = 0;
        foreach (var finding in engine.Evaluate(sysmonEvent!))
        {
            // The same alert again within the repeat window is counted on the stored finding, not reported anew.
            var decision = debouncer.Check(finding);
            if (!decision.Report)
            {
                store.AddRepeat(decision.Entry!.Tag, finding.Time);
                continue;
            }

            var taken = "none";
            if (finding.Action == FindingAction.Kill)
            {
                taken = killer is null
                    ? "not acted on (replay)"
                    // The time of the event lets the killer tell the process of the event from a later one with the same pid.
                    : string.Join("; ", finding.KillTargets.Select(target => killer.Kill(target, finding.Time)));
            }

            reported++;
            var rowId = store.Add(finding, taken);
            if (decision.Entry is { } entry)
            {
                entry.Tag = rowId;
            }

            var repeats = decision.RepeatsBefore > 0
                ? $" | seen {decision.RepeatsBefore} more time(s) since the previous report"
                : string.Empty;
            if (late)
            {
                repeats += " | written while RCEGuard was not running";
            }

            var delayMs = (long)(DateTimeOffset.UtcNow - finding.Time).TotalMilliseconds;
            var level = finding.Severity switch
            {
                Severity.Critical => LogLevel.Critical,
                Severity.High => LogLevel.Warning,
                _ => LogLevel.Information,
            };
            logger.Log(
                level,
                "{Rule} {Severity} [{Profile}] {Summary} | action: {Action} -> {Taken} | {Delay} ms after the event{Repeats}",
                finding.RuleId, finding.Severity.ToString().ToUpperInvariant(), finding.Profile, finding.Summary, finding.Action, taken, delayMs, repeats);
        }

        return reported;
    }

    private async Task RefreshHostsAsync(GuardConfig config, RuleEngine engine, CancellationToken cancellationToken)
    {
        foreach (var profile in config.Profiles.Where(p => p.AllowedHostnames.Count > 0))
        {
            var addresses = new List<IPAddress>();
            var failed = 0;
            foreach (var host in profile.AllowedHostnames)
            {
                try
                {
                    addresses.AddRange(await Dns.GetHostAddressesAsync(host, cancellationToken));
                }
                catch (Exception ex) when (ex is System.Net.Sockets.SocketException or ArgumentException)
                {
                    failed++;
                    logger.LogWarning("Host name '{Host}' of profile '{Profile}' could not be resolved: {Reason}", host, profile.Name, ex.Message);
                }
            }

            // Keep the previous addresses if nothing could be resolved (e.g. no network yet).
            if (addresses.Count > 0 || failed == 0)
            {
                engine.SetResolvedHosts(profile.Name, addresses);
            }
        }
    }

    private string Explain(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "no access to the Sysmon log. Start the console as administrator, or run RCEGuard as a service.",
        EventLogNotFoundException => "the Sysmon log does not exist. Install the sensor with scripts\\install.ps1 first.",
        EventLogException => $"the Sysmon log cannot be read: {ex.Message}",
        FileNotFoundException or FormatException or System.Xml.XmlException => ex.Message,
        Microsoft.Data.Sqlite.SqliteException => $"the findings database in '{options.DataDirectory}' cannot be opened: {ex.Message}",
        _ => ex.ToString(),
    };
}
