using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting.WindowsServices;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Learning;
using RCEGuard.Core.Notifications;
using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;
using RCEGuard.Core.State;

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

    /// <summary>
    /// While a host name could not be resolved (no network yet after a start of Windows), it is
    /// tried again this often: with the firewall on, its server is blocked until then.
    /// </summary>
    private static readonly TimeSpan HostRetryInterval = TimeSpan.FromSeconds(30);

    /// <summary>The position is saved at once after a finding, otherwise at most this often.</summary>
    private static readonly TimeSpan PositionSaveInterval = TimeSpan.FromSeconds(1);

    /// <summary>How often a quiet guard looks whether the log holds events it was not given.</summary>
    private static readonly TimeSpan DeliveryCheckInterval = TimeSpan.FromSeconds(15);

    /// <summary>What the learning mode noted is saved at most this often.</summary>
    private static readonly TimeSpan LearnedSaveInterval = TimeSpan.FromSeconds(5);

    private readonly ServiceOptions options;
    private readonly ILogger<GuardWorker> logger;
    private readonly IHostApplicationLifetime lifetime;
    private readonly Channel<LogEntry> events = Channel.CreateUnbounded<LogEntry>(new UnboundedChannelOptions { SingleReader = true });
    private FindingDebouncer debouncer = new(TimeSpan.Zero);
    private bool positionSaveFailed;
    private HostAddressBook? hosts;
    private FirewallGuard? firewallGuard;
    private LockOnKill lockOnKill = LockOnKill.Off;
    private INotifier notifier = NullNotifier.Instance;
    private GuardConfig? loadedConfig;
    private string? runningMarker;
    private Learner? learner;
    private LearnedFile? learnedFile;
    private bool learnedUnsaved;
    private bool learnedSaveFailed;
    private readonly Stopwatch sinceLearnedSave = Stopwatch.StartNew();
    private readonly HashSet<string> learningProfiles = new(StringComparer.OrdinalIgnoreCase);

    // R8: the clients that are running, by pid, as the Sysmon log told (start and end of a client).
    private readonly Dictionary<int, WatchedClient> clients = [];
    private CpuWatch? cpuWatch;
    private TimeSpan cpuPollInterval;
    private DateTimeOffset nextCpuPoll;
    private bool cpuReadFailed;

    /// <summary>Opens the notifier for an ntfy topic. Tests put one here that sends nothing over the network.</summary>
    internal Func<NtfyConfig, Action<LogLevel, string>, INotifier> OpenNotifier { get; init; } =
        (config, log) => new NtfyNotifier(config, log);

    /// <summary>Reads the processor times of the running processes. Tests put made-up ones here.</summary>
    internal Func<IReadOnlyDictionary<int, ProcessTime>> ReadProcessTimes { get; init; } = ProcessTimes.Take;

    /// <summary>Opens Windows Firewall. Tests put a stand-in here; the real one cannot be changed without administrator rights.</summary>
    internal Func<IFirewall> OpenFirewall { get; init; } = () => new WindowsFirewall();

    /// <summary>Resolves a host name. Tests replace the name resolution of Windows.</summary>
    internal Func<string, CancellationToken, Task<IPAddress[]>>? ResolveHost { get; init; }

    /// <summary>
    /// An event may be in the log this long before its delivery counts as missing. Delivery normally
    /// takes milliseconds; the margin keeps a busy machine from looking like a broken subscription.
    /// </summary>
    internal TimeSpan DeliveryGrace { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>The logger of this worker, for tests.</summary>
    internal ILogger<GuardWorker> Logger => logger;

    /// <summary>Opens the subscription to the log. Tests replace it to see what a quiet subscription leads to.</summary>
    internal Func<string, long, Action<LogEntry>, Action<Exception>, IDisposable> OpenTail { get; init; } =
        (logName, afterRecordId, onEntry, onError) =>
        {
            var tail = new EventLogTail(logName, afterRecordId, onEntry, onError);
            tail.Start();
            return tail;
        };

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
            await OnStoppedAsync();
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
            await OnStoppedAsync();
        }
        catch (Exception ex)
        {
            // Fail loudly: a guard that silently watches nothing is worse than one that is not running.
            if (ex is ChannelClosedException { InnerException: { } cause })
            {
                ex = cause;
            }

            var reason = Explain(ex);
            logger.LogCritical("RCEGuard cannot run: {Reason}", reason);
            // This end is reported here; the next start must not report it again as "ended unexpectedly".
            RemoveRunningMarker();
            notifier.Send(NotificationText.CannotRun(reason, Environment.MachineName));
            await notifier.FlushAsync(TimeSpan.FromSeconds(5));
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
        loadedConfig = config;
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
        // Lockdown goes with terminating: where nothing is terminated, nothing is locked down either.
        lockOnKill = !config.Lockdown ? LockOnKill.Off : killEnabled ? LockOnKill.On : LockOnKill.ReportOnly;
        if (config.Lockdown)
        {
            logger.LogInformation(
                "Lockdown after a finding that terminates the client is {State}", killEnabled ? "ON" : "OFF (nothing is terminated, so nothing is locked down)");
        }

        StartLearning(config);
        if (config.CpuAlertCores > 0 && options.ReplayPath is null)
        {
            cpuWatch = new CpuWatch(config.CpuAlertCores, TimeSpan.FromSeconds(config.CpuAlertSeconds));
            cpuPollInterval = TimeSpan.FromSeconds(Math.Clamp(config.CpuAlertSeconds / 5.0, 1, 15));
            logger.LogInformation(
                "R8: a client that keeps more than {Cores} processor cores busy on average over {Seconds} s is reported (this machine has {Count})",
                config.CpuAlertCores.ToString("0.0#", System.Globalization.CultureInfo.InvariantCulture), config.CpuAlertSeconds, Environment.ProcessorCount);
            if (config.CpuAlertCores >= Environment.ProcessorCount)
            {
                logger.LogWarning("R8 can never report on this machine: cpuAlertCores is not below its {Count} processor cores", Environment.ProcessorCount);
            }
        }

        if (options.ReplayPath is not null)
        {
            Replay(options.ReplayPath, engine, store);
            SaveLearned(force: true);
            lifetime.StopApplication();
            return;
        }

        if (config.Notify?.Ntfy is { Enabled: true } ntfy)
        {
            notifier = OpenNotifier(ntfy, (level, message) => logger.Log(level, "{Message}", message));
            // Only the server: on an open ntfy server the name of the topic is all that keeps others out.
            logger.LogInformation(
                "Findings that alert or terminate are also sent to ntfy at {Server}",
                Uri.TryCreate(ntfy.Url, UriKind.Absolute, out var topic) ? $"{topic.Scheme}://{topic.Authority}" : "(invalid address)");
        }

        // Fail closed: the watcher itself accepts a missing or unreadable log and then just delivers nothing.
        // Asking for the log's properties and reading its ends throws in both cases.
        using (var session = new EventLogSession())
        {
            _ = session.GetLogInformation(options.LogName, PathType.LogName);
        }

        var positionFile = new LogPositionFile(Path.Combine(options.DataDirectory, ServiceOptions.PositionFileName));
        NoteStart(positionFile.Path);
        var plan = PlanResume(positionFile, out var newestAtStart);

        // The host names must be known before old events are evaluated, or their connections would all look unknown.
        hosts = new HostAddressBook(config, ResolveHost);
        var nextHostRefresh = DateTimeOffset.UtcNow + await RefreshHostsAsync(hosts, engine, stoppingToken);

        // The firewall rules before the first event: a lockdown from before the restart must be in place again.
        // Every wanted rule is written anew once per start, so that a rule changed by hand does not stay.
        firewallGuard = new FirewallGuard(
            config,
            OpenFirewall(),
            new LockdownFile(Path.Combine(options.DataDirectory, LockdownFile.FileName)),
            (level, message) => logger.Log(level, "{Message}", message),
            dryRun: options.DryRun);
        firewallGuard.Apply(hosts.ByProfile, force: true);

        using var tail = OpenTail(
            options.LogName,
            plan.StartAfterRecordId,
            entry => events.Writer.TryWrite(entry),
            // The subscription is broken (log removed, Sysmon uninstalled, access lost). Closing the
            // channel with the error ends the guard loop instead of leaving it waiting for nothing.
            error => events.Writer.TryComplete(error));
        logger.LogInformation("Subscribed to {Log}; waiting for events", options.LogName);

        LogPosition? unsaved = null;
        var sinceSave = Stopwatch.StartNew();
        var lastDelivered = plan.StartAfterRecordId;
        var sinceDeliveryCheck = Stopwatch.StartNew();
        var idleWait = DeliveryGrace < DeliveryCheckInterval ? DeliveryGrace : DeliveryCheckInterval;
        var catchingUp = plan.Pending > 0;
        var caughtUpFindings = 0;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                if (DateTimeOffset.UtcNow >= nextHostRefresh)
                {
                    nextHostRefresh = DateTimeOffset.UtcNow + await RefreshHostsAsync(hosts, engine, stoppingToken);
                    firewallGuard.Apply(hosts.ByProfile);
                }
                else if (firewallGuard.ChangedOutside())
                {
                    // The release command ended a lockdown (and wrote the rules itself already).
                    logger.LogInformation("The lockdown state was changed from outside the guard; bringing the firewall rules in line");
                    firewallGuard.Apply(hosts.ByProfile);
                }

                PollCpu(killer, store);

                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                var waitFor = unsaved is null ? idleWait : PositionSaveInterval;
                // While a client runs, the loop must come round often enough to measure it.
                wait.CancelAfter(cpuWatch is not null && clients.Count > 0 && cpuPollInterval < waitFor ? cpuPollInterval : waitFor);
                LogEntry entry;
                try
                {
                    entry = await events.Reader.ReadAsync(wait.Token);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    // Nothing came. Save the position and look whether that is right: is the log as quiet as the subscription?
                    SavePosition(positionFile, ref unsaved, sinceSave);
                    SaveLearned(force: false);
                    if (sinceDeliveryCheck.Elapsed >= idleWait)
                    {
                        sinceDeliveryCheck.Restart();
                        var newest = EventLogTail.Newest(options.LogName);
                        if (LogResume.HasUndelivered(lastDelivered, newest, DateTimeOffset.UtcNow, DeliveryGrace))
                        {
                            // Fail closed: ending here makes Windows restart the service, and the start reads what was missed.
                            throw new LogDeliveryException(lastDelivered, newest!.RecordId);
                        }
                    }

                    continue;
                }

                lastDelivered = entry.Position.RecordId;
                var late = catchingUp && entry.Position.RecordId <= newestAtStart;
                var findings = Handle(entry.Xml, engine, killer, store, late);
                SaveLearned(force: false);
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
            SaveLearned(force: true);
        }
    }

    /// <summary>Says which profiles are in learning mode and reads what was noted for them before.</summary>
    private void StartLearning(GuardConfig config)
    {
        foreach (var profile in config.Profiles.Where(profile => profile.Learning))
        {
            learningProfiles.Add(profile.Name);
            // A warning: for this client the guard only watches. Nobody should take that for protection.
            logger.LogWarning(
                "Learning mode is ON for '{Name}': nothing is terminated, locked down or blocked for this client{Firewall}; what it does is noted for a suggestion ('--learned'). Set \"learning\": false when done",
                profile.Name,
                profile.Firewall ? ", and the firewall rule of the profile is not written" : string.Empty);
        }

        if (learningProfiles.Count == 0)
        {
            return;
        }

        learnedFile = new LearnedFile(Path.Combine(options.DataDirectory, LearnedFile.FileName));
        var known = learnedFile.Load(out var problem);
        if (problem is not null)
        {
            logger.LogWarning("What the learning mode noted before ({Path}) cannot be read and is started anew: {Reason}", learnedFile.Path, problem);
        }

        learner = new Learner(config, known);
    }

    private void SaveLearned(bool force)
    {
        if (!learnedUnsaved || learner is null || learnedFile is null || (!force && sinceLearnedSave.Elapsed < LearnedSaveInterval))
        {
            return;
        }

        sinceLearnedSave.Restart();
        try
        {
            learnedFile.Save(learner.Profiles);
            learnedUnsaved = false;
            learnedSaveFailed = false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not fatal: the guard keeps watching. Tried again with the next event.
            if (!learnedSaveFailed)
            {
                learnedSaveFailed = true;
                logger.LogWarning("What the learning mode noted could not be saved to {Path}: {Reason}", learnedFile.Path, ex.Message);
            }
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
        var findings = engine.Evaluate(sysmonEvent!);
        if (learner is not null && learner.Observe(sysmonEvent!, findings))
        {
            learnedUnsaved = true;
        }

        TrackClient(sysmonEvent!);
        foreach (var finding in findings)
        {
            if (Report(finding, killer, store, late))
            {
                reported++;
            }
        }

        return reported;
    }

    /// <summary>Notes the start and the end of a client, so that R8 knows which processes to measure.</summary>
    private void TrackClient(SysmonEvent e)
    {
        if (cpuWatch is null || loadedConfig is null || e.EventId is not (SysmonEventIds.ProcessCreate or SysmonEventIds.ProcessTerminate))
        {
            return;
        }

        var image = e.Get("Image");
        var profile = loadedConfig.Profiles.FirstOrDefault(candidate => PathRules.Same(candidate.ClientPath, image));
        if (profile is null || e.GetInt("ProcessId") is not { } pid)
        {
            return;
        }

        if (e.EventId == SysmonEventIds.ProcessTerminate)
        {
            if (clients.Remove(pid, out var ended))
            {
                cpuWatch.Forget(ended.Key(pid));
            }
        }
        else if (clients.Count < 256 || clients.ContainsKey(pid))
        {
            // An old event (read after a restart) may name a process that is long gone: the start
            // time lets the measurement tell it from whatever has that pid now.
            clients[pid] = new WatchedClient(profile.Name, image, RuleEngine.ProcessStart(e));
        }
    }

    /// <summary>R8: measures the running clients if it is time to, and reports one whose load has risen above the threshold.</summary>
    private void PollCpu(ProcessKiller killer, FindingStore store)
    {
        var now = DateTimeOffset.UtcNow;
        if (cpuWatch is null || clients.Count == 0 || now < nextCpuPoll)
        {
            return;
        }

        nextCpuPoll = now + cpuPollInterval;
        IReadOnlyDictionary<int, ProcessTime> times;
        try
        {
            times = ReadProcessTimes();
            cpuReadFailed = false;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or PlatformNotSupportedException or OutOfMemoryException)
        {
            if (!cpuReadFailed)
            {
                cpuReadFailed = true;
                logger.LogWarning("R8 cannot measure the clients: {Reason}", ex.Message);
            }

            return;
        }

        foreach (var (pid, client) in clients.ToList())
        {
            // Gone, or the pid belongs to another process by now.
            if (!times.TryGetValue(pid, out var time) || (time.Created - client.Started).Duration() > TimeSpan.FromSeconds(2))
            {
                clients.Remove(pid);
                cpuWatch.Forget(client.Key(pid));
                continue;
            }

            var verdict = cpuWatch.Sample(client.Key(pid), now, time.Cpu);
            if (verdict.Cores is { } cores && learner is not null && learner.NoteCpu(client.Profile, cores))
            {
                learnedUnsaved = true;
            }

            if (verdict.Alert)
            {
                Report(cpuWatch.ToFinding(client.Profile, client.Image, pid, verdict.Cores!.Value, now), killer, store, late: false);
            }
        }
    }

    /// <summary>Acts on one finding and reports it, unless it only repeats a reported one.</summary>
    /// <returns>True if the finding was reported.</returns>
    private bool Report(Finding finding, ProcessKiller? killer, FindingStore store, bool late)
    {
        // The same alert again within the repeat window is counted on the stored finding, not reported anew.
        var decision = debouncer.Check(finding);
        if (!decision.Report)
        {
            store.AddRepeat(decision.Entry!.Tag, finding.Time);
            return false;
        }

        var taken = "none";
        if (finding.Action == FindingAction.Kill && learningProfiles.Contains(finding.Profile))
        {
            // Still reported like any finding that terminates: the user must hear of it.
            taken = "not terminated (learning mode)";
        }
        else if (finding.Action == FindingAction.Kill)
        {
            taken = killer is null
                ? "not acted on (replay)"
                // The time of the event lets the killer tell the process of the event from a later one with the same pid.
                : string.Join("; ", finding.KillTargets.Select(target => killer.Kill(target, finding.Time)));

            // Kill switch: what made the client do this may still be there when it is started again.
            if (killer is not null && finding.Profile.Length > 0 && firewallGuard is not null && hosts is not null)
            {
                taken += lockOnKill switch
                {
                    LockOnKill.On => "; " + firewallGuard.Lock(finding, hosts.ByProfile),
                    LockOnKill.ReportOnly => "; would lock down the profile",
                    _ => string.Empty,
                };
            }
        }

        var rowId = store.Add(finding, taken);
        // Not for a replay: its events are old.
        if (killer is not null && NotificationText.Notifies(finding))
        {
            notifier.Send(NotificationText.ForFinding(finding, taken, late, Environment.MachineName));
        }
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
        return true;
    }

    /// <summary>
    /// Notes in the data folder that the guard is running, and says so if the note of the previous
    /// run is still there: that run then did not stop the regular way (ended from outside, crashed,
    /// power lost). A guard that is ended like that cannot report it itself; its next start does.
    /// </summary>
    private void NoteStart(string positionPath)
    {
        var marker = Path.Combine(options.DataDirectory, ServiceOptions.RunningMarkerName);
        try
        {
            if (File.Exists(marker))
            {
                // The position is saved while events come in: its time is the last sign of life there is.
                var signs = new[] { marker, positionPath }.Where(File.Exists).Select(path => new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero)).ToList();
                DateTimeOffset? lastSeen = signs.Count > 0 ? signs.Max() : null;
                logger.LogWarning(
                    "RCEGuard did not stop the regular way last time (last sign of life: {LastSeen}). Reading what happened in between",
                    lastSeen is { } time ? time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) : "unknown");
                notifier.Send(NotificationText.EndedUnexpectedly(lastSeen, Environment.MachineName));
            }

            File.WriteAllText(marker, DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
            runningMarker = marker;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning("The note that RCEGuard is running could not be written to {Path}: {Reason}. An unexpected end will not be reported", marker, ex.Message);
        }
    }

    private void RemoveRunningMarker()
    {
        if (runningMarker is null)
        {
            return;
        }

        try
        {
            File.Delete(runningMarker);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning("The note that RCEGuard is running could not be removed from {Path}: {Reason}", runningMarker, ex.Message);
        }

        runningMarker = null;
    }

    /// <summary>The regular end: says so if a watched client is still running, and takes the running note away.</summary>
    private async Task OnStoppedAsync()
    {
        if (runningMarker is not null && loadedConfig is not null)
        {
            try
            {
                var names = loadedConfig.Profiles.Select(profile => Path.GetFileName(profile.ClientPath)).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var running = ProcessSnapshot.Take().Select(process => process.Name).Where(names.Contains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (running.Count > 0)
                {
                    logger.LogWarning("RCEGuard is stopping while {Clients} is running: the client is not watched from now on", string.Join(", ", running));
                    notifier.Send(NotificationText.StoppedWhileClientRuns(running, Environment.MachineName));
                }
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                logger.LogWarning("Could not look whether a client is still running: {Reason}", ex.Message);
            }
        }

        await notifier.FlushAsync(TimeSpan.FromSeconds(5));
        RemoveRunningMarker();
        (notifier as IDisposable)?.Dispose();
    }

    /// <summary>Resolves the host names again and tells the rule engine. Returns when to do it next.</summary>
    private async Task<TimeSpan> RefreshHostsAsync(HostAddressBook book, RuleEngine engine, CancellationToken cancellationToken)
    {
        var problems = await book.RefreshAsync(cancellationToken);
        foreach (var problem in problems)
        {
            logger.LogWarning("{Problem}", problem);
        }

        foreach (var (profile, addresses) in book.ByProfile)
        {
            engine.SetResolvedHosts(profile, addresses);
        }

        return problems.Count == 0 ? HostRefreshInterval : HostRetryInterval;
    }

    private string Explain(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "no access to the Sysmon log. Start the console as administrator, or run RCEGuard as a service.",
        EventLogNotFoundException => "the Sysmon log does not exist. Install the sensor with scripts\\install.ps1 first.",
        EventLogException => $"the Sysmon log cannot be read: {ex.Message}",
        LogDeliveryException => ex.Message,
        FileNotFoundException or FormatException or System.Xml.XmlException => ex.Message,
        Microsoft.Data.Sqlite.SqliteException => $"the findings database in '{options.DataDirectory}' cannot be opened: {ex.Message}",
        _ => ex.ToString(),
    };
}

/// <summary>A running client that R8 measures.</summary>
/// <param name="Profile">Name of its profile.</param>
/// <param name="Image">Full path of the client.</param>
/// <param name="Started">When the process was started, as the Sysmon event said.</param>
internal sealed record WatchedClient(string Profile, string Image, DateTimeOffset Started)
{
    /// <summary>Identifies the process for the measurement: a pid alone can be reused.</summary>
    public string Key(int processId) => $"{processId}@{Started.UtcTicks}";
}

/// <summary>What a finding that terminates the client does to its profile.</summary>
internal enum LockOnKill
{
    /// <summary>Nothing: lockdown is not turned on.</summary>
    Off,

    /// <summary>The profile is put in lockdown.</summary>
    On,

    /// <summary>Lockdown is turned on, but nothing is terminated (dry run): it is only said.</summary>
    ReportOnly,
}

/// <summary>The log holds events that the subscription did not deliver.</summary>
public sealed class LogDeliveryException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="lastDelivered">Record id of the last delivered event.</param>
    /// <param name="newest">Record id of the newest event in the log.</param>
    public LogDeliveryException(long lastDelivered, long newest)
        : base($"the Sysmon log holds events up to record {newest} that were not delivered to RCEGuard (last delivered: {lastDelivered}). " +
               "Ending, so that Windows restarts the service; the start reads what was missed.")
    {
    }
}
