using System.Net;
using System.Runtime.InteropServices;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Prevention;
using RCEGuard.Core.Rules;
using RCEGuard.Core.State;

namespace RCEGuard.Service;

/// <summary>
/// Keeps the firewall rules of RCEGuard in line with the configuration and the lockdown file,
/// and puts profiles in lockdown. Used by the guard loop and by the release command.
/// </summary>
internal sealed class FirewallGuard
{
    private readonly GuardConfig config;
    private readonly IFirewall firewall;
    private readonly LockdownFile file;
    private readonly Action<LogLevel, string> log;
    private readonly bool dryRun;
    private DateTime? seenStamp;
    private string? reportedProblem;
    private bool fileProblemReported;
    private bool dryRunReported;

    /// <summary>Creates the guard.</summary>
    /// <param name="config">The configuration.</param>
    /// <param name="firewall">The firewall to keep in line.</param>
    /// <param name="file">The profiles in lockdown.</param>
    /// <param name="log">Receives what was done and what went wrong.</param>
    /// <param name="dryRun">Change nothing: neither the firewall nor the lockdown file.</param>
    public FirewallGuard(GuardConfig config, IFirewall firewall, LockdownFile file, Action<LogLevel, string> log, bool dryRun)
    {
        this.config = config;
        this.firewall = firewall;
        this.file = file;
        this.log = log;
        this.dryRun = dryRun;
    }

    /// <summary>True if the lockdown file was written by someone else since this guard last read it.</summary>
    public bool ChangedOutside() => file.Stamp() != seenStamp;

    /// <summary>
    /// Writes the rules that should exist and removes those of RCEGuard that should not.
    /// A rule that already is as wanted is left alone, unless <paramref name="force"/> is set.
    /// </summary>
    /// <param name="hosts">Per profile, the addresses of its allowed host names.</param>
    /// <param name="force">Write every wanted rule again, also one that looks right.</param>
    /// <param name="alsoLocked">A profile to treat as locked although the lockdown file does not say so (it could not be written).</param>
    /// <returns>False if the firewall could not be read or changed.</returns>
    public bool Apply(IReadOnlyDictionary<string, IReadOnlyCollection<IPAddress>> hosts, bool force = false, string? alsoLocked = null)
    {
        var locked = LockedProfiles();
        if (alsoLocked is not null)
        {
            locked.Add(alsoLocked);
        }

        var desired = FirewallPlanner.Plan(config, hosts, locked);
        if (dryRun)
        {
            if (desired.Count > 0 && !dryRunReported)
            {
                dryRunReported = true;
                log(LogLevel.Information, $"Dry run: {desired.Count} firewall rule(s) would be kept up to date ({string.Join(", ", desired.Select(rule => $"'{rule.Name}'"))}). Nothing is written to Windows Firewall");
            }

            return true;
        }

        try
        {
            var existing = firewall.ReadRules();
            foreach (var spec in desired)
            {
                var current = existing.FirstOrDefault(rule => string.Equals(rule.Name, spec.Name, StringComparison.OrdinalIgnoreCase));
                if (!force && current is not null && IsAsWanted(current, spec))
                {
                    continue;
                }

                firewall.Write(spec);
                log(LogLevel.Information, $"Firewall rule '{spec.Name}' written: {Describe(spec)}");
            }

            foreach (var stale in existing.Where(rule => !desired.Any(spec => string.Equals(spec.Name, rule.Name, StringComparison.OrdinalIgnoreCase))))
            {
                firewall.Remove(stale.Name);
                log(LogLevel.Information, $"Firewall rule '{stale.Name}' removed: neither the configuration nor a lockdown asks for it");
            }

            if (desired.Count > 0)
            {
                var problem = firewall.Problem();
                if (problem != reportedProblem)
                {
                    reportedProblem = problem;
                    if (problem is not null)
                    {
                        log(LogLevel.Warning, problem);
                    }
                }
            }

            return true;
        }
        catch (Exception ex) when (IsFirewallFailure(ex))
        {
            log(
                LogLevel.Error,
                $"Windows Firewall could not be read or changed: {ex.Message.Trim().TrimEnd('.')}. " +
                (desired.Count > 0
                    ? "What RCEGuard is to block there may NOT be blocked. Tried again with the next refresh."
                    : "Rules of RCEGuard that are no longer wanted may still be there."));
            return false;
        }
    }

    /// <summary>Puts the profile of a finding in lockdown. Returns what was done, for the log line of the finding.</summary>
    public string Lock(Finding finding, IReadOnlyDictionary<string, IReadOnlyCollection<IPAddress>> hosts)
    {
        if (dryRun)
        {
            return "would lock down the profile";
        }

        var entries = file.Load(out var problem).ToList();
        if (problem is null && entries.Any(entry => string.Equals(entry.Profile, finding.Profile, StringComparison.OrdinalIgnoreCase)))
        {
            return "already in lockdown";
        }

        string? notNoted = null;
        if (problem is null)
        {
            entries.Add(new LockdownEntry(finding.Profile, finding.Time, finding.RuleId, finding.Summary));
            try
            {
                file.Save(entries);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                notNoted = ex.Message;
            }
        }

        if (!Apply(hosts, alsoLocked: finding.Profile))
        {
            return "LOCKDOWN FAILED: the firewall rule could not be written";
        }

        return notNoted is null
            ? "locked down: the firewall blocks every outbound connection of the client until the lockdown is released"
            : $"locked down, but the lockdown could not be noted in '{file.Path}' ({notNoted}): it ends when RCEGuard refreshes its rules";
    }

    private HashSet<string> LockedProfiles()
    {
        var entries = file.Load(out var problem);
        seenStamp = file.Stamp();
        if (problem is null)
        {
            fileProblemReported = false;
            return new HashSet<string>(entries.Select(entry => entry.Profile), StringComparer.OrdinalIgnoreCase);
        }

        // Fail closed: a state that cannot be read may hide a lockdown.
        if (!fileProblemReported)
        {
            fileProblemReported = true;
            log(
                LogLevel.Error,
                $"The lockdown state '{file.Path}' cannot be read ({problem}). Every profile is treated as locked down until it is released with 'RCEGuard.Service.exe --release'");
        }

        return new HashSet<string>(config.Profiles.Select(profile => profile.Name), StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsAsWanted(InstalledFirewallRule current, FirewallRuleSpec spec) =>
        current.Enabled
        && current.BlocksOutbound
        && current.Description == spec.Description
        && string.Equals(current.ApplicationPath, spec.ApplicationPath, StringComparison.OrdinalIgnoreCase);

    private static string Describe(FirewallRuleSpec spec) =>
        spec.RemoteAddresses == FirewallRuleSpec.AnyAddress
            ? $"every outbound connection of '{spec.ApplicationPath}' is blocked (lockdown)"
            : $"outbound connections of '{spec.ApplicationPath}' are blocked except to the allowed addresses ({spec.RemoteAddresses.Split(',').Length} blocked ranges)";

    private static bool IsFirewallFailure(Exception ex) =>
        ex is COMException or UnauthorizedAccessException or InvalidOperationException or InvalidCastException
            or ArgumentException or FileNotFoundException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException;
}
