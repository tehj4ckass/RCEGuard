using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Learning;

/// <summary>What the learning mode suggests to add to the allowlist of a profile.</summary>
/// <param name="Hostnames">Host names to add to 'allowedHostnames'.</param>
/// <param name="Addresses">Addresses to add to 'allowedRemote' (no host name was seen for them).</param>
/// <param name="Programs">Programs to add to 'allowedProcessAccess' (the client opened them to look at them).</param>
public sealed record LearnedSuggestion(IReadOnlyList<string> Hostnames, IReadOnlyList<string> Addresses, IReadOnlyList<string> Programs)
{
    /// <summary>True if there is nothing to add.</summary>
    public bool IsEmpty => Hostnames.Count == 0 && Addresses.Count == 0 && Programs.Count == 0;
}

/// <summary>Turns what the learning mode noted into a suggestion and into text for a person.</summary>
public static class LearnedReport
{
    /// <summary>
    /// The suggestion for a profile: every address the client connected to that its allowlist does
    /// not cover. If the client asked the name service for a name that answered with the address,
    /// the name is suggested instead (addresses of a server change, its name does not).
    /// And every other program the client opened without rights to change it; a program it only
    /// ever opened with such rights is not suggested, because listing it would change nothing.
    /// </summary>
    public static LearnedSuggestion Suggest(LearnedProfile learned, ClientProfile profile)
    {
        var allowlist = new RemoteAllowlist(profile.AllowedRemote);
        var hostnames = new List<string>();
        var addresses = new List<string>();
        foreach (var address in learned.Remotes.Select(remote => remote.Address).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!IPAddress.TryParse(address, out var parsed) || allowlist.Contains(parsed))
            {
                continue;
            }

            var names = NamesOf(learned, address);
            if (names.Count == 0)
            {
                addresses.Add(address);
                continue;
            }

            if (names.Any(name => profile.AllowedHostnames.Contains(name, StringComparer.OrdinalIgnoreCase)))
            {
                continue; // Already allowed through its name.
            }

            // One name is enough to allow the address; the first one seen is the one the client asked for first.
            if (!hostnames.Contains(names[0], StringComparer.OrdinalIgnoreCase))
            {
                hostnames.Add(names[0]);
            }
        }

        var programs = learned.Programs
            .Where(program => !profile.AllowedProcessAccess.Contains(program.Image, StringComparer.OrdinalIgnoreCase))
            .Where(program => program.Access.Any(access => !ChangesOrUnreadable(access)))
            .Select(program => program.Image)
            .ToList();
        return new LearnedSuggestion(hostnames, addresses, programs);
    }

    private static bool ChangesOrUnreadable(string access) =>
        ProcessAccessRules.Classify(access) is ProcessAccessKind.Changes or ProcessAccessKind.Unreadable;

    private static List<string> NamesOf(LearnedProfile learned, string address) =>
        [.. learned.Hosts.Where(host => host.Addresses.Contains(address, StringComparer.OrdinalIgnoreCase)).Select(host => host.Name)];

    /// <summary>Text for a person: what was noted, and what to put into the configuration.</summary>
    /// <param name="learned">What was noted.</param>
    /// <param name="profile">The profile as it is configured now.</param>
    /// <param name="cpuAlertCores">The load above which R8 reports (0: the rule is off), to compare the highest load with.</param>
    public static string Render(LearnedProfile learned, ClientProfile profile, double cpuAlertCores = 0)
    {
        var text = new StringBuilder();
        var allowlist = new RemoteAllowlist(profile.AllowedRemote);
        text.AppendLine(CultureInfo.InvariantCulture, $"Profile '{learned.Profile}' ({profile.ClientPath})");
        text.AppendLine(CultureInfo.InvariantCulture, $"  Learning mode is {(profile.Learning ? "ON" : "off")}. Noted: {learned.Sessions} start(s) of the client, {Period(learned)}.");
        if (learned.Truncated)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"  A list was full ({Learner.MaxEntries} entries): not everything is in here.");
        }

        text.AppendLine();
        text.AppendLine("  Connections (address:port, how often, name the client asked for):");
        if (learned.Remotes.Count == 0)
        {
            text.AppendLine("    none");
        }

        foreach (var remote in learned.Remotes.OrderByDescending(remote => remote.Count).ThenBy(remote => remote.Address, StringComparer.Ordinal))
        {
            var names = NamesOf(learned, remote.Address);
            var covered = IPAddress.TryParse(remote.Address, out var parsed) && allowlist.Contains(parsed)
                ? "allowed by allowedRemote"
                : names.Any(name => profile.AllowedHostnames.Contains(name, StringComparer.OrdinalIgnoreCase))
                    ? "allowed by allowedHostnames"
                    : "NOT on the allowlist";
            var endpoint = remote.Address.Contains(':') ? $"[{remote.Address}]:{remote.Port}" : $"{remote.Address}:{remote.Port}";
            text.AppendLine(CultureInfo.InvariantCulture, $"    {endpoint,-28} {remote.Count,5}x  {(names.Count > 0 ? string.Join(", ", names) : "-"),-30} {covered}");
        }

        var unused = learned.Hosts.Where(host => !learned.Remotes.Any(remote => host.Addresses.Contains(remote.Address, StringComparer.OrdinalIgnoreCase))).ToList();
        if (unused.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("  Names the client asked for without a recorded connection to one of their addresses:");
            foreach (var host in unused.OrderBy(host => host.Name, StringComparer.Ordinal))
            {
                text.AppendLine(CultureInfo.InvariantCulture, $"    {host.Name} ({host.Count}x)");
            }
        }

        text.AppendLine();
        text.AppendLine("  Files created outside the game folder (folder, how many, extensions):");
        if (learned.Folders.Count == 0)
        {
            text.AppendLine("    none");
        }

        foreach (var folder in learned.Folders.OrderBy(folder => folder.Folder, StringComparer.OrdinalIgnoreCase))
        {
            var extensions = string.Join(" ", folder.Extensions.Select(extension => extension.Length == 0 ? "(none)" : extension));
            var note = folder.Extensions.Any(extension => PathRules.HasExecutableExtension("x" + extension)) ? "  <- program files" : string.Empty;
            text.AppendLine(CultureInfo.InvariantCulture, $"    {folder.Folder}  {folder.Count}x  {extensions}{note}");
        }

        text.AppendLine();
        text.AppendLine("  Other programs the client opened (program, how often, access rights):");
        if (learned.Programs.Count == 0)
        {
            text.AppendLine("    none");
        }

        foreach (var program in learned.Programs.OrderBy(program => program.Image, StringComparer.OrdinalIgnoreCase))
        {
            var listed = profile.AllowedProcessAccess.Contains(program.Image, StringComparer.OrdinalIgnoreCase) ? "  (on allowedProcessAccess)" : string.Empty;
            var note = program.Access.Any(ChangesOrUnreadable) ? "  <- with rights to change it: reported even if listed" : string.Empty;
            text.AppendLine(CultureInfo.InvariantCulture, $"    {program.Image}  {program.Count}x  {string.Join(" ", program.Access)}{listed}{note}");
        }

        text.AppendLine();
        text.AppendLine(learned.PeakCpuCores > 0
            ? string.Create(CultureInfo.InvariantCulture, $"  Highest processor load: {learned.PeakCpuCores:0.0#} cores on average{(cpuAlertCores > 0 ? string.Create(CultureInfo.InvariantCulture, $" (R8 reports above {cpuAlertCores:0.0#}: cpuAlertCores)") : " (R8 is off)")}")
            : "  Highest processor load: not measured (the client did not run long enough while RCEGuard watched it)");

        var suggestion = Suggest(learned, profile);
        text.AppendLine();
        if (suggestion.IsEmpty)
        {
            text.AppendLine("  Suggestion: nothing to add. Every recorded connection and every program the client looked at is on the lists already.");
            return text.ToString();
        }

        text.AppendLine("  Suggestion for this profile in appsettings.json (the lists as they would be afterwards):");
        text.AppendLine(CultureInfo.InvariantCulture, $"    \"allowedHostnames\": {JsonSerializer.Serialize(profile.AllowedHostnames.Concat(suggestion.Hostnames))},");
        text.AppendLine(CultureInfo.InvariantCulture, $"    \"allowedRemote\": {JsonSerializer.Serialize(profile.AllowedRemote.Concat(suggestion.Addresses))},");
        text.AppendLine(CultureInfo.InvariantCulture, $"    \"allowedProcessAccess\": {JsonSerializer.Serialize(profile.AllowedProcessAccess.Concat(suggestion.Programs))}");
        text.AppendLine("  Only take over what you recognise: everything the client did while learning is in here,");
        text.AppendLine("  whether you wanted it or not. Then set \"learning\": false and restart the service.");
        return text.ToString();
    }

    private static string Period(LearnedProfile learned) =>
        learned.FirstEventUtc is { } first && learned.LastEventUtc is { } last
            ? $"between {Local(first)} and {Local(last)}"
            : "no events";

    private static string Local(DateTimeOffset time) =>
        time.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
}
