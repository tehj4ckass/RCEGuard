using System.Globalization;

using RCEGuard.Core.State;

namespace RCEGuard.Service;

/// <summary>
/// 'RCEGuard.Service.exe --release [profile]': ends the lockdown of one or of all profiles. Until
/// the tray application exists this is the way to release; it needs administrator rights, because
/// it changes the data folder and Windows Firewall.
/// </summary>
internal static class ReleaseCommand
{
    /// <summary>Runs the command. Returns the exit code of the process.</summary>
    public static async Task<int> RunAsync(ServiceOptions options, IFirewall firewall, TextWriter output, TextWriter error)
    {
        Core.Configuration.GuardConfig config;
        try
        {
            config = options.LoadConfig(out _);
        }
        catch (Exception ex) when (ex is FileNotFoundException or FormatException or IOException or UnauthorizedAccessException)
        {
            error.WriteLine(ex.Message);
            return 1;
        }

        var file = new LockdownFile(Path.Combine(options.DataDirectory, LockdownFile.FileName));
        var entries = file.Load(out var problem);
        if (problem is not null)
        {
            output.WriteLine($"The lockdown state '{file.Path}' cannot be read ({problem}). It is replaced by an empty one.");
        }

        var released = entries
            .Where(entry => options.ReleaseProfile is null || string.Equals(entry.Profile, options.ReleaseProfile, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (problem is null && released.Count == 0)
        {
            if (options.ReleaseProfile is null)
            {
                output.WriteLine("No profile is in lockdown.");
                return 0;
            }

            var others = entries.Count == 0 ? "No profile is in lockdown." : $"In lockdown: {string.Join(", ", entries.Select(entry => $"'{entry.Profile}'"))}.";
            error.WriteLine($"Profile '{options.ReleaseProfile}' is not in lockdown. {others}");
            return 1;
        }

        try
        {
            file.Save([.. entries.Except(released)]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"The lockdown state '{file.Path}' could not be written: {ex.Message}");
            error.WriteLine("Run this command in a console started as administrator.");
            return 1;
        }

        // The rule goes back to what the configuration asks for; for a profile with 'firewall' that
        // needs the addresses of its host names.
        var hosts = new HostAddressBook(config);
        foreach (var unresolved in await hosts.RefreshAsync(CancellationToken.None))
        {
            output.WriteLine(unresolved);
        }

        var guard = new FirewallGuard(config, firewall, file, (level, message) => (level >= LogLevel.Warning ? error : output).WriteLine(message), dryRun: false);
        var applied = guard.Apply(hosts.ByProfile, force: true);

        foreach (var entry in released)
        {
            output.WriteLine(
                $"Released '{entry.Profile}'. It was in lockdown since {entry.SinceUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} after {entry.Rule}: {entry.Summary}");
        }

        if (!applied)
        {
            error.WriteLine(
                "The lockdown is ended in the state of RCEGuard, but the firewall rule could not be changed. " +
                "If this console was not started as administrator, run the command again in one that was. The running guard also corrects the rule with its next refresh.");
            return 1;
        }

        return 0;
    }
}
