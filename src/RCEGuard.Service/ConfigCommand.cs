using System.ComponentModel;
using System.ServiceProcess;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Notifications;

namespace RCEGuard.Service;

/// <summary>What became of restarting the guard service after a change of its configuration.</summary>
/// <param name="Failed">True if the service should run with the new configuration and does not.</param>
/// <param name="Message">What happened, for the person who ran the command.</param>
internal sealed record RestartResult(bool Failed, string Message);

/// <summary>Restarts the Windows service of the guard, which reads its configuration only when it starts.</summary>
internal static class ServiceRestart
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    /// <summary>Restarts the service if it is running.</summary>
    public static RestartResult Run()
    {
        try
        {
            using var service = new ServiceController("RCEGuard");
            ServiceControllerStatus status;
            try
            {
                status = service.Status;
            }
            catch (InvalidOperationException)
            {
                return new RestartResult(false, "The guard service is not installed, so nothing was restarted.");
            }

            if (status == ServiceControllerStatus.Stopped)
            {
                return new RestartResult(false, "The guard service is not running. It uses the new configuration when it is started.");
            }

            if (status != ServiceControllerStatus.StopPending)
            {
                service.Stop();
            }

            service.WaitForStatus(ServiceControllerStatus.Stopped, Patience);
            service.Start();
            service.WaitForStatus(ServiceControllerStatus.Running, Patience);
            return new RestartResult(false, "The guard service was restarted and uses the new configuration.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or System.ServiceProcess.TimeoutException)
        {
            var reason = ex.InnerException is null ? ex.Message : $"{ex.Message} {ex.InnerException.Message}";
            return new RestartResult(true, $"The configuration was written, but the guard service could not be restarted: {reason} Restart it yourself: Restart-Service RCEGuard");
        }
    }
}

/// <summary>
/// 'RCEGuard.Service.exe --set-mode &lt;mode&gt;' and '--allow &lt;profile&gt; &lt;address&gt;': change one thing in
/// the configuration file, keep the file from before as a copy, and restart the guard service.
/// They need administrator rights, because they write to the data folder and restart a service.
/// The tray application starts them and lets Windows ask for an administrator.
/// </summary>
internal static class ConfigCommand
{
    /// <summary>The outcome of an edit.</summary>
    /// <param name="Json">The new text of the configuration.</param>
    /// <param name="Changed">False if there was nothing to change.</param>
    /// <param name="Message">What was changed, or why nothing was.</param>
    private sealed record Change(string Json, bool Changed, string Message);

    /// <summary>Sets the mode of the guard. Returns the exit code of the process.</summary>
    public static Task<int> SetModeAsync(
        ServiceOptions options, TextWriter output, TextWriter error, Func<RestartResult>? restart = null, HttpMessageHandler? handler = null)
    {
        if (!GuardModes.TryParse(options.SetMode, out var mode))
        {
            error.WriteLine($"'{options.SetMode}' is not a mode. Modes: {string.Join(", ", Enum.GetValues<GuardMode>().Select(GuardModes.Argument))}.");
            return Task.FromResult(1);
        }

        return ApplyAsync(options, output, error, restart, handler, json =>
        {
            var before = GuardModes.Of(GuardConfigJson.Parse(json));
            return before == mode
                ? new Change(json, false, $"The mode is \"{GuardModes.Name(mode)}\" already. Nothing was changed.")
                : new Change(
                    GuardConfigEditor.SetMode(json, mode),
                    true,
                    $"The mode of the guard was changed {(before is { } old ? $"from \"{GuardModes.Name(old)}\" " : string.Empty)}to \"{GuardModes.Name(mode)}\". {GuardModes.Describe(mode)}");
        });
    }

    /// <summary>Adds an address to the allowlist of a profile. Returns the exit code of the process.</summary>
    public static Task<int> AllowAsync(
        ServiceOptions options, TextWriter output, TextWriter error, Func<RestartResult>? restart = null, HttpMessageHandler? handler = null)
    {
        var profile = options.AllowProfile ?? string.Empty;
        var address = options.AllowAddress ?? string.Empty;
        return ApplyAsync(options, output, error, restart, handler, json =>
        {
            var edited = GuardConfigEditor.AllowRemote(json, profile, address, out var added);
            return added
                ? new Change(edited, true, $"'{address.Trim()}' was added to the allowed addresses of profile '{profile}'.")
                : new Change(json, false, $"'{address.Trim()}' is on the allowed addresses of profile '{profile}' already. Nothing was changed.");
        });
    }

    private static async Task<int> ApplyAsync(
        ServiceOptions options, TextWriter output, TextWriter error, Func<RestartResult>? restart, HttpMessageHandler? handler, Func<string, Change> edit)
    {
        var path = options.ConfigPath ?? Path.Combine(options.DataDirectory, GuardConfigFile.FileName);
        var existed = File.Exists(path);
        Change change;
        try
        {
            // Without a file the guard watches the client it was installed for; the file is written from that.
            var json = existed ? File.ReadAllText(path) : GuardConfigEditor.ForProfiles(options.LoadConfig(out _).Profiles);
            change = edit(json);
        }
        catch (Exception ex) when (ex is FileNotFoundException or FormatException or IOException or UnauthorizedAccessException)
        {
            error.WriteLine(ex.Message);
            return 1;
        }

        if (!change.Changed)
        {
            output.WriteLine(change.Message);
            return 0;
        }

        var backup = path + ".bak";
        try
        {
            if (existed)
            {
                File.Copy(path, backup, overwrite: true);
            }

            // Written next to the file and moved over it: a guard that starts in between reads the old file or the new one, never half of one.
            var draft = path + ".new";
            File.WriteAllText(draft, change.Json);
            File.Move(draft, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"The configuration '{path}' could not be written: {ex.Message}");
            error.WriteLine("Run this command in a console started as administrator.");
            return 1;
        }

        output.WriteLine(change.Message);
        output.WriteLine(existed ? $"The configuration from before is kept as '{backup}'." : $"The configuration was written to '{path}'.");

        var restarted = (restart ?? (() => RestartFor(options)))();
        (restarted.Failed ? error : output).WriteLine(restarted.Message);

        // Told to the owner as well: whoever changes how the guard acts should not be able to do so unnoticed.
        if (GuardConfigJson.Parse(change.Json).Notify?.Ntfy is { Enabled: true } ntfy)
        {
            using var notifier = new NtfyNotifier(ntfy, (_, _) => { }, handler);
            var problem = await notifier.SendNowAsync(NotificationText.ConfigChanged(change.Message, Environment.MachineName), CancellationToken.None);
            output.WriteLine(problem is null ? $"The change was reported to ntfy at {notifier.Server}." : $"The change could not be reported to ntfy: {problem}.");
        }

        return restarted.Failed ? 1 : 0;
    }

    private static RestartResult RestartFor(ServiceOptions options)
    {
        // The Windows service reads the configuration of the default data folder; another file belongs to a guard someone started by hand.
        var installed = options.ConfigPath is null
            && string.Equals(
                Path.TrimEndingDirectorySeparator(options.DataDirectory),
                Path.TrimEndingDirectorySeparator(new ServiceOptions().DataDirectory),
                StringComparison.OrdinalIgnoreCase);
        return installed
            ? ServiceRestart.Run()
            : new RestartResult(false, "This is not the configuration of the installed service: restart the guard that uses it yourself.");
    }
}
