using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using RCEGuard.Core.Configuration;

namespace RCEGuard.Tray;

/// <summary>
/// Starts a command of the installed service with administrator rights and waits for it. The tray
/// application runs as the logged-on user and changes nothing itself: if it could, so could any
/// program that runs as the user. Windows asks an administrator to confirm (User Account Control).
/// </summary>
internal static class GuardCommand
{
    /// <summary>
    /// The installed service. Only ever this path: Program Files is not writable for a normal
    /// user, so what is started with administrator rights here cannot have been swapped by one.
    /// </summary>
    public static string ServiceExe =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RCEGuard", "RCEGuard.Service.exe");

    /// <summary>Said when a command that changes the configuration fails: its own output is not visible from here.</summary>
    public const string ConfigHint = "To see why, run the same command in a console started as administrator.";

    /// <summary>The arguments that set the mode of the guard.</summary>
    public static string ModeArguments(GuardMode mode) => $"--set-mode {GuardModes.Argument(mode)}";

    /// <summary>The arguments that allow an address for a profile; null if the address is not an IP address or the profile has no name.</summary>
    public static string? AllowArguments(string profile, string address) =>
        profile.Length > 0 && IPAddress.TryParse(address, out var parsed) ? $"--allow {Quote(profile)} {parsed}" : null;

    /// <summary>One argument in quotes, so that it cannot break out of them and become two.</summary>
    public static string Quote(string value)
    {
        var text = value.Replace("\"", string.Empty);
        // A backslash right before the closing quote would escape it.
        var trailing = text.Length - text.TrimEnd('\\').Length;
        return $"\"{text}{new string('\\', trailing)}\"";
    }

    /// <summary>Runs a command and waits for it. Returns null if it ran and succeeded, otherwise why it did not.</summary>
    /// <param name="arguments">The arguments for the service program.</param>
    /// <param name="name">What the command is called in a message, e.g. "The release command".</param>
    /// <param name="declined">What to say if the administrator question of Windows was answered with "No".</param>
    /// <param name="afterFailure">Where to look if the command ended with an error.</param>
    /// <param name="timeoutMs">How long to wait for it.</param>
    public static string? Run(string arguments, string name, string declined, string afterFailure, int timeoutMs = 60_000)
    {
        if (!File.Exists(ServiceExe))
        {
            return $"The guard service was not found at '{ServiceExe}'. Is RCEGuard installed?";
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo(ServiceExe, arguments)
            {
                UseShellExecute = true,   // needed for "runas"
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null)
            {
                return $"{name} could not be started.";
            }

            if (!process.WaitForExit(timeoutMs))
            {
                return $"{name} did not finish within {(timeoutMs >= 120_000 ? $"{timeoutMs / 60_000} minutes" : "a minute")}.";
            }

            return process.ExitCode == 0 ? null : $"{name} ended with exit code {process.ExitCode}. {afterFailure}";
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED: the question of Windows was answered with "No".
            return declined;
        }
        catch (Win32Exception ex)
        {
            return $"{name} could not be started: {ex.Message}";
        }
    }
}
