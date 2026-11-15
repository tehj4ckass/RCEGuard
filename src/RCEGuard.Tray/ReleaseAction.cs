using System.ComponentModel;
using System.Diagnostics;

namespace RCEGuard.Tray;

/// <summary>
/// Ends a lockdown by starting the release command of the installed service with administrator
/// rights. The tray application itself cannot release: if it could, so could any program that runs
/// as the user. Windows asks an administrator to confirm (User Account Control).
/// </summary>
internal static class ReleaseAction
{
    /// <summary>
    /// The installed service. Only ever this path: Program Files is not writable for a normal
    /// user, so what is started with administrator rights here cannot have been swapped by one.
    /// </summary>
    public static string ServiceExe =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RCEGuard", "RCEGuard.Service.exe");

    /// <summary>Stands for "every profile" where a profile name is expected.</summary>
    public const string EveryProfile = "*";

    /// <summary>The arguments for releasing one profile, or every profile.</summary>
    public static string Arguments(string profile) =>
        profile == EveryProfile ? "--release" : $"--release \"{profile.Replace("\"", string.Empty)}\"";

    /// <summary>Runs the release command and waits for it. Returns null if it ran, otherwise why it did not.</summary>
    public static string? Run(string profile)
    {
        if (!File.Exists(ServiceExe))
        {
            return $"The guard service was not found at '{ServiceExe}'. Is RCEGuard installed?";
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo(ServiceExe, Arguments(profile))
            {
                UseShellExecute = true,   // needed for "runas"
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null)
            {
                return "The release command could not be started.";
            }

            if (!process.WaitForExit(60_000))
            {
                return "The release command did not finish within a minute.";
            }

            return process.ExitCode == 0 ? null : $"The release command ended with exit code {process.ExitCode}. The log of the guard service says why.";
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED: the question of Windows was answered with "No".
            return "The lockdown was not released: the administrator question of Windows was declined.";
        }
        catch (Win32Exception ex)
        {
            return $"The release command could not be started: {ex.Message}";
        }
    }
}
