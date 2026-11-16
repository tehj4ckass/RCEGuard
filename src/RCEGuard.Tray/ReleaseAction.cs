namespace RCEGuard.Tray;

/// <summary>
/// Ends a lockdown by starting the release command of the installed service with administrator
/// rights (see <see cref="GuardCommand"/>).
/// </summary>
internal static class ReleaseAction
{
    /// <summary>The installed service.</summary>
    public static string ServiceExe => GuardCommand.ServiceExe;

    /// <summary>Stands for "every profile" where a profile name is expected.</summary>
    public const string EveryProfile = "*";

    /// <summary>The arguments for releasing one profile, or every profile.</summary>
    public static string Arguments(string profile) =>
        profile == EveryProfile ? "--release" : $"--release {GuardCommand.Quote(profile)}";

    /// <summary>Runs the release command and waits for it. Returns null if it ran, otherwise why it did not.</summary>
    public static string? Run(string profile) => GuardCommand.Run(
        Arguments(profile),
        "The release command",
        "The lockdown was not released: the administrator question of Windows was declined.",
        "The log of the guard service says why.");
}
