using System.Globalization;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Learning;
using RCEGuard.Core.State;

namespace RCEGuard.Tray.Model;

/// <summary>Whether the Windows service of the guard runs.</summary>
internal enum ServiceState
{
    /// <summary>There is no service named RCEGuard.</summary>
    NotInstalled,

    /// <summary>The service is installed and not running.</summary>
    Stopped,

    /// <summary>The service is starting or stopping.</summary>
    Changing,

    /// <summary>The service is running.</summary>
    Running,
}

/// <summary>What the tray application knows about the guard, read from the data folder and from Windows.</summary>
/// <param name="Service">State of the Windows service.</param>
/// <param name="Profiles">The watched clients; empty if the configuration could not be read.</param>
/// <param name="ConfigProblem">Why the configuration could not be read, or null.</param>
/// <param name="Locked">The profiles in lockdown.</param>
/// <param name="LockdownProblem">Why the lockdown state could not be read, or null. The service then treats every profile as locked.</param>
/// <param name="ToastEnabled">Whether new findings are shown as a pop-up.</param>
/// <param name="Learned">What the learning mode noted, per profile; empty if there is nothing or it cannot be read.</param>
/// <param name="CpuAlertCores">The processor load above which R8 reports (0: the rule is off).</param>
internal sealed record GuardStatus(
    ServiceState Service,
    IReadOnlyList<ClientProfile> Profiles,
    string? ConfigProblem,
    IReadOnlyList<LockdownEntry> Locked,
    string? LockdownProblem,
    bool ToastEnabled,
    IReadOnlyList<LearnedProfile>? Learned = null,
    double CpuAlertCores = 0)
{
    /// <summary>The profiles in learning mode: their clients are watched, not protected.</summary>
    public IReadOnlyList<ClientProfile> Learning => [.. Profiles.Where(profile => profile.Learning)];
}

/// <summary>Reads the status. Only reads: files in the data folder and the state of the service.</summary>
internal sealed class StatusReader
{
    private readonly string dataDirectory;
    private readonly Func<ServiceState> serviceState;

    /// <summary>Creates the reader.</summary>
    /// <param name="dataDirectory">Data folder of the service.</param>
    /// <param name="serviceState">Asks Windows for the state of the service; tests replace it.</param>
    public StatusReader(string dataDirectory, Func<ServiceState>? serviceState = null)
    {
        this.dataDirectory = dataDirectory;
        this.serviceState = serviceState ?? QueryService;
    }

    /// <summary>Reads everything anew.</summary>
    public GuardStatus Read()
    {
        IReadOnlyList<ClientProfile> profiles = [];
        string? configProblem = null;
        var toast = true;
        var cpuAlertCores = 0.0;
        try
        {
            var config = GuardConfigFile.Load(dataDirectory, explicitPath: null, out _);
            profiles = config.Profiles;
            toast = config.Notify?.Toast ?? true;
            cpuAlertCores = config.CpuAlertCores;
        }
        catch (FileNotFoundException)
        {
            configProblem = "RCEGuard is not installed (no configuration in the data folder).";
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            configProblem = ex.Message;
        }

        var locked = new LockdownFile(Path.Combine(dataDirectory, LockdownFile.FileName)).Load(out var lockdownProblem);
        // Notes that cannot be read are no notes: they are only shown.
        var learned = new LearnedFile(Path.Combine(dataDirectory, LearnedFile.FileName)).Load(out _);
        return new GuardStatus(serviceState(), profiles, configProblem, locked, lockdownProblem, toast, learned, cpuAlertCores);
    }

    private static ServiceState QueryService()
    {
        try
        {
            using var service = new System.ServiceProcess.ServiceController("RCEGuard");
            return service.Status switch
            {
                System.ServiceProcess.ServiceControllerStatus.Running => ServiceState.Running,
                System.ServiceProcess.ServiceControllerStatus.Stopped => ServiceState.Stopped,
                _ => ServiceState.Changing,
            };
        }
        catch (InvalidOperationException)
        {
            // No such service.
            return ServiceState.NotInstalled;
        }
    }
}

/// <summary>What the notification area icon stands for.</summary>
internal enum TrayKind
{
    /// <summary>The service runs and there is nothing new.</summary>
    Watching,

    /// <summary>There are findings the user has not looked at.</summary>
    Alert,

    /// <summary>A profile is in lockdown.</summary>
    Locked,

    /// <summary>A profile is in learning mode: its client is watched, but nothing is terminated or blocked for it.</summary>
    Learning,

    /// <summary>The service is not running: the client is not watched.</summary>
    NotWatching,
}

/// <summary>The one-glance state: icon, tooltip and the two lines at the top of the window.</summary>
/// <param name="Kind">Which icon.</param>
/// <param name="Tooltip">Text of the icon; Windows shows at most 127 characters, kept shorter here.</param>
/// <param name="Headline">First line in the window.</param>
/// <param name="Detail">Second line in the window.</param>
internal sealed record TrayState(TrayKind Kind, string Tooltip, string Headline, string Detail)
{
    /// <summary>
    /// Works the state out. What counts most comes first: a guard that is not running, then a
    /// lockdown, then findings nobody has looked at, then a client that is only watched (learning mode).
    /// </summary>
    public static TrayState From(GuardStatus status, int unseen)
    {
        var clients = status.Profiles.Count switch
        {
            0 => "no client",
            1 => $"'{status.Profiles[0].Name}'",
            _ => $"{status.Profiles.Count} clients",
        };

        if (status.Service != ServiceState.Running)
        {
            var (headline, detail) = status.Service switch
            {
                ServiceState.NotInstalled => ("RCEGuard is not installed", "There is no guard service on this machine. Nothing is watched."),
                ServiceState.Stopped => ("RCEGuard is not running", "The guard service is stopped. The client is not watched."),
                _ => ("RCEGuard is starting or stopping", "The guard service is changing its state."),
            };
            return new TrayState(TrayKind.NotWatching, Limit(headline), headline, detail);
        }

        if (status.LockdownProblem is not null)
        {
            return new TrayState(
                TrayKind.Locked,
                "RCEGuard: every client is locked down",
                "Every client is locked down",
                $"The lockdown state cannot be read ({status.LockdownProblem}). Until it is released, the firewall blocks every connection of every watched client.");
        }

        if (status.Locked.Count > 0)
        {
            var names = string.Join(", ", status.Locked.Select(entry => $"'{entry.Profile}'"));
            return new TrayState(
                TrayKind.Locked,
                Limit($"RCEGuard: {names} locked down"),
                status.Locked.Count == 1 ? $"{names} is locked down" : $"{names} are locked down",
                "The firewall blocks every connection of the client until the lockdown is released.");
        }

        var learning = status.Learning;
        var learningNames = string.Join(", ", learning.Select(profile => $"'{profile.Name}'"));
        if (unseen > 0)
        {
            var findings = unseen == 1 ? "1 new finding" : $"{unseen} new findings";
            var note = learning.Count == 0 ? string.Empty : $" Learning mode is on for {learningNames}: nothing is terminated or blocked there.";
            return new TrayState(TrayKind.Alert, Limit($"RCEGuard: {findings}"), findings, $"RCEGuard is watching {clients}." + note);
        }

        if (learning.Count > 0)
        {
            // Said first and plainly: for these clients the guard is no protection right now.
            return new TrayState(
                TrayKind.Learning,
                Limit($"RCEGuard: learning mode for {learningNames} (not protected)"),
                $"Learning mode: {learningNames} {(learning.Count == 1 ? "is" : "are")} watched, not protected",
                "For a client in learning mode nothing is terminated, locked down or blocked; what it does is noted. " +
                "Turn it off in appsettings.json (\"learning\": false) and restart the service when you are done.");
        }

        var problem = status.ConfigProblem is null ? string.Empty : $" The configuration cannot be read here: {status.ConfigProblem}";
        return new TrayState(TrayKind.Watching, Limit($"RCEGuard: watching {clients}"), $"Watching {clients}", "The guard service is running." + problem);
    }

    /// <summary>One line for a profile in lockdown.</summary>
    public static string Describe(LockdownEntry entry) =>
        $"'{entry.Profile}' since {entry.SinceUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}, after {entry.Rule}: {entry.Summary}";

    private static string Limit(string text) => text.Length <= 100 ? text : text[..97] + "...";
}

/// <summary>
/// Remembers, per Windows user, the newest finding this user was already told about, so that a
/// start of the tray application announces what happened in the meantime and nothing twice.
/// </summary>
internal sealed class SeenFile
{
    private readonly string path;

    /// <summary>Creates the store for the file at <paramref name="path"/>.</summary>
    public SeenFile(string path) => this.path = path;

    /// <summary>
    /// The place for a data folder: %LOCALAPPDATA%\RCEGuard\tray-state.txt of the current user for
    /// the data folder of the installed service, a file of its own for any other folder (someone
    /// looking at a copy must not move the mark of the real installation).
    /// </summary>
    public static string PathFor(string dataDirectory)
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RCEGuard");
        var installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RCEGuard");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataDirectory));
        if (string.Equals(full, installed, StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(folder, "tray-state.txt");
        }

        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(full.ToUpperInvariant()));
        return Path.Combine(folder, $"tray-state-{Convert.ToHexString(hash, 0, 4).ToLowerInvariant()}.txt");
    }

    /// <summary>The id that was saved, or null if nothing was saved yet (or it cannot be read).</summary>
    public long? Load()
    {
        try
        {
            return File.Exists(path) && long.TryParse(File.ReadAllText(path).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var id) ? id : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Saves the id. Failing to do so is not worth an error: the worst case is a pop-up twice.</summary>
    public void Save(long id)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, id.ToString(CultureInfo.InvariantCulture));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nothing to do.
        }
    }
}
