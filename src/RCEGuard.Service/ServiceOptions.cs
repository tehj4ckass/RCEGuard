using RCEGuard.Core.Configuration;

namespace RCEGuard.Service;

/// <summary>Command line options of the service.</summary>
public sealed record ServiceOptions
{
    /// <summary>Folder with configuration, state and the findings database.</summary>
    public string DataDirectory { get; init; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RCEGuard");

    /// <summary>Explicit configuration file; null means appsettings.json in the data folder.</summary>
    public string? ConfigPath { get; init; }

    /// <summary>Report what would be terminated, but terminate nothing.</summary>
    public bool DryRun { get; init; }

    /// <summary>
    /// Events file (as written by scripts\show-events.ps1 -OutFile) to evaluate instead of the live log.
    /// </summary>
    public string? ReplayPath { get; init; }

    /// <summary>End a lockdown instead of running the guard.</summary>
    public bool Release { get; init; }

    /// <summary>The profile whose lockdown is ended; null means every profile in lockdown.</summary>
    public string? ReleaseProfile { get; init; }

    /// <summary>Send a test notification instead of running the guard.</summary>
    public bool NotifyTest { get; init; }

    /// <summary>Show what the learning mode noted instead of running the guard.</summary>
    public bool Learned { get; init; }

    /// <summary>The profile whose notes are shown; null means every profile.</summary>
    public string? LearnedProfile { get; init; }

    /// <summary>Look at client files instead of running the guard.</summary>
    public bool CheckClient { get; init; }

    /// <summary>The file to look at; null means the client of every profile.</summary>
    public string? CheckClientPath { get; init; }

    /// <summary>
    /// The event log to read. Always the Sysmon log; only tests read another one, because the
    /// Sysmon log needs administrator rights. Not a command line option.
    /// </summary>
    public string LogName { get; init; } = "Microsoft-Windows-Sysmon/Operational";

    /// <summary>Name of the log file in the data folder.</summary>
    public const string LogFileName = "guard.log";

    /// <summary>Name of the file in the data folder that holds the position of the last handled event.</summary>
    public const string PositionFileName = "sysmon-position.json";

    /// <summary>Name of the file in the data folder that is there while the guard runs.</summary>
    public const string RunningMarkerName = "guard-running";

    /// <summary>Usage text for --help.</summary>
    public const string Usage =
        """
        RCEGuard service. Reads the Sysmon log, applies the rules and acts on findings.
        Runs as a Windows service, or in a console started as administrator.

          --dry-run            report findings, but terminate nothing
          --config <file>      configuration file (default: <data-dir>\appsettings.json)
          --data-dir <folder>  data folder (default: C:\ProgramData\RCEGuard)
          --replay <file>      evaluate a saved events file instead of the live log, then exit;
                               never terminates anything and needs no admin rights
          --release [profile]  end the lockdown of that profile (without a name: of every profile),
                               then exit; run it in a console started as administrator
          --notify-test        send a test notification to the configured ntfy topic, then exit;
                               needs no admin rights
          --learned [profile]  show what the learning mode noted for that profile (without a name:
                               for every profile) and what it suggests for the allowlist, then
                               exit; changes nothing and needs no admin rights
          --check-client [file]  say whether that program file (without a file: the client of
                               every profile) has a section that is both writable and
                               executable, then exit; only reads, needs no admin rights
          --help               show this text

        The live guard writes its log to <data-dir>\guard.log and its findings to <data-dir>\findings.db.
        It notes the last event it handled in <data-dir>\sysmon-position.json and, when started again,
        first reads what was written to the Sysmon log in the meantime.
        Profiles in lockdown are noted in <data-dir>\lockdown.json, what profiles with
        "learning": true did in <data-dir>\learned.json.
        """;

    /// <summary>Parses the arguments; returns null and an error text if they are not understood.</summary>
    public static ServiceOptions? Parse(string[] args, out string error)
    {
        var options = new ServiceOptions();
        error = string.Empty;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--dry-run":
                    options = options with { DryRun = true };
                    break;
                case "--config" when i + 1 < args.Length:
                    options = options with { ConfigPath = Path.GetFullPath(args[++i]) };
                    break;
                case "--data-dir" when i + 1 < args.Length:
                    options = options with { DataDirectory = Path.GetFullPath(args[++i]) };
                    break;
                case "--replay" when i + 1 < args.Length:
                    options = options with { ReplayPath = Path.GetFullPath(args[++i]) };
                    break;
                case "--notify-test":
                    options = options with { NotifyTest = true };
                    break;
                case "--check-client":
                    options = options with { CheckClient = true };
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        options = options with { CheckClientPath = Path.GetFullPath(args[++i]) };
                    }

                    break;
                case "--learned":
                    options = options with { Learned = true };
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        options = options with { LearnedProfile = args[++i] };
                    }

                    break;
                case "--release":
                    options = options with { Release = true };
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        options = options with { ReleaseProfile = args[++i] };
                    }

                    break;
                default:
                    error = $"Unknown or incomplete argument '{args[i]}'.";
                    return null;
            }
        }

        return options;
    }

    /// <summary>
    /// Loads the configuration. Without a configuration file the client the sensor was installed
    /// for (install-state.json) becomes the only profile, with an empty allowlist.
    /// </summary>
    public GuardConfig LoadConfig(out string source) => GuardConfigFile.Load(DataDirectory, ConfigPath, out source);
}
