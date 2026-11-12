using System.Text.Json;
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
          --help               show this text
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
    public GuardConfig LoadConfig(out string source)
    {
        var configPath = ConfigPath ?? Path.Combine(DataDirectory, "appsettings.json");
        if (File.Exists(configPath))
        {
            source = configPath;
            return GuardConfigJson.Parse(File.ReadAllText(configPath));
        }

        if (ConfigPath is not null)
        {
            throw new FileNotFoundException($"Configuration file not found: {ConfigPath}");
        }

        var statePath = Path.Combine(DataDirectory, "install-state.json");
        if (!File.Exists(statePath))
        {
            throw new FileNotFoundException(
                $"Neither '{configPath}' nor '{statePath}' exists. Run scripts\\install.ps1 first.");
        }

        using var state = JsonDocument.Parse(File.ReadAllText(statePath));
        var clientPath = state.RootElement.TryGetProperty("clientPath", out var value) ? value.GetString() : null;
        if (string.IsNullOrWhiteSpace(clientPath))
        {
            throw new FormatException($"'{statePath}' has no clientPath.");
        }

        source = statePath;
        var config = new GuardConfig { Profiles = [new ClientProfile { Name = "Default", ClientPath = clientPath }] };
        GuardConfigJson.Validate(config);
        return config;
    }
}
