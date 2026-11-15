using System.Text.Json;

namespace RCEGuard.Core.Configuration;

/// <summary>Finds and loads the configuration in the data folder, for the service and for the tray application.</summary>
public static class GuardConfigFile
{
    /// <summary>Name of the configuration file in the data folder.</summary>
    public const string FileName = "appsettings.json";

    /// <summary>Name of the file install.ps1 writes to the data folder.</summary>
    public const string InstallStateName = "install-state.json";

    /// <summary>
    /// Loads the configuration. Without a configuration file the client the sensor was installed
    /// for (install-state.json) becomes the only profile, with an empty allowlist.
    /// </summary>
    /// <param name="dataDirectory">The data folder.</param>
    /// <param name="explicitPath">A configuration file to use instead of the one in the data folder, or null.</param>
    /// <param name="source">The file the configuration came from.</param>
    /// <exception cref="FileNotFoundException">Neither file exists, or the explicit file does not.</exception>
    /// <exception cref="FormatException">The file is not a valid configuration.</exception>
    public static GuardConfig Load(string dataDirectory, string? explicitPath, out string source)
    {
        var configPath = explicitPath ?? Path.Combine(dataDirectory, FileName);
        if (File.Exists(configPath))
        {
            source = configPath;
            return GuardConfigJson.Parse(File.ReadAllText(configPath));
        }

        if (explicitPath is not null)
        {
            throw new FileNotFoundException($"Configuration file not found: {explicitPath}");
        }

        var statePath = Path.Combine(dataDirectory, InstallStateName);
        if (!File.Exists(statePath))
        {
            throw new FileNotFoundException(
                $"Neither '{configPath}' nor '{statePath}' exists. Run scripts\\install.ps1 first.");
        }

        string? clientPath;
        try
        {
            using var state = JsonDocument.Parse(File.ReadAllText(statePath));
            clientPath = state.RootElement.TryGetProperty("clientPath", out var value) ? value.GetString() : null;
        }
        catch (JsonException ex)
        {
            throw new FormatException($"'{statePath}' is not valid JSON: {ex.Message}", ex);
        }

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
