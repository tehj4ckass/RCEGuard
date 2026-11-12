using System.Text.Json;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Configuration;

/// <summary>Configuration of the guard: which clients are watched and how strictly.</summary>
public sealed record GuardConfig
{
    /// <summary>The watched clients. At least one.</summary>
    public IReadOnlyList<ClientProfile> Profiles { get; init; } = [];

    /// <summary>
    /// If false, nothing is terminated: findings that would kill a process are only reported.
    /// </summary>
    public bool KillEnabled { get; init; } = true;
}

/// <summary>One watched game client and the server it is allowed to talk to.</summary>
public sealed record ClientProfile
{
    /// <summary>Display name, e.g. "Warmane".</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Full path of the client executable, e.g. D:\Games\Warmane\Wow.exe.</summary>
    public string ClientPath { get; init; } = string.Empty;

    /// <summary>Remote addresses the client may connect to: single IPs or CIDR ranges.</summary>
    public IReadOnlyList<string> AllowedRemote { get; init; } = [];

    /// <summary>Host names whose addresses are allowed; the service resolves them periodically.</summary>
    public IReadOnlyList<string> AllowedHostnames { get; init; } = [];

    /// <summary>If true, a connection to an unknown address also terminates the client (R2).</summary>
    public bool KillOnUnknownRemote { get; init; }

    /// <summary>Folder of the client with a trailing backslash.</summary>
    public string GameDirectory
    {
        get
        {
            var index = ClientPath.LastIndexOf('\\');
            return index < 0 ? string.Empty : ClientPath[..(index + 1)];
        }
    }
}

/// <summary>Reads and validates the JSON form of <see cref="GuardConfig"/>.</summary>
public static class GuardConfigJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Parses and validates a configuration. Throws <see cref="FormatException"/> with the reason.</summary>
    public static GuardConfig Parse(string json)
    {
        GuardConfig? config;
        try
        {
            config = JsonSerializer.Deserialize<GuardConfig>(json, Options);
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Configuration is not valid JSON: {ex.Message}", ex);
        }

        if (config is null)
        {
            throw new FormatException("Configuration is empty.");
        }

        Validate(config);
        return config;
    }

    /// <summary>Checks a configuration and throws <see cref="FormatException"/> for the first problem.</summary>
    public static void Validate(GuardConfig config)
    {
        if (config.Profiles is null || config.Profiles.Count == 0)
        {
            throw new FormatException("Configuration has no profiles.");
        }

        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in config.Profiles)
        {
            if (string.IsNullOrWhiteSpace(profile.Name))
            {
                throw new FormatException("A profile has no name.");
            }

            // Not Path.IsPathRooted: the core also runs its tests on non-Windows machines.
            var path = profile.ClientPath ?? string.Empty;
            var rooted = path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\';
            if (!rooted || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new FormatException($"Profile '{profile.Name}': clientPath must be a full path to an .exe, got '{path}'.");
            }

            if (!seenPaths.Add(path))
            {
                throw new FormatException($"Profile '{profile.Name}': clientPath '{path}' is used by more than one profile.");
            }

            foreach (var entry in profile.AllowedRemote ?? [])
            {
                if (!RemoteAllowlist.TryParseRange(entry, out _))
                {
                    throw new FormatException($"Profile '{profile.Name}': '{entry}' is not an IP address or CIDR range.");
                }
            }
        }
    }
}
