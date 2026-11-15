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

    /// <summary>
    /// Seconds during which a repeated alert (same rule, client process and target) is only counted
    /// instead of reported again. 0 reports every occurrence. Findings that terminate a process are
    /// never held back.
    /// </summary>
    public int RepeatWindowSeconds { get; init; } = 300;

    /// <summary>
    /// If true, a finding that terminates a client also puts its profile in lockdown: Windows
    /// Firewall blocks every outbound connection of the client until the lockdown is released.
    /// Off by default. Like terminating, it does not happen while <see cref="KillEnabled"/> is false.
    /// </summary>
    public bool Lockdown { get; init; }

    /// <summary>Where findings are reported besides the log and the database. Null: nowhere else.</summary>
    public NotifyConfig? Notify { get; init; }
}

/// <summary>Notification settings.</summary>
public sealed record NotifyConfig
{
    /// <summary>Push notifications through an ntfy server. Null: none.</summary>
    public NtfyConfig? Ntfy { get; init; }

    /// <summary>If false, the tray application shows no pop-up for a new finding. On by default.</summary>
    public bool Toast { get; init; } = true;
}

/// <summary>
/// An ntfy topic that gets a message for every finding that alerts or terminates. The message
/// leaves the machine: it names the rule, the program, the address or file, and the computer.
/// </summary>
public sealed record NtfyConfig
{
    /// <summary>If false, nothing is sent although the rest is filled in.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Full address of the topic, e.g. https://ntfy.example.org/my-topic.</summary>
    public string Url { get; init; } = string.Empty;

    /// <summary>Access token of the ntfy server, if the topic needs one. Sent as "Authorization: Bearer".</summary>
    public string? Token { get; init; }
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

    /// <summary>
    /// If true, Windows Firewall blocks outbound connections of the client to every address that
    /// is neither in <see cref="AllowedRemote"/> nor an address of <see cref="AllowedHostnames"/>.
    /// Off by default. Needs at least one allowed address or host name.
    /// </summary>
    public bool Firewall { get; init; }

    /// <summary>
    /// Learning mode: for this client nothing is terminated, locked down or blocked by the
    /// firewall rule of the profile; connections to addresses that are not on the allowlist are
    /// only noted. What the client does is collected for a suggestion (see
    /// <see cref="RCEGuard.Core.Learning.LearnedReport"/>). Off by default; meant for the first sessions with a
    /// client, and to be turned off again by hand.
    /// </summary>
    public bool Learning { get; init; }

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

        if (config.RepeatWindowSeconds is < 0 or > 86400)
        {
            throw new FormatException($"repeatWindowSeconds must be between 0 and 86400, got {config.RepeatWindowSeconds}.");
        }

        if (config.Notify?.Ntfy is { Enabled: true } ntfy)
        {
            if (!Uri.TryCreate(ntfy.Url, UriKind.Absolute, out var topic)
                || (topic.Scheme != Uri.UriSchemeHttp && topic.Scheme != Uri.UriSchemeHttps)
                || topic.AbsolutePath.Trim('/').Length == 0)
            {
                throw new FormatException($"notify.ntfy.url must be the full address of a topic (http or https, e.g. https://ntfy.example.org/my-topic), got '{ntfy.Url}'.");
            }
        }

        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in config.Profiles)
        {
            if (string.IsNullOrWhiteSpace(profile.Name))
            {
                throw new FormatException("A profile has no name.");
            }

            // The name identifies the profile: in the findings, for the resolved host names and in
            // the name of its firewall rule. Windows Firewall does not take '|' in a rule name.
            if (!seenNames.Add(profile.Name))
            {
                throw new FormatException($"The profile name '{profile.Name}' is used by more than one profile.");
            }

            if (profile.Name.Contains('|'))
            {
                throw new FormatException($"Profile '{profile.Name}': the name must not contain '|'.");
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

            if (profile.Firewall && (profile.AllowedRemote ?? []).Count == 0 && (profile.AllowedHostnames ?? []).Count == 0)
            {
                throw new FormatException(
                    $"Profile '{profile.Name}': firewall is on, but neither allowedRemote nor allowedHostnames names an address. That would block every connection of the client.");
            }
        }
    }
}
