using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Configuration;

/// <summary>How strictly the guard acts, as one choice instead of two settings.</summary>
public enum GuardMode
{
    /// <summary>Normal operation: findings are reported, and the critical ones terminate the client.</summary>
    Protect,

    /// <summary>Everything is judged and reported as in normal operation, but nothing is terminated or locked down ("killEnabled": false).</summary>
    ReportOnly,

    /// <summary>Every profile is in learning mode ("learning": true): the guard collects instead of judging connections, and terminates and blocks nothing.</summary>
    Learning,
}

/// <summary>Reads the mode from a configuration and names it.</summary>
public static class GuardModes
{
    /// <summary>
    /// The mode a configuration amounts to. Null if it is none of the three: some profiles learn and
    /// others do not, or every profile learns while terminating is turned off as well.
    /// </summary>
    public static GuardMode? Of(GuardConfig config)
    {
        var learning = config.Profiles.Count(profile => profile.Learning);
        if (learning == 0)
        {
            return config.KillEnabled ? GuardMode.Protect : GuardMode.ReportOnly;
        }

        return learning == config.Profiles.Count && config.KillEnabled ? GuardMode.Learning : null;
    }

    /// <summary>The mode as it is written on the command line: protect, report-only, learning.</summary>
    public static string Argument(GuardMode mode) => mode switch
    {
        GuardMode.Protect => "protect",
        GuardMode.ReportOnly => "report-only",
        _ => "learning",
    };

    /// <summary>The mode as it is shown to the user.</summary>
    public static string Name(GuardMode mode) => mode switch
    {
        GuardMode.Protect => "Protect",
        GuardMode.ReportOnly => "Report only",
        _ => "Learning",
    };

    /// <summary>One sentence on what the mode means.</summary>
    public static string Describe(GuardMode mode) => mode switch
    {
        GuardMode.Protect => "Findings are reported, and the critical ones terminate the client.",
        GuardMode.ReportOnly => "Findings are reported as in normal operation, but nothing is terminated and nothing is locked down.",
        _ => "The client is watched, not protected: connections are noted instead of judged, and nothing is terminated or blocked.",
    };

    /// <summary>Reads a mode from the command line.</summary>
    public static bool TryParse(string? text, out GuardMode mode)
    {
        foreach (var candidate in Enum.GetValues<GuardMode>())
        {
            if (string.Equals(Argument(candidate), text, StringComparison.OrdinalIgnoreCase))
            {
                mode = candidate;
                return true;
            }
        }

        mode = GuardMode.Protect;
        return false;
    }
}

/// <summary>
/// Changes single settings in the text of a configuration file and leaves everything else in it
/// as it is (the settings it does not know included). Comments in the file do not survive, and the
/// file is written with indentation. Every method returns the new text and throws
/// <see cref="FormatException"/> if the text is not a valid configuration before or after.
/// </summary>
public static class GuardConfigEditor
{
    private static readonly JsonDocumentOptions ReadOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        // Paths and names stay readable: without this an apostrophe or an umlaut is written as \uXXXX.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        // Needed to write values that were added as .NET values (a new address) next to the ones read from the file.
        TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver(),
    };

    /// <summary>The configuration <c>install.ps1</c> stands for when there is no file: one profile for one client.</summary>
    public static string ForProfiles(IEnumerable<ClientProfile> profiles)
    {
        var list = new JsonArray();
        foreach (var profile in profiles)
        {
            list.Add(new JsonObject { ["name"] = profile.Name, ["clientPath"] = profile.ClientPath });
        }

        return Finish(new JsonObject { ["profiles"] = list });
    }

    /// <summary>Sets the mode: "killEnabled" at the top and "learning" on every profile.</summary>
    public static string SetMode(string json, GuardMode mode)
    {
        var root = Read(json);
        Set(root, "killEnabled", mode != GuardMode.ReportOnly);
        foreach (var profile in Profiles(root))
        {
            Set(profile, "learning", mode == GuardMode.Learning);
        }

        return Finish(root);
    }

    /// <summary>Adds an address or a range to "allowedRemote" of one profile.</summary>
    /// <param name="json">Text of the configuration.</param>
    /// <param name="profileName">Name of the profile.</param>
    /// <param name="address">An IP address or a CIDR range.</param>
    /// <param name="added">False if the list covered the address already; the text is then returned unchanged.</param>
    public static string AllowRemote(string json, string profileName, string address, out bool added)
    {
        var entry = address.Trim();
        if (!RemoteAllowlist.TryParseRange(entry, out var range))
        {
            throw new FormatException($"'{address}' is not an IP address or CIDR range.");
        }

        var root = Read(json);
        var profiles = Profiles(root).ToList();
        var profile = profiles.FirstOrDefault(candidate => string.Equals(Text(candidate, "name"), profileName, StringComparison.OrdinalIgnoreCase))
            ?? throw new FormatException(
                $"There is no profile '{profileName}'. Profiles: {string.Join(", ", profiles.Select(candidate => $"'{Text(candidate, "name")}'"))}.");

        var existing = Get(profile, "allowedRemote") as JsonArray;
        var entries = (existing ?? []).Select(node => node?.GetValue<string>() ?? string.Empty).ToList();
        // Covered already: the same entry, or (for a single address) a range that holds it.
        var single = range.PrefixLength == (range.Network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32);
        if (entries.Contains(entry, StringComparer.OrdinalIgnoreCase) || (single && new RemoteAllowlist(entries).Contains(range.Network)))
        {
            added = false;
            return json;
        }

        if (existing is null)
        {
            existing = [];
            Set(profile, "allowedRemote", existing);
        }

        existing.Add(entry);
        added = true;
        return Finish(root);
    }

    private static JsonObject Read(string json)
    {
        // Not a valid configuration to begin with: say so before anything is changed in it.
        GuardConfigJson.Parse(json);
        return JsonNode.Parse(json, nodeOptions: null, ReadOptions) as JsonObject ?? throw new FormatException("Configuration is empty.");
    }

    private static string Finish(JsonObject root)
    {
        var text = root.ToJsonString(WriteOptions) + Environment.NewLine;
        GuardConfigJson.Parse(text);
        return text;
    }

    private static IEnumerable<JsonObject> Profiles(JsonObject root) => (Get(root, "profiles") as JsonArray ?? []).OfType<JsonObject>();

    private static string Text(JsonObject target, string name) => Get(target, name)?.GetValue<string>() ?? string.Empty;

    // The loader does not mind the case of a setting's name, so "KillEnabled" must be found too, not added a second time.
    private static JsonNode? Get(JsonObject target, string name) =>
        target.FirstOrDefault(property => string.Equals(property.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

    private static void Set(JsonObject target, string name, JsonNode? value)
    {
        var existing = target.FirstOrDefault(property => string.Equals(property.Key, name, StringComparison.OrdinalIgnoreCase)).Key;
        target[existing ?? name] = value;
    }
}
