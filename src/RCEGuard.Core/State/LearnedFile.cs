using System.Text.Json;
using RCEGuard.Core.Learning;

namespace RCEGuard.Core.State;

/// <summary>
/// What the learning mode noted, in a small file in the data folder. The guard writes it; the
/// command that shows the suggestion reads it.
/// </summary>
public sealed class LearnedFile
{
    /// <summary>Name of the file in the data folder.</summary>
    public const string FileName = "learned.json";

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private readonly string path;

    /// <summary>Creates the store for the file at <paramref name="path"/>.</summary>
    public LearnedFile(string path) => this.path = path;

    /// <summary>Path of the file.</summary>
    public string Path => path;

    /// <summary>
    /// Reads what was noted. No file means nothing. A file that cannot be understood is reported
    /// through <paramref name="problem"/> and counts as nothing: it only holds observations.
    /// </summary>
    public IReadOnlyList<LearnedProfile> Load(out string? problem)
    {
        problem = null;
        if (!File.Exists(path))
        {
            return [];
        }

        try
        {
            var content = JsonSerializer.Deserialize<Content>(File.ReadAllText(path), Options);
            if (content?.Profiles is null || content.Profiles.Any(profile => profile is null || string.IsNullOrWhiteSpace(profile.Profile)))
            {
                throw new FormatException("no list 'profiles' of entries with a profile name");
            }

            return content.Profiles;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or IOException or UnauthorizedAccessException)
        {
            problem = ex.Message;
            return [];
        }
    }

    /// <summary>Saves what was noted. The file is replaced in one step, so it is never half written.</summary>
    public void Save(IReadOnlyList<LearnedProfile> profiles)
    {
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(new Content([.. profiles]), Options));
        File.Move(temporary, path, overwrite: true);
    }

    private sealed record Content(List<LearnedProfile> Profiles);
}
