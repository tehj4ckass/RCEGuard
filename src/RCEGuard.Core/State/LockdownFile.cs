using System.Text.Json;

namespace RCEGuard.Core.State;

/// <summary>A profile in lockdown and the finding that caused it.</summary>
/// <param name="Profile">Name of the profile.</param>
/// <param name="SinceUtc">Time of the event that caused the lockdown.</param>
/// <param name="Rule">Rule id of the finding.</param>
/// <param name="Summary">Summary of the finding.</param>
public sealed record LockdownEntry(string Profile, DateTimeOffset SinceUtc, string Rule, string Summary);

/// <summary>
/// The profiles in lockdown, in a small file in the data folder. The file is what counts: the
/// firewall rules are written from it, by the guard and by the release command alike, so a
/// lockdown outlasts a restart of the guard and of Windows.
/// </summary>
public sealed class LockdownFile
{
    /// <summary>Name of the file in the data folder.</summary>
    public const string FileName = "lockdown.json";

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private readonly string path;

    /// <summary>Creates the store for the file at <paramref name="path"/>.</summary>
    public LockdownFile(string path) => this.path = path;

    /// <summary>Path of the file.</summary>
    public string Path => path;

    /// <summary>When the file was last written, or null if there is none.</summary>
    public DateTime? Stamp()
    {
        try
        {
            return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the profiles in lockdown. No file means none. A file that cannot be understood is
    /// reported through <paramref name="problem"/>; the caller then has to assume the worst.
    /// </summary>
    public IReadOnlyList<LockdownEntry> Load(out string? problem)
    {
        problem = null;
        if (!File.Exists(path))
        {
            return [];
        }

        try
        {
            var content = JsonSerializer.Deserialize<Content>(File.ReadAllText(path), Options);
            if (content?.Locked is null || content.Locked.Any(entry => entry is null || string.IsNullOrWhiteSpace(entry.Profile)))
            {
                throw new FormatException("no list 'locked' of entries with a profile name");
            }

            return content.Locked;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or IOException or UnauthorizedAccessException)
        {
            problem = ex.Message;
            return [];
        }
    }

    /// <summary>Saves the profiles in lockdown. The file is replaced in one step, so it is never half written.</summary>
    public void Save(IReadOnlyList<LockdownEntry> entries)
    {
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(new Content([.. entries]), Options));
        File.Move(temporary, path, overwrite: true);
    }

    private sealed record Content(List<LockdownEntry> Locked);
}
