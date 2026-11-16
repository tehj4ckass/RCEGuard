using RCEGuard.Core.Client;

namespace RCEGuard.Service;

/// <summary>
/// 'RCEGuard.Service.exe --check-client [file]': says whether a client file has a section that is
/// both writable and executable. Without a file it looks at the client of every profile. It only
/// reads the file on disk and changes nothing; it needs no administrator rights.
/// </summary>
internal static class ClientCheckCommand
{
    /// <summary>Runs the command. Returns 0 if every file could be read, 1 otherwise.</summary>
    public static int Run(ServiceOptions options, TextWriter output, TextWriter error)
    {
        var files = new List<(string Label, string Path)>();
        if (options.CheckClientPath is not null)
        {
            files.Add((options.CheckClientPath, options.CheckClientPath));
        }
        else
        {
            try
            {
                foreach (var profile in options.LoadConfig(out _).Profiles)
                {
                    files.Add(($"'{profile.Name}' ({profile.ClientPath})", profile.ClientPath));
                }
            }
            catch (Exception ex) when (ex is FileNotFoundException or FormatException or IOException or UnauthorizedAccessException)
            {
                error.WriteLine(ex.Message);
                return 1;
            }
        }

        var unread = 0;
        foreach (var (label, path) in files)
        {
            var info = ClientFileInspector.InspectFile(path);
            switch (info.State)
            {
                case ClientFileState.HasWritableCode:
                    output.WriteLine($"{label}: has a section that is both writable and executable ({string.Join(", ", info.WritableExecutableSections)}). Code that gets written there can run.");
                    output.WriteLine("  scripts\\patch-client.ps1 can take the execute right away from it; see \"Patching the client\" in the README.");
                    break;
                case ClientFileState.NoWritableCode:
                    output.WriteLine($"{label}: no section is both writable and executable.");
                    break;
                default:
                    unread++;
                    error.WriteLine($"{label}: cannot say, {(info.State == ClientFileState.Unreadable ? "the file could not be read" : "the file is not a Windows program")}: {info.Problem}");
                    break;
            }
        }

        return unread == 0 ? 0 : 1;
    }
}
