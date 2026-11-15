using RCEGuard.Core.Learning;
using RCEGuard.Core.State;

namespace RCEGuard.Service;

/// <summary>
/// 'RCEGuard.Service.exe --learned [profile]': shows what the learning mode noted and what it
/// suggests for the allowlist. It only reads and changes nothing; the configuration is edited by hand.
/// </summary>
internal static class LearnedCommand
{
    /// <summary>Runs the command. Returns the exit code of the process.</summary>
    public static int Run(ServiceOptions options, TextWriter output, TextWriter error)
    {
        Core.Configuration.GuardConfig config;
        try
        {
            config = options.LoadConfig(out _);
        }
        catch (Exception ex) when (ex is FileNotFoundException or FormatException or IOException or UnauthorizedAccessException)
        {
            error.WriteLine(ex.Message);
            return 1;
        }

        var file = new LearnedFile(Path.Combine(options.DataDirectory, LearnedFile.FileName));
        var learned = file.Load(out var problem);
        if (problem is not null)
        {
            error.WriteLine($"What the learning mode noted ('{file.Path}') cannot be read: {problem}");
            return 1;
        }

        var wanted = config.Profiles
            .Where(profile => options.LearnedProfile is null || string.Equals(profile.Name, options.LearnedProfile, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (wanted.Count == 0)
        {
            error.WriteLine($"There is no profile '{options.LearnedProfile}'. Profiles: {string.Join(", ", config.Profiles.Select(profile => $"'{profile.Name}'"))}.");
            return 1;
        }

        var shown = 0;
        foreach (var profile in wanted)
        {
            var notes = learned.FirstOrDefault(candidate => string.Equals(candidate.Profile, profile.Name, StringComparison.OrdinalIgnoreCase));
            if (notes is null)
            {
                output.WriteLine(profile.Learning
                    ? $"Profile '{profile.Name}': learning mode is ON, nothing was noted yet. Play a session, then run this command again."
                    : $"Profile '{profile.Name}': nothing was noted. Learning mode is off; turn it on with \"learning\": true in the profile and restart the service.");
            }
            else
            {
                output.Write(LearnedReport.Render(notes, profile, config.CpuAlertCores));
                shown++;
            }

            output.WriteLine();
        }

        return shown > 0 || options.LearnedProfile is null ? 0 : 1;
    }
}
