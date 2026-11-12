using System.Net;
using System.Text.RegularExpressions;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Rules;

/// <summary>
/// Turns Sysmon events into findings (rules R1–R7 and R9 of the concept).
/// The engine keeps a little state (children the client started) and is not thread-safe:
/// feed it events one at a time, in log order.
/// </summary>
public sealed class RuleEngine
{
    private const int MaxTrackedChildren = 4096;

    private static readonly string[] MinerMarkers = ["stratum+tcp", "stratum+ssl", "xmrig", "--donate-level"];

    private readonly GuardConfig config;
    private readonly Dictionary<string, RemoteAllowlist> staticAllowlists = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<IPAddress>> resolvedHosts = new(StringComparer.OrdinalIgnoreCase);

    // Process GUID of a child -> process GUID of the client that started it.
    private readonly Dictionary<string, string> childToClient = new(StringComparer.OrdinalIgnoreCase);

    private readonly string consoleHostImage;
    private readonly Regex consoleHostCommandLine;

    /// <summary>Creates an engine for a validated configuration.</summary>
    /// <param name="config">Profiles to watch.</param>
    /// <param name="systemDirectory">
    /// The Windows system directory of the watched machine (the service passes its own);
    /// used to recognise the console host that Windows itself starts for a console program.
    /// </param>
    public RuleEngine(GuardConfig config, string systemDirectory = @"C:\Windows\System32")
    {
        GuardConfigJson.Validate(config);
        this.config = config;
        consoleHostImage = systemDirectory.TrimEnd('\\') + @"\conhost.exe";

        // Exactly what the kernel passes: the NT path of conhost.exe and the handle of the console
        // session, e.g. "\??\C:\WINDOWS\system32\conhost.exe 0x4". Anything else on the command line
        // (conhost.exe can start other programs) stays an ordinary R1.
        consoleHostCommandLine = new Regex(
            @"^\\\?\?\\" + Regex.Escape(consoleHostImage) + @" 0x[0-9a-f]{1,16}( -ForceV1)?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (var profile in config.Profiles)
        {
            staticAllowlists[profile.Name] = new RemoteAllowlist(profile.AllowedRemote);
        }
    }

    /// <summary>
    /// Replaces the addresses the service resolved for a profile's allowed host names.
    /// </summary>
    public void SetResolvedHosts(string profileName, IEnumerable<IPAddress> addresses) =>
        resolvedHosts[profileName] = [.. addresses.Select(RemoteAllowlist.Normalize)];

    /// <summary>Evaluates one event. Returns no findings for events that are expected.</summary>
    public IReadOnlyList<Finding> Evaluate(SysmonEvent e) => e.EventId switch
    {
        SysmonEventIds.ProcessCreate => OnProcessCreate(e),
        SysmonEventIds.ProcessTerminate => OnProcessTerminate(e),
        SysmonEventIds.NetworkConnect => OnNetworkConnect(e),
        SysmonEventIds.ImageLoad => OnImageLoad(e),
        SysmonEventIds.CreateRemoteThread => OnCreateRemoteThread(e),
        SysmonEventIds.ProcessAccess => OnProcessAccess(e),
        SysmonEventIds.FileCreate => OnFileCreate(e),
        SysmonEventIds.RegistryCreateDelete or SysmonEventIds.RegistrySetValue or SysmonEventIds.RegistryRename => OnRegistry(e),
        _ => [],
    };

    private ClientProfile? ProfileFor(string image)
    {
        foreach (var profile in config.Profiles)
        {
            if (PathRules.Same(profile.ClientPath, image))
            {
                return profile;
            }
        }

        return null;
    }

    // --- Event 1: R1 (child of the client) and R9 (miner-like command line) -------------------
    private IReadOnlyList<Finding> OnProcessCreate(SysmonEvent e)
    {
        var image = e.Get("Image");
        var commandLine = e.Get("CommandLine");
        var parentImage = e.Get("ParentImage");
        var pid = e.GetInt("ProcessId");
        var parentProfile = ProfileFor(parentImage);
        var looksLikeMiner = MinerMarkers.Any(marker => commandLine.Contains(marker, StringComparison.OrdinalIgnoreCase));

        var findings = new List<Finding>();
        IReadOnlyList<KillTarget> killChildAndClient = [];

        if (parentProfile is not null && IsConsoleHostStartedByWindows(image, commandLine))
        {
            // Windows starts conhost.exe as a child of every console program that gets its own console.
            // The client did not choose that program and it runs nothing else, so it is no reason to
            // terminate anything. A graphical client has no console, hence still worth a log line.
            RememberChild(e.Get("ProcessGuid"), e.Get("ParentProcessGuid"));
            findings.Add(new Finding
            {
                RuleId = "R1",
                Severity = Severity.Medium,
                Action = FindingAction.Log,
                Summary = "Windows attached a console to the game client (conhost.exe)",
                Profile = parentProfile.Name,
                Image = parentImage,
                ProcessId = e.GetInt("ParentProcessId"),
                Target = image,
                CommandLine = commandLine,
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            });
        }
        else if (parentProfile is not null)
        {
            RememberChild(e.Get("ProcessGuid"), e.Get("ParentProcessGuid"));

            var targets = new List<KillTarget>();
            if (pid is { } childPid)
            {
                targets.Add(new KillTarget(childPid, image, IncludeDescendants: true));
            }

            if (e.GetInt("ParentProcessId") is { } parentPid)
            {
                targets.Add(new KillTarget(parentPid, parentImage, IncludeDescendants: true));
            }

            killChildAndClient = targets;
            findings.Add(new Finding
            {
                RuleId = "R1",
                Severity = Severity.Critical,
                Action = FindingAction.Kill,
                Summary = $"The game client started another program: {image}",
                Profile = parentProfile.Name,
                Image = parentImage,
                ProcessId = e.GetInt("ParentProcessId"),
                Target = image,
                CommandLine = commandLine,
                KillTargets = killChildAndClient,
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            });
        }

        if (looksLikeMiner)
        {
            // Only a process the client started is terminated. Anywhere else the match is a string
            // in a command line and nothing ties it to the client, so it is reported, not killed.
            findings.Add(new Finding
            {
                RuleId = "R9",
                Severity = Severity.Critical,
                Action = parentProfile is not null ? FindingAction.Kill : FindingAction.Alert,
                Summary = $"A program was started with a coin-miner command line: {image}",
                Profile = parentProfile?.Name ?? string.Empty,
                Image = image,
                ProcessId = pid,
                Target = image,
                CommandLine = commandLine,
                KillTargets = killChildAndClient,
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            });
        }

        return findings;
    }

    private bool IsConsoleHostStartedByWindows(string image, string commandLine) =>
        PathRules.Same(image, consoleHostImage) && consoleHostCommandLine.IsMatch(commandLine);

    private IReadOnlyList<Finding> OnProcessTerminate(SysmonEvent e)
    {
        var clientGuid = e.Get("ProcessGuid");
        if (ProfileFor(e.Get("Image")) is not null && clientGuid.Length > 0)
        {
            foreach (var child in childToClient.Where(pair => string.Equals(pair.Value, clientGuid, StringComparison.OrdinalIgnoreCase)).Select(pair => pair.Key).ToList())
            {
                childToClient.Remove(child);
            }
        }

        return [];
    }

    private void RememberChild(string childGuid, string clientGuid)
    {
        if (childGuid.Length == 0)
        {
            return;
        }

        if (childToClient.Count >= MaxTrackedChildren)
        {
            childToClient.Clear(); // Bounded on purpose; losing the hint only makes R7 log an own child.
        }

        childToClient[childGuid] = clientGuid;
    }

    // --- Event 3: R2 (connection to an address that is not on the allowlist) ------------------
    private IReadOnlyList<Finding> OnNetworkConnect(SysmonEvent e)
    {
        var image = e.Get("Image");
        var profile = ProfileFor(image);
        if (profile is null)
        {
            return [];
        }

        var remote = e.Get("DestinationIp");
        var port = e.Get("DestinationPort");
        var target = $"{remote}:{port}";
        var outbound = string.Equals(e.Get("Initiated"), "true", StringComparison.OrdinalIgnoreCase);

        if (!IPAddress.TryParse(remote, out var address))
        {
            // Fail closed: an address that cannot be read cannot be shown to be allowed.
            return [NetworkFinding(e, profile, image, target, $"The game client connected to an address that could not be read: '{remote}'")];
        }

        address = RemoteAllowlist.Normalize(address);
        if (IPAddress.IsLoopback(address) || IsAllowed(profile, address))
        {
            return [];
        }

        if (!outbound)
        {
            return
            [
                new Finding
                {
                    RuleId = "R2",
                    Severity = Severity.Medium,
                    Action = FindingAction.Log,
                    Summary = $"The game client received a connection from {target}",
                    Profile = profile.Name,
                    Image = image,
                    ProcessId = e.GetInt("ProcessId"),
                    Target = target,
                    Time = e.TimeCreated,
                    RecordId = e.RecordId,
                },
            ];
        }

        return [NetworkFinding(e, profile, image, target, $"The game client connected to an address that is not on the allowlist: {target}")];
    }

    private bool IsAllowed(ClientProfile profile, IPAddress address) =>
        staticAllowlists[profile.Name].Contains(address)
        || (resolvedHosts.TryGetValue(profile.Name, out var resolved) && resolved.Contains(address));

    private static Finding NetworkFinding(SysmonEvent e, ClientProfile profile, string image, string target, string summary)
    {
        var pid = e.GetInt("ProcessId");
        var kill = profile.KillOnUnknownRemote && pid is not null;
        return new Finding
        {
            RuleId = "R2",
            Severity = Severity.Critical,
            Action = kill ? FindingAction.Kill : FindingAction.Alert,
            Summary = summary,
            Profile = profile.Name,
            Image = image,
            ProcessId = pid,
            Target = target,
            KillTargets = kill ? [new KillTarget(pid!.Value, image, IncludeDescendants: true)] : [],
            Time = e.TimeCreated,
            RecordId = e.RecordId,
        };
    }

    // --- Event 11: R3 (file created where the client has no business) -------------------------
    private IReadOnlyList<Finding> OnFileCreate(SysmonEvent e)
    {
        var image = e.Get("Image");
        var profile = ProfileFor(image);
        if (profile is null)
        {
            return [];
        }

        var file = e.Get("TargetFilename");
        var insideGameFolder = PathRules.IsUnder(file, profile.GameDirectory);
        var executable = PathRules.HasExecutableExtension(file);
        var startup = PathRules.IsStartupFolder(file);

        string summary;
        Severity severity;
        if (startup)
        {
            (severity, summary) = (Severity.High, $"The game client created a file in a Startup folder: {file}");
        }
        else if (executable && insideGameFolder)
        {
            (severity, summary) = (Severity.High, $"The game client created a program file in its own folder: {file}");
        }
        else if (executable)
        {
            (severity, summary) = (Severity.High, $"The game client created a program file outside its folder: {file}");
        }
        else if (!insideGameFolder)
        {
            (severity, summary) = (Severity.Medium, $"The game client created a file outside its folder: {file}");
        }
        else
        {
            return []; // Ordinary data file inside the game folder.
        }

        return
        [
            new Finding
            {
                RuleId = "R3",
                Severity = severity,
                Action = severity >= Severity.High ? FindingAction.Alert : FindingAction.Log,
                Summary = summary,
                Profile = profile.Name,
                Image = image,
                ProcessId = e.GetInt("ProcessId"),
                Target = file,
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            },
        ];
    }

    // --- Events 12/13/14: R4 (autostart, Winlogon, services, debugger hijack) -----------------
    private IReadOnlyList<Finding> OnRegistry(SysmonEvent e)
    {
        var image = e.Get("Image");
        var profile = ProfileFor(image);
        if (profile is null)
        {
            return [];
        }

        var key = e.Get("TargetObject");
        var eventType = e.Get("EventType");
        var concern = RegistryRules.Classify(key, eventType);
        if (concern == RegistryConcern.None)
        {
            return [];
        }

        var pid = e.GetInt("ProcessId");
        var what = concern switch
        {
            RegistryConcern.Autostart => "an autostart entry",
            RegistryConcern.Winlogon => "the Windows logon settings",
            RegistryConcern.ImageFileExecutionOptions => "the debugger settings of a program",
            RegistryConcern.ServiceConfiguration => "a Windows service",
            _ => "a key below Services",
        };

        Severity severity;
        FindingAction action;
        string verb;
        if (concern == RegistryConcern.ServicesOther)
        {
            (severity, action, verb) = (Severity.Info, FindingAction.Log, "wrote");
        }
        else if (RegistryRules.IsDeletion(eventType))
        {
            (severity, action, verb) = (Severity.Medium, FindingAction.Log, "removed");
        }
        else
        {
            (severity, action, verb) = (Severity.Critical, pid is null ? FindingAction.Alert : FindingAction.Kill, "changed");
        }

        return
        [
            new Finding
            {
                RuleId = "R4",
                Severity = severity,
                Action = action,
                Summary = $"The game client {verb} {what}: {key}",
                Profile = profile.Name,
                Image = image,
                ProcessId = pid,
                Target = key,
                KillTargets = action == FindingAction.Kill ? [new KillTarget(pid!.Value, image, IncludeDescendants: true)] : [],
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            },
        ];
    }

    // --- Event 7: R5 (unsigned module loaded from a place a user can write to) ----------------
    private IReadOnlyList<Finding> OnImageLoad(SysmonEvent e)
    {
        var image = e.Get("Image");
        var profile = ProfileFor(image);
        if (profile is null)
        {
            return [];
        }

        var module = e.Get("ImageLoaded");
        var signed = string.Equals(e.Get("Signed"), "true", StringComparison.OrdinalIgnoreCase)
            && string.Equals(e.Get("SignatureStatus"), "Valid", StringComparison.OrdinalIgnoreCase);

        // The client itself and the libraries in its folder are often unsigned and are not what R5 is about;
        // a file the client drops there is caught by R3.
        if (signed || PathRules.Same(module, image) || PathRules.IsUnder(module, profile.GameDirectory))
        {
            return [];
        }

        var userWritable = PathRules.IsUserWritableLocation(module);
        return
        [
            new Finding
            {
                RuleId = "R5",
                Severity = userWritable ? Severity.High : Severity.Medium,
                Action = userWritable ? FindingAction.Alert : FindingAction.Log,
                Summary = userWritable
                    ? $"The game client loaded an unsigned module from a user-writable folder: {module}"
                    : $"The game client loaded an unsigned module: {module}",
                Profile = profile.Name,
                Image = image,
                ProcessId = e.GetInt("ProcessId"),
                Target = module,
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            },
        ];
    }

    // --- Event 8: R6 (thread started in another process) --------------------------------------
    private IReadOnlyList<Finding> OnCreateRemoteThread(SysmonEvent e)
    {
        var image = e.Get("SourceImage");
        var profile = ProfileFor(image);
        if (profile is null)
        {
            return [];
        }

        var pid = e.GetInt("SourceProcessId");
        var target = e.Get("TargetImage");
        return
        [
            new Finding
            {
                RuleId = "R6",
                Severity = Severity.Critical,
                Action = pid is null ? FindingAction.Alert : FindingAction.Kill,
                Summary = $"The game client started a thread inside another program: {target}",
                Profile = profile.Name,
                Image = image,
                ProcessId = pid,
                Target = target,
                KillTargets = pid is null ? [] : [new KillTarget(pid.Value, image, IncludeDescendants: true)],
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            },
        ];
    }

    // --- Event 10: R7 (other process opened) - recorded only until the learning mode exists ---
    private IReadOnlyList<Finding> OnProcessAccess(SysmonEvent e)
    {
        var image = e.Get("SourceImage");
        var profile = ProfileFor(image);
        if (profile is null)
        {
            return [];
        }

        // A parent always holds a handle to the child it started; that access belongs to R1.
        if (childToClient.ContainsKey(e.Get("TargetProcessGUID")))
        {
            return [];
        }

        var target = e.Get("TargetImage");
        return
        [
            new Finding
            {
                RuleId = "R7",
                Severity = Severity.Medium,
                Action = FindingAction.Log,
                Summary = $"The game client opened another program ({e.Get("GrantedAccess")}): {target}",
                Profile = profile.Name,
                Image = image,
                ProcessId = e.GetInt("SourceProcessId"),
                Target = target,
                Time = e.TimeCreated,
                RecordId = e.RecordId,
            },
        ];
    }
}
