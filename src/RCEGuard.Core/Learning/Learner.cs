using System.Net;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Learning;

/// <summary>
/// Notes what the clients of profiles in learning mode do: where they connect to, which host
/// names they resolve, where they create files outside the game folder and which other programs
/// they open. It only collects; nothing it notes changes what the rules decide.
/// Not thread-safe: feed it events one at a time.
/// </summary>
public sealed class Learner
{
    /// <summary>Upper limit of entries per list of a profile. What does not fit is left out and the profile is marked.</summary>
    public const int MaxEntries = 500;

    /// <summary>Sysmon event id of a name service query.</summary>
    public const int DnsQueryEventId = 22;

    private readonly List<ClientProfile> learning;
    private readonly Dictionary<string, LearnedProfile> byProfile = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Creates a learner.</summary>
    /// <param name="config">The configuration; only profiles with <see cref="ClientProfile.Learning"/> are noted.</param>
    /// <param name="known">What was noted before (also for profiles that are not learning any more: it is kept).</param>
    public Learner(GuardConfig config, IEnumerable<LearnedProfile> known)
    {
        learning = [.. config.Profiles.Where(profile => profile.Learning)];
        foreach (var profile in known)
        {
            byProfile[profile.Profile] = profile;
        }
    }

    /// <summary>True if at least one profile is in learning mode.</summary>
    public bool Active => learning.Count > 0;

    /// <summary>Everything noted so far, for every profile that ever learned.</summary>
    public IReadOnlyList<LearnedProfile> Profiles => [.. byProfile.Values];

    /// <summary>Notes one event. Returns true if something was added or counted.</summary>
    /// <param name="e">The event.</param>
    /// <param name="findings">What the rule engine made of the event.</param>
    public bool Observe(SysmonEvent e, IReadOnlyList<Finding> findings)
    {
        if (learning.Count == 0)
        {
            return false;
        }

        var image = e.Get(e.EventId == SysmonEventIds.ProcessAccess ? "SourceImage" : "Image");
        var profile = learning.FirstOrDefault(candidate => PathRules.Same(candidate.ClientPath, image));
        if (profile is null)
        {
            return false;
        }

        var learned = For(profile.Name);
        var wasTruncated = learned.Truncated;
        var noted = e.EventId switch
        {
            SysmonEventIds.ProcessCreate => NoteStart(learned),
            SysmonEventIds.NetworkConnect => NoteConnection(learned, e),
            DnsQueryEventId => NoteQuery(learned, e),
            SysmonEventIds.FileCreate => NoteFile(learned, profile, e),
            // The rule engine knows which programs the client started itself; those are not "opened".
            SysmonEventIds.ProcessAccess when findings.Any(finding => finding.RuleId == "R7") => NoteProgram(learned, e),
            _ => false,
        };
        if (noted)
        {
            learned.FirstEventUtc ??= e.TimeCreated;
            if (learned.LastEventUtc is null || e.TimeCreated > learned.LastEventUtc)
            {
                learned.LastEventUtc = e.TimeCreated;
            }
        }

        // "A list is full" is news too: it has to reach the file.
        return noted || learned.Truncated != wasTruncated;
    }

    private LearnedProfile For(string name)
    {
        if (!byProfile.TryGetValue(name, out var learned))
        {
            learned = new LearnedProfile { Profile = name };
            byProfile[name] = learned;
        }

        return learned;
    }

    private static bool NoteStart(LearnedProfile learned)
    {
        learned.Sessions++;
        return true;
    }

    private static bool NoteConnection(LearnedProfile learned, SysmonEvent e)
    {
        if (!string.Equals(e.Get("Initiated"), "true", StringComparison.OrdinalIgnoreCase)
            || !IPAddress.TryParse(e.Get("DestinationIp"), out var address)
            || e.GetInt("DestinationPort") is not { } port)
        {
            return false;
        }

        address = RemoteAllowlist.Normalize(address);
        if (IPAddress.IsLoopback(address))
        {
            return false;
        }

        var text = address.ToString();
        var known = learned.Remotes.FirstOrDefault(remote => remote.Port == port && remote.Address == text);
        if (known is null)
        {
            if (IsFull(learned, learned.Remotes.Count))
            {
                return false;
            }

            known = new LearnedRemote { Address = text, Port = port };
            learned.Remotes.Add(known);
        }

        known.Count++;
        return true;
    }

    private static bool NoteQuery(LearnedProfile learned, SysmonEvent e)
    {
        var name = e.Get("QueryName").Trim().TrimEnd('.');
        if (name.Length == 0)
        {
            return false;
        }

        var known = learned.Hosts.FirstOrDefault(host => string.Equals(host.Name, name, StringComparison.OrdinalIgnoreCase));
        if (known is null)
        {
            if (IsFull(learned, learned.Hosts.Count))
            {
                return false;
            }

            known = new LearnedHost { Name = name.ToLowerInvariant() };
            learned.Hosts.Add(known);
        }

        known.Count++;
        foreach (var address in AddressesIn(e.Get("QueryResults")))
        {
            // A name behind a load balancer answers with other addresses every time: bounded like the lists.
            if (!known.Addresses.Contains(address) && known.Addresses.Count < 64)
            {
                known.Addresses.Add(address);
            }
        }

        return true;
    }

    /// <summary>
    /// The addresses in the answer of a name service query as Sysmon writes it: entries separated
    /// by ';', addresses as text (IPv4 often as "::ffff:1.2.3.4"), other records as "type: 5 name".
    /// </summary>
    public static IReadOnlyList<string> AddressesIn(string queryResults)
    {
        var addresses = new List<string>();
        foreach (var part in queryResults.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!part.StartsWith("type:", StringComparison.OrdinalIgnoreCase) && IPAddress.TryParse(part, out var address))
            {
                var text = RemoteAllowlist.Normalize(address).ToString();
                if (!addresses.Contains(text))
                {
                    addresses.Add(text);
                }
            }
        }

        return addresses;
    }

    private static bool NoteFile(LearnedProfile learned, ClientProfile profile, SysmonEvent e)
    {
        var file = e.Get("TargetFilename");
        var cut = file.LastIndexOf('\\');
        if (cut <= 0 || PathRules.IsUnder(file, profile.GameDirectory))
        {
            return false;
        }

        var folder = file[..(cut + 1)];
        var name = file[(cut + 1)..];
        var dot = name.LastIndexOf('.');
        var extension = dot < 0 ? string.Empty : name[dot..].ToLowerInvariant();

        var known = learned.Folders.FirstOrDefault(candidate => PathRules.Same(candidate.Folder, folder));
        if (known is null)
        {
            if (IsFull(learned, learned.Folders.Count))
            {
                return false;
            }

            known = new LearnedFolder { Folder = folder };
            learned.Folders.Add(known);
        }

        known.Count++;
        if (!known.Extensions.Contains(extension) && known.Extensions.Count < 64)
        {
            known.Extensions.Add(extension);
        }

        return true;
    }

    private static bool NoteProgram(LearnedProfile learned, SysmonEvent e)
    {
        var target = e.Get("TargetImage");
        if (target.Length == 0)
        {
            return false;
        }

        var known = learned.Programs.FirstOrDefault(program => PathRules.Same(program.Image, target));
        if (known is null)
        {
            if (IsFull(learned, learned.Programs.Count))
            {
                return false;
            }

            known = new LearnedProgram { Image = target };
            learned.Programs.Add(known);
        }

        known.Count++;
        var access = e.Get("GrantedAccess").ToLowerInvariant();
        if (access.Length > 0 && !known.Access.Contains(access) && known.Access.Count < 64)
        {
            known.Access.Add(access);
        }

        return true;
    }

    private static bool IsFull(LearnedProfile learned, int count)
    {
        if (count < MaxEntries)
        {
            return false;
        }

        learned.Truncated = true;
        return true;
    }
}
