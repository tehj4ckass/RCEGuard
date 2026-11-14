using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Prevention;

/// <summary>
/// One outbound block rule of Windows Firewall as RCEGuard wants it. All rules of RCEGuard are
/// block rules for one program and carry the group <see cref="Group"/>.
/// </summary>
/// <param name="Name">Name of the rule, unique among the rules of RCEGuard.</param>
/// <param name="ApplicationPath">Full path of the program the rule applies to.</param>
/// <param name="RemoteAddresses">
/// The blocked remote addresses as Windows Firewall takes them: <see cref="AnyAddress"/> or
/// comma-separated "first-last" runs.
/// </param>
/// <param name="Description">
/// Text shown in the firewall console. It ends with a fingerprint of path and addresses, so a rule
/// with the same description as wanted is the wanted rule and need not be written again.
/// </param>
public sealed record FirewallRuleSpec(string Name, string ApplicationPath, string RemoteAddresses, string Description)
{
    /// <summary>Group of every firewall rule of RCEGuard; removing RCEGuard removes the group.</summary>
    public const string Group = "RCEGuard";

    /// <summary>Remote address that stands for every address.</summary>
    public const string AnyAddress = "*";
}

/// <summary>Decides which firewall rules should exist for a configuration.</summary>
public static class FirewallPlanner
{
    /// <summary>Name of the rule of a profile.</summary>
    public static string RuleName(string profileName) => $"RCEGuard: {profileName}";

    /// <summary>
    /// The rules that should exist, at most one per profile:
    /// a locked profile blocks every outbound connection of its client; a profile with
    /// <see cref="ClientProfile.Firewall"/> blocks every address that is neither on its allowlist
    /// nor an address of one of its host names; any other profile has no rule.
    /// A profile whose host names could not be resolved and that lists no addresses blocks
    /// everything but loopback: what is not known to be allowed is blocked.
    /// </summary>
    /// <param name="config">The configuration.</param>
    /// <param name="resolvedHosts">Per profile name, the addresses its host names resolve to now.</param>
    /// <param name="lockedProfiles">Names of the profiles in lockdown.</param>
    public static IReadOnlyList<FirewallRuleSpec> Plan(
        GuardConfig config,
        IReadOnlyDictionary<string, IReadOnlyCollection<IPAddress>> resolvedHosts,
        IReadOnlyCollection<string> lockedProfiles)
    {
        var locked = new HashSet<string>(lockedProfiles, StringComparer.OrdinalIgnoreCase);
        var rules = new List<FirewallRuleSpec>();
        foreach (var profile in config.Profiles)
        {
            if (locked.Contains(profile.Name))
            {
                rules.Add(Rule(
                    profile,
                    FirewallRuleSpec.AnyAddress,
                    $"RCEGuard lockdown of profile '{profile.Name}': every outbound connection of this program is blocked until the lockdown is released."));
            }
            else if (profile.Firewall)
            {
                var allowed = AllowedRanges(profile, resolvedHosts);
                var blocked = AddressBlocks.Outside(allowed, AddressFamily.InterNetwork)
                    .Concat(AddressBlocks.Outside(allowed, AddressFamily.InterNetworkV6));
                rules.Add(Rule(
                    profile,
                    string.Join(",", blocked),
                    $"RCEGuard, profile '{profile.Name}': outbound connections of this program are blocked, except to the {allowed.Count} allowed address(es) and range(s) of the profile."));
            }
        }

        return rules;
    }

    private static List<IpRange> AllowedRanges(ClientProfile profile, IReadOnlyDictionary<string, IReadOnlyCollection<IPAddress>> resolvedHosts)
    {
        var allowed = new List<IpRange>();
        foreach (var entry in profile.AllowedRemote)
        {
            if (!RemoteAllowlist.TryParseRange(entry, out var range))
            {
                throw new FormatException($"Profile '{profile.Name}': '{entry}' is not an IP address or CIDR range.");
            }

            allowed.Add(range);
        }

        if (resolvedHosts.TryGetValue(profile.Name, out var addresses))
        {
            foreach (var address in addresses)
            {
                var normalized = RemoteAllowlist.Normalize(address);
                allowed.Add(new IpRange(normalized, normalized.AddressFamily == AddressFamily.InterNetwork ? 32 : 128));
            }
        }

        return allowed;
    }

    private static FirewallRuleSpec Rule(ClientProfile profile, string remoteAddresses, string text)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{profile.ClientPath.ToUpperInvariant()}|{remoteAddresses}"));
        var fingerprint = Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
        return new FirewallRuleSpec(RuleName(profile.Name), profile.ClientPath, remoteAddresses, $"{text} [{fingerprint}]");
    }
}
