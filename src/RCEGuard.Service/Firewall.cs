using System.Runtime.InteropServices;
using RCEGuard.Core.Prevention;

namespace RCEGuard.Service;

/// <summary>A rule of RCEGuard as Windows Firewall has it.</summary>
/// <param name="Name">Name of the rule.</param>
/// <param name="Description">Its description; ends with the fingerprint RCEGuard wrote.</param>
/// <param name="ApplicationPath">The program the rule applies to.</param>
/// <param name="RemoteAddresses">The remote addresses as the firewall returns them.</param>
/// <param name="Enabled">Whether the rule is turned on.</param>
/// <param name="BlocksOutbound">Whether it is an outbound block rule.</param>
internal sealed record InstalledFirewallRule(
    string Name, string Description, string ApplicationPath, string RemoteAddresses, bool Enabled, bool BlocksOutbound);

/// <summary>The part of Windows Firewall RCEGuard uses: its own rules, nothing else.</summary>
internal interface IFirewall
{
    /// <summary>The rules of the group <see cref="FirewallRuleSpec.Group"/>.</summary>
    IReadOnlyList<InstalledFirewallRule> ReadRules();

    /// <summary>Creates the rule, or changes the rule of RCEGuard with that name to match.</summary>
    void Write(FirewallRuleSpec spec);

    /// <summary>Removes the rule of RCEGuard with that name.</summary>
    void Remove(string name);

    /// <summary>Why rules would have no effect on this machine right now, or null.</summary>
    string? Problem();
}

/// <summary>
/// Windows Firewall through its COM interface (HNetCfg.FwPolicy2). Reading works for every user,
/// changing needs administrator rights or LocalSystem.
/// </summary>
internal sealed class WindowsFirewall : IFirewall
{
    private const int DirectionOut = 2;             // NET_FW_RULE_DIR_OUT
    private const int ActionBlock = 0;              // NET_FW_ACTION_BLOCK
    private const int AllProfiles = int.MaxValue;   // NET_FW_PROFILE2_ALL
    private const int OverriddenByGroupPolicy = 1;  // NET_FW_MODIFY_STATE_GP_OVERRIDE

    private static readonly (int Bit, string Name)[] NetworkProfiles = [(1, "domain"), (2, "private"), (4, "public")];

    /// <inheritdoc />
    public IReadOnlyList<InstalledFirewallRule> ReadRules()
    {
        var result = new List<InstalledFirewallRule>();
        foreach (var rule in OwnRules(Create("HNetCfg.FwPolicy2")))
        {
            result.Add(new InstalledFirewallRule(
                (string?)rule.Name ?? string.Empty,
                (string?)rule.Description ?? string.Empty,
                (string?)rule.ApplicationName ?? string.Empty,
                (string?)rule.RemoteAddresses ?? string.Empty,
                (bool)rule.Enabled,
                (int)rule.Direction == DirectionOut && (int)rule.Action == ActionBlock));
        }

        return result;
    }

    /// <inheritdoc />
    public void Write(FirewallRuleSpec spec)
    {
        var policy = Create("HNetCfg.FwPolicy2");
        var existing = Find(policy, spec.Name);
        if (existing is not null && (int)existing.Direction != DirectionOut)
        {
            // The direction of a rule cannot be changed: replace it.
            policy.Rules.Remove(spec.Name);
            existing = null;
        }

        if (existing is null)
        {
            var rule = Create("HNetCfg.FWRule");
            rule.Name = spec.Name;
            rule.Grouping = FirewallRuleSpec.Group;
            rule.Direction = DirectionOut;
            rule.Action = ActionBlock;
            rule.Profiles = AllProfiles;
            rule.ApplicationName = spec.ApplicationPath;
            rule.RemoteAddresses = spec.RemoteAddresses;
            rule.Description = spec.Description;
            rule.Enabled = true;
            policy.Rules.Add(rule);
            return;
        }

        // Changed in place, so that there is no moment without the rule. Every assignment takes effect
        // at once; the description with the fingerprint comes last, so that a half-changed rule does
        // not look like the wanted one.
        existing.ApplicationName = spec.ApplicationPath;
        existing.Action = ActionBlock;
        existing.Profiles = AllProfiles;
        existing.RemoteAddresses = spec.RemoteAddresses;
        existing.Enabled = true;
        existing.Description = spec.Description;
    }

    /// <inheritdoc />
    public void Remove(string name)
    {
        var policy = Create("HNetCfg.FwPolicy2");
        // Rules are removed by name. Only if RCEGuard has a rule of that name: a rule of someone else is not touched.
        if (Find(policy, name) is not null)
        {
            policy.Rules.Remove(name);
        }
    }

    /// <inheritdoc />
    public string? Problem()
    {
        var policy = Create("HNetCfg.FwPolicy2");
        var current = (int)policy.CurrentProfileTypes;
        var off = new List<string>();
        foreach (var (bit, name) in NetworkProfiles)
        {
            if ((current & bit) != 0 && !(bool)policy.FirewallEnabled[bit])
            {
                off.Add(name);
            }
        }

        if (off.Count > 0)
        {
            return $"Windows Firewall is turned off for the network profile in use ({string.Join(", ", off)}): the firewall rules of RCEGuard block nothing.";
        }

        return (int)policy.LocalPolicyModifyState == OverriddenByGroupPolicy
            ? "A group policy overrides the local rules of Windows Firewall: the firewall rules of RCEGuard may have no effect."
            : null;
    }

    private static dynamic Create(string programId)
    {
        var type = Type.GetTypeFromProgID(programId)
            ?? throw new InvalidOperationException($"The COM class '{programId}' of Windows Firewall is not registered.");
        return Activator.CreateInstance(type)
            ?? throw new InvalidOperationException($"The COM class '{programId}' of Windows Firewall could not be created.");
    }

    private static dynamic? Find(dynamic policy, string name)
    {
        foreach (var rule in OwnRules(policy))
        {
            if (string.Equals((string?)rule.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return rule;
            }
        }

        return null;
    }

    private static IEnumerable<dynamic> OwnRules(dynamic policy)
    {
        foreach (var rule in policy.Rules)
        {
            if (string.Equals((string?)rule.Grouping, FirewallRuleSpec.Group, StringComparison.Ordinal))
            {
                yield return rule;
            }
            else
            {
                // Several hundred rules of others pass by here on every read.
                Marshal.ReleaseComObject(rule);
            }
        }
    }
}
