using System.Net;
using System.Net.Sockets;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Prevention;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Tests;

public class FirewallPlanTests
{
    private static readonly IReadOnlyDictionary<string, IReadOnlyCollection<IPAddress>> NoHosts =
        new Dictionary<string, IReadOnlyCollection<IPAddress>>();

    private static IpRange[] Ranges(params string[] entries) =>
        [.. entries.Select(entry => RemoteAllowlist.TryParseRange(entry, out var range) ? range : throw new FormatException(entry))];

    private static string Outside(AddressFamily family, params string[] allowed) =>
        string.Join(",", AddressBlocks.Outside(Ranges(allowed), family));

    [Theory]
    // Nothing allowed: everything but loopback.
    [InlineData("", "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255")]
    [InlineData("203.0.113.7", "0.0.0.0-126.255.255.255,128.0.0.0-203.0.113.6,203.0.113.8-255.255.255.255")]
    [InlineData("203.0.113.0/24", "0.0.0.0-126.255.255.255,128.0.0.0-203.0.112.255,203.0.114.0-255.255.255.255")]
    // The host part of a range is ignored: 10.1.2.3/8 is 10.0.0.0/8.
    [InlineData("10.1.2.3/8", "0.0.0.0-9.255.255.255,11.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255")]
    // Overlapping, nested, touching and unordered ranges give the same runs as their union.
    [InlineData("10.0.1.0/24;10.0.0.0/16;10.1.0.0/16;9.255.255.255", "0.0.0.0-9.255.255.254,10.2.0.0-126.255.255.255,128.0.0.0-255.255.255.255")]
    // The ends of the address space.
    [InlineData("0.0.0.0/8", "1.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255")]
    [InlineData("255.255.255.255", "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.254")]
    [InlineData("128.0.0.0/1", "0.0.0.0-126.255.255.255")]
    // Ranges of the other family do not count.
    [InlineData("2001:db8::/32", "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255")]
    public void Everything_outside_the_allowed_IPv4_ranges(string allowed, string expected)
    {
        Assert.Equal(expected, Outside(AddressFamily.InterNetwork, allowed.Split(';', StringSplitOptions.RemoveEmptyEntries)));
    }

    [Fact]
    public void Allowing_all_of_IPv4_leaves_nothing_to_block()
    {
        Assert.Empty(AddressBlocks.Outside(Ranges("0.0.0.0/0"), AddressFamily.InterNetwork));
    }

    [Theory]
    [InlineData("", "::-::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("2001:db8::/32", "::-::,::2-2001:db7:ffff:ffff:ffff:ffff:ffff:ffff,2001:db9::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("2001:db8::5", "::-::,::2-2001:db8::4,2001:db8::6-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("8000::/1", "::-::,::2-7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("203.0.113.7", "::-::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    public void Everything_outside_the_allowed_IPv6_ranges(string allowed, string expected)
    {
        Assert.Equal(expected, Outside(AddressFamily.InterNetworkV6, allowed.Split(';', StringSplitOptions.RemoveEmptyEntries)));
    }

    [Fact]
    public void Allowing_all_of_IPv6_leaves_nothing_to_block()
    {
        Assert.Empty(AddressBlocks.Outside(Ranges("::/0"), AddressFamily.InterNetworkV6));
    }

    [Theory]
    [InlineData("203.0.113.7", true)]
    [InlineData("203.0.113.6", false)]
    [InlineData("203.0.113.8", false)]
    [InlineData("198.51.100.200", true)]    // in 198.51.100.128/25
    [InlineData("198.51.100.127", false)]
    [InlineData("127.0.0.1", true)]         // loopback is never blocked
    [InlineData("127.255.255.255", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("::1", true)]
    [InlineData("2001:db8:1::9", true)]
    [InlineData("2001:db9::1", false)]
    [InlineData("::", false)]
    public void An_address_is_blocked_exactly_if_it_is_not_allowed(string address, bool allowed)
    {
        var ranges = Ranges("203.0.113.7", "198.51.100.128/25", "2001:db8::/32");
        var candidate = IPAddress.Parse(address);

        var blocked = AddressBlocks.Outside(ranges, candidate.AddressFamily).Any(span => Within(span, candidate));

        Assert.Equal(!allowed, blocked);
    }

    [Fact]
    public void The_runs_are_ascending_and_do_not_touch()
    {
        var spans = AddressBlocks.Outside(Ranges("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.7"), AddressFamily.InterNetwork);

        Assert.Equal(6, spans.Count);   // five holes (four ranges and loopback) make six runs
        for (var i = 0; i < spans.Count; i++)
        {
            Assert.True(Number(spans[i].First) <= Number(spans[i].Last));
            if (i > 0)
            {
                // At least one allowed address lies between two runs.
                Assert.True(Number(spans[i].First) > Number(spans[i - 1].Last) + 1);
            }
        }
    }

    [Fact]
    public void A_profile_without_firewall_and_lockdown_gets_no_rule()
    {
        var config = Config(new ClientProfile { Name = "Plain", ClientPath = @"C:\Games\A\Wow.exe", AllowedRemote = ["203.0.113.7"] });

        Assert.Empty(FirewallPlanner.Plan(config, NoHosts, []));
    }

    [Fact]
    public void A_profile_with_firewall_blocks_everything_but_its_addresses_and_its_host_names()
    {
        var config = Config(new ClientProfile
        {
            Name = "Warmane",
            ClientPath = @"D:\Games\Warmane\Wow.exe",
            AllowedRemote = ["203.0.113.0/24"],
            AllowedHostnames = ["logon.example.org"],
            Firewall = true,
        });
        var hosts = new Dictionary<string, IReadOnlyCollection<IPAddress>>
        {
            // An IPv4-mapped address counts as the IPv4 address it stands for.
            ["Warmane"] = [IPAddress.Parse("198.51.100.9"), IPAddress.Parse("::ffff:198.51.100.10"), IPAddress.Parse("2001:db8::5")],
        };

        var rule = Assert.Single(FirewallPlanner.Plan(config, hosts, []));

        Assert.Equal("RCEGuard: Warmane", rule.Name);
        Assert.Equal(@"D:\Games\Warmane\Wow.exe", rule.ApplicationPath);
        Assert.Equal(
            "0.0.0.0-126.255.255.255,128.0.0.0-198.51.100.8,198.51.100.11-203.0.112.255,203.0.114.0-255.255.255.255," +
            "::-::,::2-2001:db8::4,2001:db8::6-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            rule.RemoteAddresses);
        Assert.Contains("profile 'Warmane'", rule.Description);
        Assert.Contains("4 allowed", rule.Description);
    }

    [Fact]
    public void Host_names_that_resolve_to_nothing_block_everything_but_loopback()
    {
        var config = Config(new ClientProfile { Name = "A", ClientPath = @"C:\Games\A\Wow.exe", AllowedHostnames = ["logon.example.org"], Firewall = true });

        var rule = Assert.Single(FirewallPlanner.Plan(config, NoHosts, []));

        Assert.Equal(
            "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::-::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            rule.RemoteAddresses);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_locked_profile_blocks_every_address_whether_or_not_its_firewall_is_on(bool firewall)
    {
        var config = Config(
            new ClientProfile { Name = "Locked", ClientPath = @"C:\Games\A\Wow.exe", AllowedRemote = ["203.0.113.7"], Firewall = firewall },
            new ClientProfile { Name = "Other", ClientPath = @"C:\Games\B\Wow.exe", AllowedRemote = ["203.0.113.7"], Firewall = true });

        var rules = FirewallPlanner.Plan(config, NoHosts, ["locked"]);   // the name is matched without regard to case

        Assert.Equal(2, rules.Count);
        Assert.Equal("*", rules[0].RemoteAddresses);
        Assert.Contains("lockdown", rules[0].Description);
        Assert.NotEqual("*", rules[1].RemoteAddresses);
    }

    [Fact]
    public void The_description_changes_exactly_when_path_or_addresses_change()
    {
        var profile = new ClientProfile { Name = "A", ClientPath = @"C:\Games\A\Wow.exe", AllowedRemote = ["203.0.113.7"], Firewall = true };
        string Description(ClientProfile p, params string[] locked) => Assert.Single(FirewallPlanner.Plan(Config(p), NoHosts, locked)).Description;

        var original = Description(profile);

        Assert.Equal(original, Description(profile));
        // The same single address written as a range, and the path in another case: the same rule.
        Assert.Equal(original, Description(profile with { AllowedRemote = ["203.0.113.7/32"], ClientPath = @"c:\games\a\WOW.EXE" }));
        // Another address with the same number of entries: only the fingerprint tells them apart.
        Assert.NotEqual(original, Description(profile with { AllowedRemote = ["203.0.113.8"] }));
        Assert.NotEqual(original, Description(profile with { ClientPath = @"C:\Games\B\Wow.exe" }));
        Assert.NotEqual(original, Description(profile, "A"));
    }

    [Theory]
    [InlineData("""{"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe","firewall":true}]}""", "would block every connection")]
    [InlineData("""{"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe"},{"name":"A","clientPath":"C:\\b\\Wow.exe"}]}""", "used by more than one profile")]
    [InlineData("""{"profiles":[{"name":"a|b","clientPath":"C:\\a\\Wow.exe"}]}""", "must not contain '|'")]
    public void Invalid_prevention_settings_are_rejected_with_a_reason(string json, string expectedReason)
    {
        var error = Assert.Throws<FormatException>(() => GuardConfigJson.Parse(json));

        Assert.Contains(expectedReason, error.Message);
    }

    [Fact]
    public void Prevention_is_off_unless_the_configuration_turns_it_on()
    {
        var plain = GuardConfigJson.Parse("""{"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe"}]}""");
        var set = GuardConfigJson.Parse(
            """{"lockdown":true,"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe","allowedHostnames":["logon.example.org"],"firewall":true}]}""");

        Assert.False(plain.Lockdown);
        Assert.False(plain.Profiles[0].Firewall);
        Assert.True(set.Lockdown);
        Assert.True(set.Profiles[0].Firewall);
    }

    private static GuardConfig Config(params ClientProfile[] profiles)
    {
        var config = new GuardConfig { Profiles = profiles };
        GuardConfigJson.Validate(config);
        return config;
    }

    private static bool Within(AddressSpan span, IPAddress address) =>
        Number(span.First) <= Number(address) && Number(address) <= Number(span.Last);

    private static UInt128 Number(IPAddress address)
    {
        var value = UInt128.Zero;
        foreach (var part in address.GetAddressBytes())
        {
            value = (value << 8) | part;
        }

        return value;
    }
}
