using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Prevention;
using RCEGuard.Core.Rules;
using RCEGuard.Core.State;

namespace RCEGuard.Service.Tests;

/// <summary>Stand-in for Windows Firewall: the real one cannot be changed without administrator rights.</summary>
internal sealed class FakeFirewall : IFirewall
{
    private readonly object gate = new();
    private readonly List<InstalledFirewallRule> rules = [];
    private readonly List<string> calls = [];

    public Exception? Fail { get; set; }

    public string? ProblemText { get; set; }

    public IReadOnlyList<InstalledFirewallRule> Rules
    {
        get
        {
            lock (gate)
            {
                return [.. rules];
            }
        }
    }

    public IReadOnlyList<string> Calls
    {
        get
        {
            lock (gate)
            {
                return [.. calls];
            }
        }
    }

    public void Put(InstalledFirewallRule rule)
    {
        lock (gate)
        {
            rules.RemoveAll(existing => existing.Name == rule.Name);
            rules.Add(rule);
        }
    }

    public IReadOnlyList<InstalledFirewallRule> ReadRules()
    {
        ThrowIfFailing();
        return Rules;
    }

    public void Write(FirewallRuleSpec spec)
    {
        ThrowIfFailing();
        lock (gate)
        {
            calls.Add($"write {spec.Name}");
        }

        Put(new InstalledFirewallRule(spec.Name, spec.Description, spec.ApplicationPath, spec.RemoteAddresses, Enabled: true, BlocksOutbound: true));
    }

    public void Remove(string name)
    {
        ThrowIfFailing();
        lock (gate)
        {
            calls.Add($"remove {name}");
            rules.RemoveAll(existing => existing.Name == name);
        }
    }

    public string? Problem() => ProblemText;

    private void ThrowIfFailing()
    {
        if (Fail is not null)
        {
            throw Fail;
        }
    }
}

public sealed class FirewallGuardTests : IDisposable
{
    private const string Client = @"C:\RCEGuardTest\Wow.exe";
    private const string Blocked = "0.0.0.0-126.255.255.255,128.0.0.0-203.0.113.6,203.0.113.8-255.255.255.255,::-::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";

    private static readonly IReadOnlyDictionary<string, IReadOnlyCollection<IPAddress>> NoHosts =
        new Dictionary<string, IReadOnlyCollection<IPAddress>>();

    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-firewall-").FullName;
    private readonly FakeFirewall firewall = new();
    private readonly List<string> log = [];

    public void Dispose() => Directory.Delete(folder, recursive: true);

    private LockdownFile File => new(Path.Combine(folder, LockdownFile.FileName));

    private static GuardConfig Config(bool firewall = true) => new()
    {
        Lockdown = true,
        Profiles =
        [
            new ClientProfile { Name = "Test", ClientPath = Client, AllowedRemote = ["203.0.113.7"], Firewall = firewall },
        ],
    };

    private FirewallGuard Guard(GuardConfig? config = null, bool dryRun = false) =>
        new(config ?? Config(), firewall, File, (level, message) => log.Add($"{level}: {message}"), dryRun);

    private static Finding Finding(string profile = "Test") => new()
    {
        RuleId = "R1",
        Severity = Severity.Critical,
        Action = FindingAction.Kill,
        Summary = "Client started a child process",
        Profile = profile,
        Time = new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero),
    };

    [Fact]
    public void The_rule_of_a_profile_with_firewall_is_written_once()
    {
        var guard = Guard();

        Assert.True(guard.Apply(NoHosts));
        Assert.True(guard.Apply(NoHosts));

        var rule = Assert.Single(firewall.Rules);
        Assert.Equal("RCEGuard: Test", rule.Name);
        Assert.Equal(Client, rule.ApplicationPath);
        Assert.Equal(Blocked, rule.RemoteAddresses);
        Assert.Equal(["write RCEGuard: Test"], firewall.Calls);
        Assert.Single(log, line => line.Contains("written") && line.Contains("except to the allowed addresses"));
    }

    [Fact]
    public void A_start_writes_the_rule_again_although_it_looks_right()
    {
        Guard().Apply(NoHosts);

        Guard().Apply(NoHosts, force: true);

        Assert.Equal(2, firewall.Calls.Count);
    }

    [Fact]
    public void New_addresses_of_a_host_name_change_the_rule()
    {
        var config = new GuardConfig
        {
            Profiles = [new ClientProfile { Name = "Test", ClientPath = Client, AllowedHostnames = ["logon.example.org"], Firewall = true }],
        };
        var guard = Guard(config);
        guard.Apply(new Dictionary<string, IReadOnlyCollection<IPAddress>> { ["Test"] = [IPAddress.Parse("203.0.113.7")] });
        Assert.Equal(Blocked, firewall.Rules[0].RemoteAddresses);

        guard.Apply(new Dictionary<string, IReadOnlyCollection<IPAddress>> { ["Test"] = [IPAddress.Parse("203.0.113.9")] });

        Assert.Contains("203.0.113.10-255.255.255.255", Assert.Single(firewall.Rules).RemoteAddresses);
        Assert.Equal(2, firewall.Calls.Count);
    }

    [Theory]
    [InlineData(false, true)]   // turned off by hand
    [InlineData(true, false)]   // turned into an allow rule or an inbound rule
    public void A_rule_that_no_longer_blocks_is_written_again(bool enabled, bool blocksOutbound)
    {
        var guard = Guard();
        guard.Apply(NoHosts);
        firewall.Put(firewall.Rules[0] with { Enabled = enabled, BlocksOutbound = blocksOutbound });

        guard.Apply(NoHosts);

        var rule = Assert.Single(firewall.Rules);
        Assert.True(rule.Enabled && rule.BlocksOutbound);
        Assert.Equal(2, firewall.Calls.Count);
    }

    [Fact]
    public void A_rule_of_RCEGuard_that_nothing_asks_for_is_removed()
    {
        firewall.Put(new InstalledFirewallRule("RCEGuard: Gone", "old", @"C:\Old\Wow.exe", "*", true, true));

        Guard(Config(firewall: false)).Apply(NoHosts);

        Assert.Empty(firewall.Rules);
        Assert.Equal(["remove RCEGuard: Gone"], firewall.Calls);
    }

    [Fact]
    public void A_lockdown_blocks_every_address_and_is_noted()
    {
        var guard = Guard();
        guard.Apply(NoHosts);

        var taken = guard.Lock(Finding(), NoHosts);

        Assert.StartsWith("locked down", taken);
        Assert.Equal("*", Assert.Single(firewall.Rules).RemoteAddresses);
        var entry = Assert.Single(File.Load(out var problem));
        Assert.Null(problem);
        Assert.Equal(("Test", "R1", "Client started a child process"), (entry.Profile, entry.Rule, entry.Summary));
        Assert.Equal(Finding().Time, entry.SinceUtc);
        Assert.Contains(log, line => line.Contains("(lockdown)"));
    }

    [Fact]
    public void A_second_finding_does_not_lock_again()
    {
        var guard = Guard();
        guard.Lock(Finding(), NoHosts);
        var calls = firewall.Calls.Count;

        var taken = guard.Lock(Finding() with { RuleId = "R4" }, NoHosts);

        Assert.Equal("already in lockdown", taken);
        Assert.Equal(calls, firewall.Calls.Count);
        Assert.Equal("R1", Assert.Single(File.Load(out _)).Rule);   // the first finding stays the reason
    }

    [Fact]
    public void A_lockdown_survives_a_new_guard_and_ends_when_the_file_says_so()
    {
        Guard(Config(firewall: false)).Lock(Finding(), NoHosts);

        // A restart: a new guard, the same file.
        var restarted = Guard(Config(firewall: false));
        restarted.Apply(NoHosts, force: true);
        Assert.Equal("*", Assert.Single(firewall.Rules).RemoteAddresses);
        Assert.False(restarted.ChangedOutside());

        // The release command empties the file; the guard notices and takes the rule away.
        Thread.Sleep(20);   // a new time stamp on the file
        File.Save([]);
        Assert.True(restarted.ChangedOutside());
        restarted.Apply(NoHosts);

        Assert.Empty(firewall.Rules);
        Assert.False(restarted.ChangedOutside());
    }

    [Fact]
    public void After_a_release_a_profile_with_firewall_gets_its_own_rule_back()
    {
        var guard = Guard();
        guard.Lock(Finding(), NoHosts);

        File.Save([]);
        guard.Apply(NoHosts);

        Assert.Equal(Blocked, Assert.Single(firewall.Rules).RemoteAddresses);
    }

    [Fact]
    public void A_lockdown_state_that_cannot_be_read_locks_every_profile()
    {
        System.IO.File.WriteAllText(File.Path, "{ not json");
        var guard = Guard(Config(firewall: false));

        guard.Apply(NoHosts);
        guard.Apply(NoHosts);

        Assert.Equal("*", Assert.Single(firewall.Rules).RemoteAddresses);
        Assert.Single(log, line => line.StartsWith("Error") && line.Contains("cannot be read") && line.Contains("--release"));
    }

    [Fact]
    public void A_dry_run_changes_neither_the_firewall_nor_the_state()
    {
        var guard = Guard(dryRun: true);

        Assert.True(guard.Apply(NoHosts, force: true));
        var taken = guard.Lock(Finding(), NoHosts);

        Assert.Equal("would lock down the profile", taken);
        Assert.Empty(firewall.Calls);
        Assert.False(System.IO.File.Exists(File.Path));
        Assert.Single(log, line => line.Contains("Dry run") && line.Contains("'RCEGuard: Test'"));
    }

    [Fact]
    public void A_firewall_that_cannot_be_changed_is_reported_and_does_not_stop_the_guard()
    {
        firewall.Fail = new COMException("Access is denied.", unchecked((int)0x80070005));
        var guard = Guard();

        Assert.False(guard.Apply(NoHosts));
        var taken = guard.Lock(Finding(), NoHosts);

        Assert.StartsWith("LOCKDOWN FAILED", taken);
        Assert.Contains(log, line => line.StartsWith("Error") && line.Contains("Access is denied") && line.Contains("NOT be blocked"));
        // The lockdown is noted all the same: the next refresh that reaches the firewall puts it in place.
        Assert.Single(File.Load(out _));
        firewall.Fail = null;
        Assert.True(guard.Apply(NoHosts));
        Assert.Equal("*", Assert.Single(firewall.Rules).RemoteAddresses);
    }

    [Fact]
    public void A_firewall_that_is_turned_off_is_reported_once()
    {
        firewall.ProblemText = "Windows Firewall is turned off";
        var guard = Guard();

        guard.Apply(NoHosts);
        guard.Apply(NoHosts, force: true);

        Assert.Single(log, line => line.StartsWith("Warning") && line.Contains("turned off"));
    }

    [Fact]
    public void The_lockdown_file_keeps_its_entries_and_reports_damage()
    {
        var file = File;
        Assert.Empty(file.Load(out var problem));
        Assert.Null(problem);
        Assert.Null(file.Stamp());

        var entry = new LockdownEntry("Test", new DateTimeOffset(2026, 11, 15, 12, 0, 0, 123, TimeSpan.Zero), "R4", "Run key \"x\"");
        file.Save([entry]);

        Assert.Equal([entry], file.Load(out problem));
        Assert.Null(problem);
        Assert.NotNull(file.Stamp());

        foreach (var damaged in new[] { "", "{}", "[]", """{"locked":[{"rule":"R1"}]}""", """{"locked":[null]}""" })
        {
            System.IO.File.WriteAllText(file.Path, damaged);
            Assert.Empty(file.Load(out problem));
            Assert.NotNull(problem);
        }
    }

    [Fact]
    public async Task A_host_name_that_fails_keeps_the_addresses_it_had()
    {
        var config = new GuardConfig
        {
            Profiles = [new ClientProfile { Name = "Test", ClientPath = Client, AllowedHostnames = ["logon.example.org", "realm.example.org"] }],
        };
        var failing = new HashSet<string>();
        var book = new HostAddressBook(config, (host, _) => failing.Contains(host)
            ? throw new SocketException(11001)
            : Task.FromResult(new[] { IPAddress.Parse(host.StartsWith("logon", StringComparison.Ordinal) ? "203.0.113.7" : "203.0.113.8") }));

        Assert.Empty(await book.RefreshAsync(CancellationToken.None));
        Assert.Equal(2, book.ByProfile["Test"].Count);

        failing.Add("realm.example.org");
        var problems = await book.RefreshAsync(CancellationToken.None);

        Assert.Contains("realm.example.org", Assert.Single(problems));
        Assert.Contains("Keeping the 1 address", problems[0]);
        Assert.Equal(2, book.ByProfile["Test"].Count);

        // A host name that never resolved has no address: its server stays unknown.
        var fresh = new HostAddressBook(config, (host, _) => throw new SocketException(11001));
        Assert.Equal(2, (await fresh.RefreshAsync(CancellationToken.None)).Count);
        Assert.Empty(fresh.ByProfile["Test"]);
    }

    [Fact]
    public void Windows_Firewall_can_be_read_without_changing_it()
    {
        // Read only, and it works for every user. Shows that the COM calls of the adapter are right:
        // walking all rules, the properties of a rule, the state of the network profiles.
        var windows = new WindowsFirewall();

        var rules = windows.ReadRules();
        var problem = windows.Problem();

        Assert.All(rules, rule => Assert.StartsWith("RCEGuard", rule.Name));
        Assert.True(problem is null || problem.Contains("Windows Firewall"), problem);
    }
}
