using System.Net;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Learning;
using RCEGuard.Core.Prevention;
using RCEGuard.Core.Rules;
using RCEGuard.Core.State;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

/// <summary>Learning mode: what the rules do differently, what is noted and what is suggested.</summary>
public class LearningTests
{
    private const string Client = TestData.Client;

    private static readonly ClientProfile Learning = new() { Name = "Test", ClientPath = Client, Learning = true };

    private static GuardConfig Config(ClientProfile profile) => new() { Profiles = [profile] };

    private static SysmonEvent Connect(string ip, int port = 3724, string initiated = "true") => TestData.Event(
        SysmonEventIds.NetworkConnect,
        ("Image", Client),
        ("ProcessId", "100"),
        ("DestinationIp", ip),
        ("DestinationPort", port.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        ("Initiated", initiated));

    private static SysmonEvent Query(string name, string results) => TestData.Event(
        Learner.DnsQueryEventId, ("Image", Client), ("ProcessId", "100"), ("QueryName", name), ("QueryStatus", "0"), ("QueryResults", results));

    private static SysmonEvent FileCreate(string file) => TestData.Event(
        SysmonEventIds.FileCreate, ("Image", Client), ("ProcessId", "100"), ("TargetFilename", file));

    private static LearnedProfile Observe(ClientProfile profile, params SysmonEvent[] events)
    {
        var config = Config(profile);
        var engine = new RuleEngine(config);
        var learner = new Learner(config, []);
        foreach (var e in events)
        {
            learner.Observe(e, engine.Evaluate(e));
        }

        return learner.Profiles.SingleOrDefault() ?? new LearnedProfile();
    }

    // --- What the rules do differently ---------------------------------------------------------
    [Fact]
    public void While_learning_an_unknown_address_is_noted_instead_of_alerted()
    {
        var finding = Assert.Single(new RuleEngine(Config(Learning)).Evaluate(Connect("203.0.113.9")));

        Assert.Equal(("R2", Severity.Info, FindingAction.Log), (finding.RuleId, finding.Severity, finding.Action));
        Assert.StartsWith("Learning mode:", finding.Summary);
        Assert.Empty(finding.KillTargets);
    }

    [Fact]
    public void While_learning_an_unknown_address_does_not_terminate_even_if_the_profile_says_so()
    {
        var profile = Learning with { KillOnUnknownRemote = true };

        var finding = Assert.Single(new RuleEngine(Config(profile)).Evaluate(Connect("203.0.113.9")));

        Assert.Equal(FindingAction.Log, finding.Action);
    }

    [Fact]
    public void While_learning_an_address_that_cannot_be_read_still_alerts_but_does_not_terminate()
    {
        var profile = Learning with { KillOnUnknownRemote = true };

        var finding = Assert.Single(new RuleEngine(Config(profile)).Evaluate(Connect("not-an-address")));

        Assert.Equal((Severity.Critical, FindingAction.Alert), (finding.Severity, finding.Action));
    }

    [Fact]
    public void Learning_does_not_change_the_other_rules()
    {
        // What terminates stays a finding that terminates; that it is not carried out is the service's part.
        var finding = Assert.Single(new RuleEngine(Config(Learning)).Evaluate(TestData.Fixture("r1-child-process")));

        Assert.Equal(("R1", Severity.Critical, FindingAction.Kill), (finding.RuleId, finding.Severity, finding.Action));
    }

    [Fact]
    public void While_learning_the_firewall_rule_of_the_profile_is_not_planned_but_a_lockdown_is()
    {
        var profile = Learning with { Firewall = true, AllowedRemote = ["203.0.113.0/24"] };
        var noHosts = new Dictionary<string, IReadOnlyCollection<IPAddress>>();

        Assert.Empty(FirewallPlanner.Plan(Config(profile), noHosts, []));
        Assert.Equal("*", Assert.Single(FirewallPlanner.Plan(Config(profile), noHosts, ["Test"])).RemoteAddresses);
        Assert.Single(FirewallPlanner.Plan(Config(profile with { Learning = false }), noHosts, []));
    }

    // --- What is noted -------------------------------------------------------------------------
    [Fact]
    public void Connections_are_counted_per_address_and_port()
    {
        var learned = Observe(
            Learning,
            Connect("203.0.113.9"), Connect("203.0.113.9"), Connect("203.0.113.9", 8085), Connect("::ffff:203.0.113.10"),
            Connect("127.0.0.1"), Connect("198.51.100.1", initiated: "false"), Connect("not-an-address"));

        Assert.Equal(
            ["203.0.113.9:3724 x2", "203.0.113.9:8085 x1", "203.0.113.10:3724 x1"],
            learned.Remotes.Select(remote => $"{remote.Address}:{remote.Port} x{remote.Count}"));
    }

    [Fact]
    public void Addresses_that_are_allowed_already_are_noted_too()
    {
        // The notes say what the client does; what of it is new is decided when the suggestion is made.
        var learned = Observe(Learning with { AllowedRemote = ["203.0.113.0/24"] }, Connect("203.0.113.9"));

        Assert.Single(learned.Remotes);
    }

    [Theory]
    [InlineData("::ffff:203.0.113.9;", "203.0.113.9")]
    [InlineData("type:  5 edge.example.net;::ffff:203.0.113.9;::ffff:203.0.113.10;", "203.0.113.9,203.0.113.10")]
    [InlineData("203.0.113.9;2001:db8::1;", "203.0.113.9,2001:db8::1")]
    [InlineData("-", "")]
    [InlineData("", "")]
    public void The_addresses_are_read_from_the_answer_of_a_name_query(string results, string expected)
    {
        Assert.Equal(expected, string.Join(",", Learner.AddressesIn(results)));
    }

    [Fact]
    public void Name_queries_are_noted_with_their_addresses()
    {
        var learned = Observe(
            Learning,
            Query("Logon.Example.org.", "::ffff:203.0.113.9;"),
            Query("logon.example.org", "::ffff:203.0.113.10;"),
            Query("", "::ffff:203.0.113.11;"));

        var host = Assert.Single(learned.Hosts);
        Assert.Equal(("logon.example.org", 2), (host.Name, host.Count));
        Assert.Equal(["203.0.113.9", "203.0.113.10"], host.Addresses);
    }

    [Fact]
    public void Files_outside_the_game_folder_are_noted_by_folder_and_extension()
    {
        var learned = Observe(
            Learning,
            FileCreate(@"C:\Users\player\AppData\Local\Temp\a.tmp"),
            FileCreate(@"c:\users\player\appdata\local\temp\B.TMP"),
            FileCreate(@"C:\Users\player\AppData\Local\Temp\noextension"),
            FileCreate(@"C:\RCEGuardTest\Data\patch.MPQ"));

        var folder = Assert.Single(learned.Folders);
        Assert.Equal((@"C:\Users\player\AppData\Local\Temp\", 3), (folder.Folder, folder.Count));
        Assert.Equal([".tmp", string.Empty], folder.Extensions);
    }

    [Fact]
    public void A_program_the_client_started_itself_is_not_noted_as_opened()
    {
        var learned = Observe(Learning, TestData.Fixture("r1-child-process"), TestData.Fixture("r7-process-access-own-child"));

        Assert.Empty(learned.Programs);
    }

    [Fact]
    public void Another_program_the_client_opens_is_noted_with_the_access_rights()
    {
        var access = TestData.Fixture("r7-process-access-own-child");

        var learned = Observe(Learning, access, access);

        var program = Assert.Single(learned.Programs);
        Assert.Equal((@"C:\WINDOWS\SYSTEM32\cmd.exe", 2), (program.Image, program.Count));
        Assert.Equal(["0x1fffff"], program.Access);
    }

    [Fact]
    public void Starts_of_the_client_are_counted_and_the_period_is_kept()
    {
        var learned = Observe(Learning, TestData.Fixture("client-start"), TestData.Fixture("r2-network-connect"));

        Assert.Equal(1, learned.Sessions);
        Assert.Equal(TestData.Fixture("client-start").TimeCreated, learned.FirstEventUtc);
        Assert.Equal(TestData.Fixture("r2-network-connect").TimeCreated, learned.LastEventUtc);
    }

    [Fact]
    public void Nothing_is_noted_for_a_profile_that_is_not_learning()
    {
        var config = Config(Learning with { Learning = false });
        var learner = new Learner(config, []);

        Assert.False(learner.Active);
        Assert.False(learner.Observe(Connect("203.0.113.9"), []));
        Assert.Empty(learner.Profiles);
    }

    [Fact]
    public void Earlier_notes_are_continued_and_those_of_other_profiles_are_kept()
    {
        var before = new LearnedProfile { Profile = "test", Sessions = 2, Remotes = [new LearnedRemote { Address = "203.0.113.9", Port = 3724, Count = 5 }] };
        var other = new LearnedProfile { Profile = "Gone", Sessions = 1 };
        var learner = new Learner(Config(Learning), [before, other]);

        Assert.True(learner.Observe(Connect("203.0.113.9"), []));

        Assert.Equal(2, learner.Profiles.Count);
        Assert.Equal(6, learner.Profiles.Single(profile => profile.Profile == "test").Remotes.Single().Count);
    }

    [Fact]
    public void A_full_list_takes_nothing_new_and_says_so()
    {
        var config = Config(Learning);
        var learner = new Learner(config, []);
        for (var i = 0; i < Learner.MaxEntries; i++)
        {
            learner.Observe(Connect($"203.0.{i / 250}.{i % 250 + 1}"), []);
        }

        var learned = learner.Profiles.Single();
        Assert.False(learned.Truncated);

        Assert.True(learner.Observe(Connect("198.51.100.1"), []));   // "full" is news that has to be saved
        Assert.False(learner.Observe(Connect("198.51.100.2"), []));
        Assert.True(learner.Observe(Connect("203.0.0.1"), []));      // known: still counted

        Assert.True(learned.Truncated);
        Assert.Equal(Learner.MaxEntries, learned.Remotes.Count);
    }

    // --- What is suggested ---------------------------------------------------------------------
    [Fact]
    public void An_address_without_a_name_is_suggested_as_an_address()
    {
        var learned = Observe(Learning, Connect("203.0.113.9"), Connect("203.0.113.9", 8085));

        var suggestion = LearnedReport.Suggest(learned, Learning);

        Assert.Equal(["203.0.113.9"], suggestion.Addresses);
        Assert.Empty(suggestion.Hostnames);
    }

    [Fact]
    public void An_address_the_client_asked_a_name_for_is_suggested_as_that_name()
    {
        var learned = Observe(
            Learning,
            Query("logon.example.org", "::ffff:203.0.113.9;::ffff:203.0.113.10;"),
            Connect("203.0.113.9"), Connect("203.0.113.10"), Connect("198.51.100.7"));

        var suggestion = LearnedReport.Suggest(learned, Learning);

        Assert.Equal(["logon.example.org"], suggestion.Hostnames);
        Assert.Equal(["198.51.100.7"], suggestion.Addresses);
    }

    private static SysmonEvent Access(string target, string access) => TestData.Event(
        SysmonEventIds.ProcessAccess,
        ("SourceImage", Client),
        ("SourceProcessId", "100"),
        ("SourceProcessGUID", "{22222222-0000-0000-0000-000000000001}"),
        ("TargetImage", target),
        ("TargetProcessGUID", "{22222222-0000-0000-0000-000000000002}"),
        ("GrantedAccess", access));

    [Fact]
    public void A_program_the_client_looked_at_is_suggested_but_not_one_it_only_opened_to_change()
    {
        var learned = Observe(
            Learning,
            Access(@"C:\Windows\explorer.exe", "0x1410"),
            Access(@"C:\Tools\both.exe", "0x1000"), Access(@"C:\Tools\both.exe", "0x1fffff"),
            Access(@"C:\Tools\changed.exe", "0x1fffff"));

        var suggestion = LearnedReport.Suggest(learned, Learning);
        var text = LearnedReport.Render(learned, Learning);

        Assert.Equal([@"C:\Windows\explorer.exe", @"C:\Tools\both.exe"], suggestion.Programs);
        Assert.Contains(@"C:\Tools\changed.exe  1x  0x1fffff  <- with rights to change it: reported even if listed", text);
        Assert.Contains(@"C:\Windows\explorer.exe  1x  0x1410" + Environment.NewLine, text);
        Assert.Contains(@"""allowedProcessAccess"": [""C:\\Windows\\explorer.exe"",""C:\\Tools\\both.exe""]", text);
    }

    [Fact]
    public void A_listed_program_is_neither_noted_again_nor_suggested()
    {
        var profile = Learning with { AllowedProcessAccess = [@"C:\Windows\explorer.exe"] };

        var learned = Observe(profile, Access(@"C:\WINDOWS\Explorer.EXE", "0x1410"), Access(@"C:\WINDOWS\Explorer.EXE", "0x1fffff"));

        // Looking at it left no finding and so no note; opening it to change it did.
        var program = Assert.Single(learned.Programs);
        Assert.Equal(["0x1fffff"], program.Access);
        Assert.True(LearnedReport.Suggest(learned, profile).IsEmpty);
        Assert.Contains("(on allowedProcessAccess)", LearnedReport.Render(learned, profile));
    }

    [Fact]
    public void What_the_allowlist_covers_already_is_not_suggested()
    {
        var profile = Learning with { AllowedRemote = ["198.51.100.0/24"], AllowedHostnames = ["LOGON.example.org"] };
        var learned = Observe(profile, Query("logon.example.org", "::ffff:203.0.113.9;"), Connect("203.0.113.9"), Connect("198.51.100.7"));

        var suggestion = LearnedReport.Suggest(learned, profile);

        Assert.Empty(suggestion.Hostnames);
        Assert.Empty(suggestion.Addresses);
        Assert.Contains("nothing to add", LearnedReport.Render(learned, profile));
    }

    [Fact]
    public void The_text_shows_what_was_noted_and_the_lists_as_they_would_be()
    {
        var profile = Learning with { AllowedRemote = ["198.51.100.0/24"] };
        var learned = Observe(
            profile,
            TestData.Fixture("client-start"),
            Query("logon.example.org", "::ffff:203.0.113.9;"),
            Query("unused.example.org", "::ffff:192.0.2.1;"),
            Connect("203.0.113.9"), Connect("198.51.100.7"), Connect("192.0.2.200", 80),
            FileCreate(@"C:\Users\player\AppData\Roaming\x.exe"),
            TestData.Fixture("r7-process-access-own-child"));

        var text = LearnedReport.Render(learned, profile);

        Assert.Contains("Learning mode is ON. Noted: 1 start(s) of the client", text);
        Assert.Matches(@"203\.0\.113\.9:3724\s+1x\s+logon\.example\.org\s+NOT on the allowlist", text);
        Assert.Matches(@"198\.51\.100\.7:3724\s+1x\s+-\s+allowed by allowedRemote", text);
        Assert.Contains("unused.example.org (1x)", text);
        Assert.Contains(@"C:\Users\player\AppData\Roaming\  1x  .exe  <- program files", text);
        Assert.Contains(@"C:\WINDOWS\SYSTEM32\cmd.exe  1x  0x1fffff", text);
        Assert.Contains("\"allowedHostnames\": [\"logon.example.org\"],", text);
        Assert.Contains("\"allowedRemote\": [\"198.51.100.0/24\",\"192.0.2.200\"]", text);
        Assert.Contains("Only take over what you recognise", text);
    }

    // --- The file ------------------------------------------------------------------------------
    [Fact]
    public void The_notes_survive_being_saved_and_read()
    {
        var folder = Directory.CreateTempSubdirectory("rceguard-learned-").FullName;
        try
        {
            var file = new LearnedFile(Path.Combine(folder, LearnedFile.FileName));
            Assert.Empty(file.Load(out var none));
            Assert.Null(none);

            var learned = Observe(
                Learning, TestData.Fixture("client-start"), Query("logon.example.org", "::ffff:203.0.113.9;"), Connect("203.0.113.9"),
                FileCreate(@"C:\Temp\a.tmp"), TestData.Fixture("r7-process-access-own-child"));
            file.Save([learned]);

            var read = Assert.Single(file.Load(out var problem));
            Assert.Null(problem);
            Assert.Equal(LearnedReport.Render(learned, Learning), LearnedReport.Render(read, Learning));
            Assert.Equal(learned.FirstEventUtc, read.FirstEventUtc);

            File.WriteAllText(file.Path, "{ not json");
            Assert.Empty(file.Load(out problem));
            Assert.NotNull(problem);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void The_switch_is_read_from_the_configuration_and_is_off_by_default()
    {
        var json = $$"""{"profiles":[{"name":"A","clientPath":"C:\\A\\Wow.exe","learning":true},{"name":"B","clientPath":"C:\\B\\Wow.exe"}]}""";

        var config = GuardConfigJson.Parse(json);

        Assert.Equal([true, false], config.Profiles.Select(profile => profile.Learning));
    }
}
