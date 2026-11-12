using System.Net;
using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

/// <summary>The rules against events Sysmon really recorded for the simulator.</summary>
public class RecordedEventTests
{
    [Fact]
    public void Parser_reads_the_fields_of_a_recorded_event()
    {
        var e = TestData.Fixture("r1-child-process");

        Assert.Equal(SysmonEventIds.ProcessCreate, e.EventId);
        Assert.Equal(25, e.RecordId);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 14, 4, 58, TimeSpan.Zero), e.TimeCreated.AddTicks(-(e.TimeCreated.Ticks % TimeSpan.TicksPerSecond)));
        Assert.Equal("R1", e.RuleName);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", e.Get("Image"));
        Assert.Equal(33884, e.GetInt("ProcessId"));
        Assert.Equal(TestData.Client, e.Get("parentimage")); // field names ignore case
        Assert.Equal(string.Empty, e.Get("NoSuchField"));
        Assert.Null(e.GetInt("Image"));
    }

    [Theory]
    [InlineData("client-start")]
    [InlineData("client-exit")]
    [InlineData("r4-bam-services-noise")]
    [InlineData("r5-client-image-unsigned")]
    [InlineData("r5-system-dll-signed")]
    public void Expected_events_produce_no_finding(string fixture)
    {
        Assert.Empty(TestData.Engine().Evaluate(TestData.Fixture(fixture)));
    }

    [Fact]
    public void R1_child_process_kills_the_child_and_the_client()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r1-child-process")));

        Assert.Equal("R1", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Kill, finding.Action);
        Assert.Equal("Test", finding.Profile);
        Assert.Equal(TestData.ClientPid, finding.ProcessId);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", finding.Target);
        Assert.Equal(
            [
                new KillTarget(33884, @"C:\Windows\System32\cmd.exe", true, new DateTimeOffset(2026, 11, 12, 14, 4, 58, 424, TimeSpan.Zero)),
                new KillTarget(TestData.ClientPid, TestData.Client, true),
            ],
            finding.KillTargets);
    }

    [Fact]
    public void R9_is_found_from_the_command_line_although_sysmon_names_only_R1()
    {
        var e = TestData.Fixture("r1-miner-child");
        Assert.Equal("R1", e.RuleName);

        var findings = TestData.Engine().Evaluate(e);

        Assert.Equal(["R1", "R9"], findings.Select(f => f.RuleId));
        Assert.All(findings, f => Assert.Equal(FindingAction.Kill, f.Action));
        Assert.All(findings, f => Assert.Equal(2, f.KillTargets.Count));
    }

    [Fact]
    public void R9_outside_the_client_is_reported_but_nothing_is_killed()
    {
        // Same event, but the configured client is a different one: the miner-like process is unrelated to it.
        var engine = TestData.Engine(TestData.Profile(@"D:\Games\Other\Wow.exe"));

        var finding = Assert.Single(engine.Evaluate(TestData.Fixture("r1-miner-child")));

        Assert.Equal("R9", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Alert, finding.Action);
        Assert.Empty(finding.KillTargets);
        Assert.Equal(string.Empty, finding.Profile);
    }

    [Fact]
    public void R2_unknown_remote_alerts_without_killing_by_default()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r2-network-connect")));

        Assert.Equal("R2", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Alert, finding.Action);
        Assert.Equal("1.1.1.1:443", finding.Target);
        Assert.Empty(finding.KillTargets);
    }

    [Fact]
    public void R2_kills_when_the_profile_asks_for_it()
    {
        var engine = TestData.Engine(TestData.Profile() with { KillOnUnknownRemote = true });

        var finding = Assert.Single(engine.Evaluate(TestData.Fixture("r2-network-connect")));

        Assert.Equal(FindingAction.Kill, finding.Action);
        Assert.Equal([new KillTarget(finding.ProcessId!.Value, TestData.Client, true)], finding.KillTargets);
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("1.1.1.0/24")]
    [InlineData("0.0.0.0/0")]
    public void R2_allowed_remote_produces_no_finding(string allowed)
    {
        var engine = TestData.Engine(TestData.Profile() with { AllowedRemote = [allowed] });

        Assert.Empty(engine.Evaluate(TestData.Fixture("r2-network-connect")));
    }

    [Fact]
    public void R2_address_of_a_resolved_host_name_is_allowed()
    {
        var engine = TestData.Engine();
        engine.SetResolvedHosts("Test", [IPAddress.Parse("1.1.1.1")]);

        Assert.Empty(engine.Evaluate(TestData.Fixture("r2-network-connect")));
    }

    [Fact]
    public void R3_program_file_outside_the_game_folder_alerts()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r3-file-create-appdata")));

        Assert.Equal("R3", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(FindingAction.Alert, finding.Action);
        Assert.Equal(@"C:\Users\player\AppData\Roaming\rceguard-test.exe", finding.Target);
    }

    [Fact]
    public void R4_run_key_under_the_user_hive_kills_the_client()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r4-run-key-set")));

        Assert.Equal("R4", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Kill, finding.Action);
        Assert.StartsWith(@"HKU\S-1-5-21-", finding.Target);
        Assert.Equal(TestData.Client, Assert.Single(finding.KillTargets).Image);
    }

    [Fact]
    public void R4_removing_a_run_value_is_only_logged()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r4-run-key-delete")));

        Assert.Equal("R4", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingAction.Log, finding.Action);
        Assert.Empty(finding.KillTargets);
    }

    [Fact]
    public void R7_access_to_a_child_the_client_started_is_part_of_R1()
    {
        var engine = TestData.Engine();
        engine.Evaluate(TestData.Fixture("r1-child-process"));

        Assert.Empty(engine.Evaluate(TestData.Fixture("r7-process-access-own-child")));
    }

    [Fact]
    public void R7_access_to_an_unknown_process_is_logged()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r7-process-access-own-child")));

        Assert.Equal("R7", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingAction.Log, finding.Action);
        Assert.Contains("0x1fffff", finding.Summary);
    }

    [Fact]
    public void Children_are_forgotten_when_the_client_exits()
    {
        var engine = TestData.Engine();
        engine.Evaluate(TestData.Fixture("r1-child-process"));
        engine.Evaluate(TestData.Fixture("client-exit"));

        Assert.Single(engine.Evaluate(TestData.Fixture("r7-process-access-own-child")));
    }

    [Fact]
    public void Events_of_a_client_that_is_not_configured_are_ignored()
    {
        var engine = TestData.Engine(TestData.Profile(@"D:\Games\Other\Wow.exe"));

        foreach (var fixture in new[] { "r1-child-process", "r2-network-connect", "r3-file-create-appdata", "r4-run-key-set", "r7-process-access-own-child" })
        {
            Assert.Empty(engine.Evaluate(TestData.Fixture(fixture)));
        }
    }

    [Fact]
    public void Client_path_is_compared_without_case()
    {
        var engine = TestData.Engine(TestData.Profile(@"c:\rceguardtest\WOW.EXE"));

        Assert.Single(engine.Evaluate(TestData.Fixture("r1-child-process")));
    }
}
