using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

/// <summary>A scan (the client opens many programs to read them) becomes one finding.</summary>
public class ScanBundlerTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 15, 22, 27, 15, TimeSpan.Zero);

    private static ScanBundler Bundler() => new(TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(60));

    private static Finding Opened(string program, double atSeconds, string access = "0x10", int pid = 100, string profile = "Test") => new()
    {
        RuleId = "R7",
        Severity = ProcessAccessRules.Classify(access) == ProcessAccessKind.ReadsMemory ? Severity.Medium : Severity.Info,
        Action = FindingAction.Log,
        Summary = $"The game client opened another program to read its memory ({access}): {program}",
        Profile = profile,
        Image = TestData.Client,
        ProcessId = pid,
        Target = program,
        Detail = access,
        Time = Start.AddSeconds(atSeconds),
        RecordId = 1000 + (long)(atSeconds * 100),
    };

    [Fact]
    public void A_burst_is_held_back_and_reported_as_one_finding_when_it_is_over()
    {
        var bundler = Bundler();
        string[] programs =
        [
            @"C:\Program Files\Google\Chrome\Application\chrome.exe", @"C:\Users\player\AppData\Local\Discord\Discord.exe", @"C:\WINDOWS\Explorer.EXE",
            @"C:\WINDOWS\system32\svchost.exe", @"C:\WINDOWS\system32\conhost.exe", @"C:\WINDOWS\system32\sihost.exe", @"C:\Windows\System32\smartscreen.exe",
        ];
        for (var i = 0; i < programs.Length; i++)
        {
            Assert.Empty(bundler.Add(Opened(programs[i], i * 0.05)));
        }

        // The same programs once more: accesses, not programs.
        Assert.Empty(bundler.Add(Opened(programs[0].ToUpperInvariant(), 0.4)));
        Assert.Empty(bundler.Add(Opened(programs[1], 0.5, access: "0x1410")));
        Assert.True(bundler.HasPending);
        Assert.Empty(bundler.Flush(Start.AddSeconds(3.4)));   // 2.9 s after the last one: not over yet

        var finding = Assert.Single(bundler.Flush(Start.AddSeconds(3.5)));

        Assert.False(bundler.HasPending);
        Assert.Equal(("R7", Severity.Medium, FindingAction.Log, "Test", 100), (finding.RuleId, finding.Severity, finding.Action, finding.Profile, finding.ProcessId));
        Assert.Equal(
            "The game client opened 7 other programs to read their memory (0x10, 0x1410; 9 accesses within 1 s): chrome.exe, Discord.exe, Explorer.EXE, svchost.exe, conhost.exe and 2 more",
            finding.Summary);
        Assert.Equal("7 programs", finding.Target);
        Assert.Equal(Start, finding.Time);
        Assert.Empty(bundler.Flush(Start.AddSeconds(100)));
    }

    [Fact]
    public void One_program_opened_once_is_reported_as_it_came()
    {
        var bundler = Bundler();
        var single = Opened(@"C:\WINDOWS\Explorer.EXE", 0, access: "0x1010");
        bundler.Add(single);

        Assert.Same(single, Assert.Single(bundler.Flush(Start.AddSeconds(3))));
    }

    [Fact]
    public void One_program_opened_several_times_says_so()
    {
        var bundler = Bundler();
        bundler.Add(Opened(@"C:\WINDOWS\Explorer.EXE", 0, access: "0x1000"));
        bundler.Add(Opened(@"C:\WINDOWS\Explorer.EXE", 1, access: "0x1000"));
        bundler.Add(Opened(@"C:\WINDOWS\Explorer.EXE", 2.5, access: "0x1000"));

        var finding = Assert.Single(bundler.Flush(Start.AddSeconds(10)));

        Assert.Equal("The game client opened another program without reading or changing it (0x1000; 3 accesses within 3 s): Explorer.EXE", finding.Summary);
        Assert.Equal((Severity.Info, @"C:\WINDOWS\Explorer.EXE"), (finding.Severity, finding.Target));
    }

    [Fact]
    public void A_finding_that_alerts_and_other_rules_pass_at_once_and_untouched()
    {
        var bundler = Bundler();
        bundler.Add(Opened(@"C:\a.exe", 0));
        var alert = Opened(@"C:\WINDOWS\Explorer.EXE", 0.1, access: "0x102a") with { Severity = Severity.High, Action = FindingAction.Alert };
        var other = Opened(@"C:\x", 0.2) with { RuleId = "R3" };

        Assert.Same(alert, Assert.Single(bundler.Add(alert)));
        Assert.Same(other, Assert.Single(bundler.Add(other)));
        // The scan they arrived in is still open.
        Assert.True(bundler.HasPending);
    }

    [Fact]
    public void Two_scans_are_two_findings_also_when_nobody_flushes_in_between()
    {
        // As in a replayed file: only the times of the events tell the scans apart.
        var bundler = Bundler();
        bundler.Add(Opened(@"C:\a.exe", 0));
        bundler.Add(Opened(@"C:\b.exe", 0.2));

        var first = Assert.Single(bundler.Add(Opened(@"C:\c.exe", 30)));
        bundler.Add(Opened(@"C:\d.exe", 30.1));
        var second = Assert.Single(bundler.FlushAll());

        Assert.StartsWith("The game client opened 2 other programs", first.Summary);
        Assert.EndsWith(": a.exe, b.exe", first.Summary);
        Assert.EndsWith(": c.exe, d.exe", second.Summary);
        Assert.False(bundler.HasPending);
    }

    [Fact]
    public void Old_events_that_are_read_up_on_are_held_until_nothing_more_arrives()
    {
        // The guard was down while the client scanned: the events are an hour old, but they arrive now, one by one.
        var bundler = Bundler();
        var now = Start.AddHours(1);
        Assert.Empty(bundler.Add(Opened(@"C:\a.exe", 0), arrived: now));
        Assert.Empty(bundler.Flush(now.AddSeconds(0.5)));
        Assert.Empty(bundler.Add(Opened(@"C:\b.exe", 0.1), arrived: now.AddSeconds(1)));
        Assert.Empty(bundler.Flush(now.AddSeconds(3.5)));   // 2.5 s after the last arrival

        var finding = Assert.Single(bundler.Flush(now.AddSeconds(4)));

        Assert.StartsWith("The game client opened 2 other programs to read their memory (0x10; 2 accesses within 1 s)", finding.Summary);
        Assert.Equal(Start, finding.Time);
    }

    [Fact]
    public void A_scan_that_never_pauses_is_reported_after_a_minute()
    {
        var bundler = Bundler();
        var reported = new List<Finding>();
        for (var second = 0; second <= 130; second++)
        {
            reported.AddRange(bundler.Add(Opened($@"C:\p{second}.exe", second)));
            reported.AddRange(bundler.Flush(Start.AddSeconds(second)));
        }

        Assert.Equal(2, reported.Count);
        Assert.All(reported, finding => Assert.Contains("60 other programs", finding.Summary));
    }

    [Fact]
    public void Clients_and_profiles_are_bundled_apart()
    {
        var bundler = Bundler();
        bundler.Add(Opened(@"C:\a.exe", 0, pid: 100));
        bundler.Add(Opened(@"C:\b.exe", 0, pid: 100));
        bundler.Add(Opened(@"C:\a.exe", 0, pid: 200));
        bundler.Add(Opened(@"C:\b.exe", 0, pid: 200, profile: "Other"));

        var findings = bundler.Flush(Start.AddSeconds(5));

        Assert.Equal(3, findings.Count);
        Assert.Single(findings, finding => finding.Summary.Contains("2 other programs"));
    }

    [Fact]
    public void The_rule_engine_hands_the_access_rights_on_for_bundling()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r7-process-access-read")));

        Assert.Equal("0x1010", finding.Detail);
        Assert.Empty(Bundler().Add(finding));
    }
}
