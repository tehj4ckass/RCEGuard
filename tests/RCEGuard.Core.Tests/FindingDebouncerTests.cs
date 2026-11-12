using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Tests;

public class FindingDebouncerTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 12, 18, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    private static Finding Alert(double secondsAfterStart, string target = "1.1.1.1:443", int pid = 100, string rule = "R2",
        FindingAction action = FindingAction.Alert, Severity severity = Severity.Critical) => new()
    {
        RuleId = rule,
        Severity = severity,
        Action = action,
        Summary = "test",
        Profile = "Test",
        ProcessId = pid,
        Target = target,
        Time = Start.AddSeconds(secondsAfterStart),
    };

    [Fact]
    public void The_first_finding_is_reported_and_repeats_within_the_window_are_counted()
    {
        var debouncer = new FindingDebouncer(Window);

        var first = debouncer.Check(Alert(0));
        var second = debouncer.Check(Alert(10));
        var third = debouncer.Check(Alert(299));

        Assert.True(first.Report);
        Assert.False(second.Report);
        Assert.False(third.Report);
        Assert.Same(first.Entry, third.Entry);
        Assert.Equal(2, first.Entry!.Repeats);
        Assert.Equal(Start.AddSeconds(299), first.Entry.Last);
    }

    [Fact]
    public void After_the_window_the_finding_is_reported_again_with_the_count_of_the_repeats()
    {
        var debouncer = new FindingDebouncer(Window);
        debouncer.Check(Alert(0));
        debouncer.Check(Alert(1));
        debouncer.Check(Alert(2));

        var again = debouncer.Check(Alert(300));

        Assert.True(again.Report);
        Assert.Equal(2, again.RepeatsBefore);
        Assert.Equal(0, again.Entry!.Repeats);
        Assert.False(debouncer.Check(Alert(301)).Report);
    }

    [Theory]
    [InlineData("9.9.9.9:443", 100, "R2")] // other target
    [InlineData("1.1.1.1:443", 200, "R2")] // other client process: a new session of the game
    [InlineData("1.1.1.1:443", 100, "R3")] // other rule
    public void A_different_target_process_or_rule_is_its_own_finding(string target, int pid, string rule)
    {
        var debouncer = new FindingDebouncer(Window);
        debouncer.Check(Alert(0));

        Assert.True(debouncer.Check(Alert(1, target, pid, rule)).Report);
    }

    [Fact]
    public void A_higher_severity_for_the_same_target_is_reported()
    {
        var debouncer = new FindingDebouncer(Window);
        debouncer.Check(Alert(0, action: FindingAction.Log, severity: Severity.Medium));

        Assert.True(debouncer.Check(Alert(1, action: FindingAction.Alert, severity: Severity.High)).Report);
    }

    [Fact]
    public void Targets_are_compared_without_case()
    {
        var debouncer = new FindingDebouncer(Window);
        debouncer.Check(Alert(0, @"C:\Users\player\AppData\Roaming\x.exe", rule: "R3"));

        Assert.False(debouncer.Check(Alert(1, @"c:\users\PLAYER\appdata\roaming\X.EXE", rule: "R3")).Report);
    }

    [Fact]
    public void Findings_that_terminate_a_process_always_pass()
    {
        var debouncer = new FindingDebouncer(Window);

        for (var i = 0; i < 5; i++)
        {
            var decision = debouncer.Check(Alert(i, action: FindingAction.Kill));
            Assert.True(decision.Report);
            Assert.Null(decision.Entry);
        }
    }

    [Fact]
    public void A_window_of_zero_reports_everything()
    {
        var debouncer = new FindingDebouncer(TimeSpan.Zero);

        Assert.True(debouncer.Check(Alert(0)).Report);
        Assert.True(debouncer.Check(Alert(0)).Report);
    }

    [Fact]
    public void An_event_older_than_the_report_counts_as_a_repeat()
    {
        var debouncer = new FindingDebouncer(Window);
        var first = debouncer.Check(Alert(10));

        Assert.False(debouncer.Check(Alert(5)).Report);
        Assert.Equal(Start.AddSeconds(10), first.Entry!.Last);
    }

    [Fact]
    public void The_memory_is_bounded()
    {
        var debouncer = new FindingDebouncer(Window, capacity: 3);
        for (var i = 0; i < 10; i++)
        {
            Assert.True(debouncer.Check(Alert(i, target: $"10.0.0.{i}:443")).Report);
        }

        // The oldest entries were dropped; the price is one extra report, never a lost one.
        Assert.True(debouncer.Check(Alert(11, target: "10.0.0.0:443")).Report);
        Assert.False(debouncer.Check(Alert(12, target: "10.0.0.0:443")).Report);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(86401)]
    public void The_window_in_the_configuration_is_validated(int seconds)
    {
        var json = $$"""{ "repeatWindowSeconds": {{seconds}}, "profiles": [ { "name": "A", "clientPath": "C:\\Games\\Wow.exe" } ] }""";

        Assert.Throws<FormatException>(() => GuardConfigJson.Parse(json));
    }

    [Fact]
    public void The_window_defaults_to_five_minutes_and_can_be_set()
    {
        const string Profiles = """ "profiles": [ { "name": "A", "clientPath": "C:\\Games\\Wow.exe" } ] """;

        Assert.Equal(300, GuardConfigJson.Parse("{" + Profiles + "}").RepeatWindowSeconds);
        Assert.Equal(0, GuardConfigJson.Parse("""{ "repeatWindowSeconds": 0, """ + Profiles + "}").RepeatWindowSeconds);
    }
}
