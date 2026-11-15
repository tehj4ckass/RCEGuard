using RCEGuard.Core.Configuration;
using RCEGuard.Core.Learning;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Tests;

/// <summary>R8: processor load of a client over a window of time.</summary>
public class CpuWatchTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Feeds samples every 15 s; <paramref name="coresPerStep"/> is the load between one sample and the next.</summary>
    private static List<CpuVerdict> Run(CpuWatch watch, params double[] coresPerStep)
    {
        var verdicts = new List<CpuVerdict> { watch.Sample("p", Start, TimeSpan.Zero) };
        var cpu = TimeSpan.Zero;
        for (var i = 0; i < coresPerStep.Length; i++)
        {
            cpu += TimeSpan.FromSeconds(15 * coresPerStep[i]);
            verdicts.Add(watch.Sample("p", Start.AddSeconds(15 * (i + 1)), cpu));
        }

        return verdicts;
    }

    [Fact]
    public void Nothing_is_said_before_a_whole_window_was_watched()
    {
        var verdicts = Run(new CpuWatch(2.0, TimeSpan.FromSeconds(60)), 8, 8, 8);

        Assert.All(verdicts, verdict => Assert.Equal(new CpuVerdict(null, false), verdict));
    }

    [Fact]
    public void A_window_above_the_threshold_alerts_once_and_not_again_while_it_stays_high()
    {
        var verdicts = Run(new CpuWatch(2.0, TimeSpan.FromSeconds(60)), 8, 8, 8, 8, 8, 8);

        Assert.Equal([false, false, false, false, true, false, false], verdicts.Select(verdict => verdict.Alert));
        Assert.Equal(8.0, verdicts[4].Cores!.Value, 3);
    }

    [Fact]
    public void The_average_counts_not_a_short_burst()
    {
        // One step at eight cores in a minute of one core: (8 + 1 + 1 + 1) / 4 = 2.75 > 2 while the
        // burst is in the window, 1.0 once it has left.
        var verdicts = Run(new CpuWatch(3.0, TimeSpan.FromSeconds(60)), 1, 1, 1, 8, 1, 1, 1, 1);

        Assert.DoesNotContain(verdicts, verdict => verdict.Alert);
        Assert.Equal(2.75, verdicts[4].Cores!.Value, 3);
        Assert.Equal(1.0, verdicts[8].Cores!.Value, 3);
    }

    [Fact]
    public void A_load_at_the_threshold_is_not_above_it()
    {
        var verdicts = Run(new CpuWatch(2.0, TimeSpan.FromSeconds(60)), 2, 2, 2, 2, 2);

        Assert.DoesNotContain(verdicts, verdict => verdict.Alert);
        Assert.Equal(2.0, verdicts[^1].Cores!.Value, 3);
    }

    [Fact]
    public void After_the_load_dropped_a_new_stretch_alerts_again()
    {
        var verdicts = Run(new CpuWatch(2.0, TimeSpan.FromSeconds(30)), 4, 4, 4, 0, 0, 0, 4, 4, 4);

        // Alerts with the first full window (index 2), is quiet while the load stays, falls to the
        // threshold and below (from index 4), and alerts again with the next window above it (index 8).
        Assert.Equal(
            [false, false, true, false, false, false, false, false, true, false],
            verdicts.Select(verdict => verdict.Alert));
    }

    [Fact]
    public void Processor_time_that_goes_back_starts_the_measurement_over()
    {
        var watch = new CpuWatch(2.0, TimeSpan.FromSeconds(30));
        watch.Sample("p", Start, TimeSpan.FromSeconds(1000));
        watch.Sample("p", Start.AddSeconds(15), TimeSpan.FromSeconds(1100));

        // Another process has the pid now: its counter starts low.
        Assert.Null(watch.Sample("p", Start.AddSeconds(30), TimeSpan.FromSeconds(1)).Cores);
        Assert.Null(watch.Sample("p", Start.AddSeconds(45), TimeSpan.FromSeconds(2)).Cores);
        Assert.Equal(1.0 / 15, watch.Sample("p", Start.AddSeconds(60), TimeSpan.FromSeconds(3)).Cores!.Value, 3);
    }

    [Fact]
    public void Processes_are_measured_apart_and_a_forgotten_one_starts_over()
    {
        var watch = new CpuWatch(2.0, TimeSpan.FromSeconds(15));
        watch.Sample("a", Start, TimeSpan.Zero);
        watch.Sample("b", Start, TimeSpan.Zero);

        Assert.True(watch.Sample("a", Start.AddSeconds(15), TimeSpan.FromSeconds(60)).Alert);
        Assert.False(watch.Sample("b", Start.AddSeconds(15), TimeSpan.FromSeconds(1)).Alert);

        watch.Forget("a");
        Assert.Null(watch.Sample("a", Start.AddSeconds(30), TimeSpan.FromSeconds(120)).Cores);
    }

    [Theory]
    [InlineData(300, "over the last 5 min")]
    [InlineData(30, "over the last 30 s")]
    [InlineData(90, "over the last 90 s")]
    public void The_finding_is_an_alert_that_terminates_nothing(int seconds, string expected)
    {
        var finding = new CpuWatch(2.0, TimeSpan.FromSeconds(seconds)).ToFinding("Test", TestData.Client, 100, 7.96, Start);

        Assert.Equal(("R8", Severity.Medium, FindingAction.Alert), (finding.RuleId, finding.Severity, finding.Action));
        Assert.Equal($"The game client kept 8.0 processor cores busy on average {expected} (alert above 2.0)", finding.Summary);
        Assert.Equal(("Test", TestData.Client, 100, Start), (finding.Profile, finding.Image, finding.ProcessId, finding.Time));
        Assert.Empty(finding.KillTargets);
    }

    [Theory]
    [InlineData("""{"cpuAlertCores": -1,""", "cpuAlertCores must be between 0 (off) and 1024")]
    [InlineData("""{"cpuAlertCores": 2000,""", "cpuAlertCores must be between 0 (off) and 1024")]
    [InlineData("""{"cpuAlertSeconds": 4,""", "cpuAlertSeconds must be between 5 and 86400")]
    [InlineData("""{"cpuAlertSeconds": 90000,""", "cpuAlertSeconds must be between 5 and 86400")]
    public void The_settings_are_checked(string start, string expected)
    {
        var error = Assert.Throws<FormatException>(() => GuardConfigJson.Parse(start + """ "profiles":[{"name":"A","clientPath":"C:\\A\\Wow.exe"}]}"""));

        Assert.Contains(expected, error.Message);
    }

    [Fact]
    public void The_defaults_are_two_cores_over_five_minutes_and_zero_turns_the_rule_off()
    {
        var defaults = GuardConfigJson.Parse("""{"profiles":[{"name":"A","clientPath":"C:\\A\\Wow.exe"}]}""");
        var off = GuardConfigJson.Parse("""{"cpuAlertCores": 0, "profiles":[{"name":"A","clientPath":"C:\\A\\Wow.exe"}]}""");

        Assert.Equal((2.0, 300), (defaults.CpuAlertCores, defaults.CpuAlertSeconds));
        Assert.Equal(0, off.CpuAlertCores);
    }

    [Fact]
    public void While_learning_the_highest_load_is_noted_and_shown()
    {
        var profile = new ClientProfile { Name = "Test", ClientPath = TestData.Client, Learning = true };
        var learner = new Learner(new GuardConfig { Profiles = [profile] }, []);

        Assert.True(learner.NoteCpu("test", 1.2345));
        Assert.False(learner.NoteCpu("Test", 1.1));       // lower: nothing new
        Assert.False(learner.NoteCpu("Test", 1.2349));    // the same to two decimals
        Assert.False(learner.NoteCpu("Other", 9));        // not a learning profile
        Assert.True(learner.NoteCpu("Test", 1.5));

        var learned = Assert.Single(learner.Profiles);
        Assert.Equal(1.5, learned.PeakCpuCores);
        Assert.Contains("Highest processor load: 1.5 cores on average (R8 reports above 2.0: cpuAlertCores)", LearnedReport.Render(learned, profile, 2.0));
        Assert.Contains("Highest processor load: 1.5 cores on average (R8 is off)", LearnedReport.Render(learned, profile));
        Assert.Contains("Highest processor load: not measured", LearnedReport.Render(new LearnedProfile { Profile = "Test" }, profile, 2.0));
    }
}
