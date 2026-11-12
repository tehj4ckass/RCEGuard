using System.Diagnostics;
using RCEGuard.Core.Rules;

namespace RCEGuard.Service.Tests;

/// <summary>
/// The killer against real processes. Every test starts its own cmd.exe / ping.exe (ping to this
/// machine, as a harmless way to wait) and removes whatever is still running at the end.
/// </summary>
public sealed class ProcessKillerTests : IDisposable
{
    private static readonly string Cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
    private readonly List<int> startedParents = [];

    public void Dispose()
    {
        // Nothing a test started may outlive it.
        foreach (var parent in startedParents)
        {
            foreach (var child in ChildrenOf(parent))
            {
                TryKillTree(child.ProcessId);
            }

            TryKillTree(parent);
        }
    }

    /// <summary>A child that starts a waiting program and exits: the program is left without a living parent.</summary>
    private (int ParentPid, DateTimeOffset ParentStarted, int LeftBehindPid) StartAndLeaveBehind()
    {
        using var parent = Start("/c start \"\" /b cmd.exe /c \"ping -n 40 127.0.0.1 > nul\"");
        var started = new DateTimeOffset(parent.StartTime);
        Assert.True(parent.WaitForExit(10_000), "the parent did not exit");

        // Windows also leaves the console host of the exited parent behind; the test follows the program.
        var leftBehind = WaitFor(() => ChildrenOf(parent.Id).Where(p => Named(p, "cmd.exe")).Select(p => (int?)p.ProcessId).FirstOrDefault());
        Assert.True(leftBehind.HasValue, "no program was left behind");
        return (parent.Id, started, leftBehind!.Value);
    }

    private static bool Named(ProcessEntry entry, string name) => entry.Name.Equals(name, StringComparison.OrdinalIgnoreCase);

    private Process Start(string arguments)
    {
        var process = Process.Start(new ProcessStartInfo(Cmd, arguments) { UseShellExecute = false, CreateNoWindow = true })!;
        startedParents.Add(process.Id);
        return process;
    }

    private static List<ProcessEntry> ChildrenOf(int pid) =>
        [.. ProcessSnapshot.Take().Where(p => p.ParentProcessId == pid)];

    private static bool IsRunning(int pid) => ProcessSnapshot.Take().Any(p => p.ProcessId == pid);

    private static T? WaitFor<T>(Func<T?> probe, int milliseconds = 5000)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            var value = probe();
            if (!EqualityComparer<T?>.Default.Equals(value, default) || watch.ElapsedMilliseconds > milliseconds)
            {
                return value;
            }

            Thread.Sleep(50);
        }
    }

    private static bool WaitUntilGone(int pid) => WaitFor(() => IsRunning(pid) ? (bool?)null : true) == true;

    private static void TryKillTree(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Already gone.
        }
    }

    [Fact]
    public void Snapshot_lists_this_process_with_its_parent()
    {
        var me = Assert.Single(ProcessSnapshot.Take(), p => p.ProcessId == Environment.ProcessId);

        Assert.True(me.ParentProcessId > 0);
        Assert.EndsWith(".exe", me.Name, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_program_left_behind_by_an_exited_target_is_terminated_with_its_own_children()
    {
        var (parentPid, parentStarted, leftBehind) = StartAndLeaveBehind();
        var ping = WaitFor(() => ChildrenOf(leftBehind).Where(p => Named(p, "PING.EXE")).Select(p => (int?)p.ProcessId).FirstOrDefault());
        Assert.True(ping.HasValue, "the left-behind program has no child");

        var result = new ProcessKiller(dryRun: false).Kill(new KillTarget(parentPid, Cmd, IncludeDescendants: true, StartedAt: parentStarted));

        Assert.Equal(KillOutcome.AlreadyExited, result.Outcome);
        Assert.Contains("left behind", result.Message);
        Assert.Contains("terminated", result.Message);
        Assert.True(WaitUntilGone(leftBehind), "the left-behind program is still running");
        Assert.True(WaitUntilGone(ping!.Value), "the child of the left-behind program is still running");
    }

    [Fact]
    public void Without_a_start_time_nothing_is_searched()
    {
        var (parentPid, _, leftBehind) = StartAndLeaveBehind();

        var result = new ProcessKiller(dryRun: false).Kill(new KillTarget(parentPid, Cmd, IncludeDescendants: true));

        Assert.Equal(KillOutcome.AlreadyExited, result.Outcome);
        Assert.Equal("already exited", result.Message);
        Assert.True(IsRunning(leftBehind));
    }

    [Fact]
    public void Without_descendants_nothing_is_searched()
    {
        var (parentPid, parentStarted, leftBehind) = StartAndLeaveBehind();

        var result = new ProcessKiller(dryRun: false).Kill(new KillTarget(parentPid, Cmd, IncludeDescendants: false, StartedAt: parentStarted));

        Assert.Equal("already exited", result.Message);
        Assert.True(IsRunning(leftBehind));
    }

    [Fact]
    public void A_program_older_than_the_target_is_not_its_child_and_is_left_alone()
    {
        // The pid of the target once belonged to another process: its children are older than the target.
        var (parentPid, _, leftBehind) = StartAndLeaveBehind();
        var targetStartedLater = DateTimeOffset.Now.AddSeconds(5);

        var result = new ProcessKiller(dryRun: false).Kill(new KillTarget(parentPid, Cmd, IncludeDescendants: true, StartedAt: targetStartedLater));

        Assert.Equal("already exited", result.Message);
        Assert.True(IsRunning(leftBehind));
    }

    [Fact]
    public void A_dry_run_reports_the_left_behind_program_and_terminates_nothing()
    {
        var (parentPid, parentStarted, leftBehind) = StartAndLeaveBehind();

        var result = new ProcessKiller(dryRun: true).Kill(new KillTarget(parentPid, Cmd, IncludeDescendants: true, StartedAt: parentStarted));

        Assert.Equal(KillOutcome.AlreadyExited, result.Outcome);
        Assert.Contains($"cmd.exe ({leftBehind}) would be terminated (dry run)", result.Message);
        Assert.True(IsRunning(leftBehind));
    }

    [Fact]
    public void A_running_target_is_terminated_with_its_tree()
    {
        using var target = Start("/c ping -n 40 127.0.0.1 > nul");
        var started = new DateTimeOffset(target.StartTime);
        var ping = WaitFor(() => ChildrenOf(target.Id).Where(p => Named(p, "PING.EXE")).Select(p => (int?)p.ProcessId).FirstOrDefault());
        Assert.True(ping.HasValue, "ping did not start");

        var result = new ProcessKiller(dryRun: false).Kill(new KillTarget(target.Id, Cmd, IncludeDescendants: true, StartedAt: started));

        Assert.Equal(KillOutcome.Terminated, result.Outcome);
        Assert.True(WaitUntilGone(target.Id));
        Assert.True(WaitUntilGone(ping!.Value));
    }

    [Fact]
    public void A_process_started_after_the_event_is_another_process_and_is_left_alone()
    {
        // An old event read after a restart of the guard: the pid runs the same program again, in a new process.
        using var later = Start("/c ping -n 40 127.0.0.1 > nul");
        var eventTime = new DateTimeOffset(later.StartTime).AddMinutes(-1);

        var result = new ProcessKiller(dryRun: false).Kill(new KillTarget(later.Id, Cmd, IncludeDescendants: true), eventTime);

        Assert.Equal(KillOutcome.PidReused, result.Outcome);
        Assert.Contains("started after the event", result.Message);
        Assert.True(IsRunning(later.Id));
    }

    [Fact]
    public void A_process_started_before_the_event_is_terminated()
    {
        using var target = Start("/c ping -n 40 127.0.0.1 > nul");

        var result = new ProcessKiller(dryRun: false).Kill(new KillTarget(target.Id, Cmd, IncludeDescendants: true), eventTime: DateTimeOffset.UtcNow);

        Assert.Equal(KillOutcome.Terminated, result.Outcome);
        Assert.True(WaitUntilGone(target.Id));
    }

    [Fact]
    public void After_a_recent_event_the_left_behind_program_is_terminated()
    {
        var (parentPid, parentStarted, leftBehind) = StartAndLeaveBehind();

        var result = new ProcessKiller(dryRun: false).Kill(
            new KillTarget(parentPid, Cmd, IncludeDescendants: true, StartedAt: parentStarted), eventTime: DateTimeOffset.UtcNow);

        Assert.Contains("left behind", result.Message);
        Assert.True(WaitUntilGone(leftBehind), "the left-behind program is still running");
    }

    [Fact]
    public void After_an_old_event_left_behind_programs_are_not_searched()
    {
        // The pid of the exited child may have had other owners since; their children must not be mistaken for its own.
        var (parentPid, parentStarted, leftBehind) = StartAndLeaveBehind();
        var old = DateTimeOffset.UtcNow - ProcessKiller.LeftBehindSearchMaxAge - TimeSpan.FromSeconds(5);

        var result = new ProcessKiller(dryRun: false).Kill(
            new KillTarget(parentPid, Cmd, IncludeDescendants: true, StartedAt: parentStarted), eventTime: old);

        Assert.Equal(KillOutcome.AlreadyExited, result.Outcome);
        Assert.Contains("not searched", result.Message);
        Assert.True(IsRunning(leftBehind));
    }

    [Fact]
    public void A_pid_that_runs_another_program_is_left_alone_and_so_are_its_children()
    {
        // The event named another image for this pid: the pid was reused. What the new owner
        // started after its own start belongs to the new owner.
        using var owner = Start("/c ping -n 40 127.0.0.1 > nul");
        var ping = WaitFor(() => ChildrenOf(owner.Id).Where(p => Named(p, "PING.EXE")).Select(p => (int?)p.ProcessId).FirstOrDefault());
        Assert.True(ping.HasValue, "ping did not start");
        var longAgo = DateTimeOffset.Now.AddHours(-1);

        var result = new ProcessKiller(dryRun: false).Kill(
            new KillTarget(owner.Id, @"C:\Somewhere\Else\payload.exe", IncludeDescendants: true, StartedAt: longAgo));

        Assert.Equal(KillOutcome.ImageMismatch, result.Outcome);
        Assert.DoesNotContain("left behind", result.Message);
        Assert.True(IsRunning(owner.Id));
        Assert.True(IsRunning(ping!.Value));
    }
}
