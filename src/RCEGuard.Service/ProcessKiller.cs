using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using RCEGuard.Core.Rules;

namespace RCEGuard.Service;

/// <summary>Outcome of one termination attempt.</summary>
public enum KillOutcome
{
    /// <summary>The process was terminated.</summary>
    Terminated,

    /// <summary>The process had already exited.</summary>
    AlreadyExited,

    /// <summary>The pid now belongs to a different program; nothing was touched.</summary>
    ImageMismatch,

    /// <summary>Dry run: the process would have been terminated.</summary>
    DryRun,

    /// <summary>Terminating failed, see the message.</summary>
    Failed,
}

/// <summary>Result of one termination attempt.</summary>
public sealed record KillResult(KillTarget Target, KillOutcome Outcome, string Message)
{
    /// <summary>Short text for logs, e.g. "cmd.exe (33884): already exited".</summary>
    public override string ToString() =>
        $"{Path.GetFileName(Target.Image)} ({Target.ProcessId}): {Message}";
}

/// <summary>
/// Terminates processes named by findings. A process is only terminated if its pid still runs the
/// image the event named. The image is read with QueryFullProcessImageName on a limited-information
/// handle: the address space of the process is never opened for reading.
/// </summary>
public sealed class ProcessKiller
{
    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int ErrorInvalidParameter = 87;

    private readonly bool dryRun;

    /// <summary>Creates a killer; with <paramref name="dryRun"/> nothing is terminated.</summary>
    public ProcessKiller(bool dryRun) => this.dryRun = dryRun;

    /// <summary>
    /// Terminates one target and, if requested, everything it started. If the target has already
    /// exited (or its pid belongs to another program by now) and its start time is known, the
    /// programs it left behind are terminated as well.
    /// </summary>
    public KillResult Kill(KillTarget target)
    {
        var result = KillProcess(target);
        if (!target.IncludeDescendants || target.StartedAt is not { } startedAt
            || result.Outcome is not (KillOutcome.AlreadyExited or KillOutcome.ImageMismatch))
        {
            return result;
        }

        // A running target was terminated together with its tree. Only a target that is gone can
        // have left something behind that no longer hangs below a running process.
        DateTimeOffset? reusedSince = null;
        if (result.Outcome == KillOutcome.ImageMismatch)
        {
            reusedSince = StartTimeOf(target.ProcessId);
            if (reusedSince is null)
            {
                return result; // Cannot tell the children of the old process from those of the new one.
            }
        }

        var leftBehind = KillLeftBehind(target.ProcessId, startedAt, reusedSince);
        return leftBehind.Count == 0
            ? result
            : result with { Message = $"{result.Message}, left behind: {string.Join(", ", leftBehind)}" };
    }

    /// <summary>
    /// Terminates the running programs a process that is gone left behind: their parent pid is the
    /// pid of that process and they were started after it. If the pid has been reused since, programs
    /// started after the new owner are its children and are left alone.
    /// </summary>
    private List<string> KillLeftBehind(int parentPid, DateTimeOffset parentStartedAt, DateTimeOffset? reusedSince)
    {
        var report = new List<string>();
        IReadOnlyList<ProcessEntry> snapshot;
        try
        {
            snapshot = ProcessSnapshot.Take();
        }
        catch (Win32Exception ex)
        {
            report.Add($"process list could not be read: {ex.Message}");
            return report;
        }

        foreach (var entry in snapshot)
        {
            if (entry.ParentProcessId != parentPid || entry.ProcessId <= 4 || entry.ProcessId == Environment.ProcessId)
            {
                continue;
            }

            var label = $"{entry.Name} ({entry.ProcessId})";
            try
            {
                // The Process object holds a handle from here on, so the pid cannot change owners in between.
                using var process = Process.GetProcessById(entry.ProcessId);
                var started = new DateTimeOffset(process.StartTime);
                if (started < parentStartedAt || (reusedSince is { } reused && started >= reused))
                {
                    continue; // Not a child of the process the finding is about.
                }

                if (process.HasExited)
                {
                    continue;
                }

                if (dryRun)
                {
                    report.Add($"{label} would be terminated (dry run)");
                    continue;
                }

                process.Kill(entireProcessTree: true);
                report.Add($"{label} terminated");
            }
            catch (ArgumentException)
            {
                // Exited in the meantime.
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or AggregateException)
            {
                report.Add($"{label} could not be terminated: {ex.Message}");
            }
        }

        return report;
    }

    private static DateTimeOffset? StartTimeOf(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return new DateTimeOffset(process.StartTime);
        }
        catch (Exception ex) when (ex is ArgumentException or Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }

    private KillResult KillProcess(KillTarget target)
    {
        if (target.ProcessId <= 4 || target.ProcessId == Environment.ProcessId)
        {
            return new KillResult(target, KillOutcome.Failed, "refused: system process or the guard itself");
        }

        // While this handle is open Windows cannot reuse the pid, so everything below is about the same process.
        using var handle = OpenProcess(ProcessQueryLimitedInformation | ProcessTerminate, false, target.ProcessId);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            return error == ErrorInvalidParameter
                ? new KillResult(target, KillOutcome.AlreadyExited, "already exited")
                : new KillResult(target, KillOutcome.Failed, $"could not be opened: {new Win32Exception(error).Message}");
        }

        if (GetExitCodeProcess(handle, out var exitCode) && exitCode != StillActive)
        {
            return new KillResult(target, KillOutcome.AlreadyExited, "already exited");
        }

        var image = QueryImage(handle);
        if (image is null || !string.Equals(image, target.Image, StringComparison.OrdinalIgnoreCase))
        {
            return new KillResult(target, KillOutcome.ImageMismatch, $"pid now runs '{image ?? "unknown"}', left alone");
        }

        if (dryRun)
        {
            return new KillResult(target, KillOutcome.DryRun, "would be terminated (dry run)");
        }

        try
        {
            if (target.IncludeDescendants)
            {
                using var process = Process.GetProcessById(target.ProcessId);
                process.Kill(entireProcessTree: true);
            }
            else if (!TerminateProcess(handle, 1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new KillResult(target, KillOutcome.Terminated, "terminated");
        }
        catch (ArgumentException)
        {
            return new KillResult(target, KillOutcome.AlreadyExited, "already exited");
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or AggregateException)
        {
            return new KillResult(target, KillOutcome.Failed, $"could not be terminated: {ex.Message}");
        }
    }

    private const uint StillActive = 259;

    private static string? QueryImage(SafeProcessHandle handle)
    {
        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        return QueryFullProcessImageName(handle, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, [Out] char[] exeName, ref uint size);
}
