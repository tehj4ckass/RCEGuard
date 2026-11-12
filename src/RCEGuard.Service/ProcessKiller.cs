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

    /// <summary>Terminates one target and, if requested, everything it started.</summary>
    public KillResult Kill(KillTarget target)
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
