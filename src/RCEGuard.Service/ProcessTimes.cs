using System.ComponentModel;
using System.Runtime.InteropServices;

namespace RCEGuard.Service;

/// <summary>One running process as Windows accounts for it.</summary>
/// <param name="ProcessId">Its pid.</param>
/// <param name="Name">Its file name, without the path.</param>
/// <param name="Created">When it was started.</param>
/// <param name="Cpu">Processor time it has used since then (user and kernel).</param>
public readonly record struct ProcessTime(int ProcessId, string Name, DateTimeOffset Created, TimeSpan Cpu);

/// <summary>
/// Reads the processor time of every running process from the process list of the operating
/// system (NtQuerySystemInformation, the list Task Manager shows). No process is opened for it:
/// the guard gets no handle to the game client and reads nothing from it.
/// </summary>
public static class ProcessTimes
{
    private const int SystemProcessInformation = 5;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    // SYSTEM_PROCESS_INFORMATION on 64-bit Windows.
    private const int OffsetCreateTime = 32;
    private const int OffsetUserTime = 40;
    private const int OffsetKernelTime = 48;
    private const int OffsetNameLength = 56;
    private const int OffsetNameBuffer = 64;
    private const int OffsetProcessId = 80;
    private const int MinimumEntrySize = 96;

    /// <summary>Returns the running processes by pid.</summary>
    public static IReadOnlyDictionary<int, ProcessTime> Take()
    {
        if (!Environment.Is64BitProcess)
        {
            throw new PlatformNotSupportedException("The process list is read with the layout of 64-bit Windows.");
        }

        var size = 1 << 20;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = NtQuerySystemInformation(SystemProcessInformation, buffer, (uint)size, out var needed);
                if (status == StatusInfoLengthMismatch)
                {
                    // The list grew between two calls: ask again with room to spare.
                    size = Math.Max(size * 2, (int)needed + 65536);
                    continue;
                }

                if (status != 0)
                {
                    throw new Win32Exception($"The process list could not be read (NTSTATUS 0x{status:X8}).");
                }

                return Parse(buffer, size);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new Win32Exception("The process list could not be read: it kept growing.");
    }

    private static Dictionary<int, ProcessTime> Parse(IntPtr buffer, int size)
    {
        var result = new Dictionary<int, ProcessTime>(256);
        var offset = 0;
        while (offset >= 0 && offset + MinimumEntrySize <= size)
        {
            var entry = buffer + offset;
            var processId = (int)Marshal.ReadIntPtr(entry, OffsetProcessId).ToInt64();
            var nameLength = (ushort)Marshal.ReadInt16(entry, OffsetNameLength);
            var namePointer = Marshal.ReadIntPtr(entry, OffsetNameBuffer);
            var name = namePointer == IntPtr.Zero || nameLength == 0 ? string.Empty : Marshal.PtrToStringUni(namePointer, nameLength / 2);
            var created = Marshal.ReadInt64(entry, OffsetCreateTime);
            var cpu = Marshal.ReadInt64(entry, OffsetUserTime) + Marshal.ReadInt64(entry, OffsetKernelTime);
            result[processId] = new ProcessTime(
                processId,
                name,
                created > 0 ? DateTimeOffset.FromFileTime(created).ToUniversalTime() : DateTimeOffset.MinValue,
                TimeSpan.FromTicks(Math.Max(0, cpu)));

            var next = Marshal.ReadInt32(entry, 0);
            if (next <= 0)
            {
                break;
            }

            offset += next;
        }

        return result;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass, IntPtr buffer, uint length, out uint returnLength);
}
