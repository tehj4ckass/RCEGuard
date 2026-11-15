using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using RCEGuard.Core.Rules;

namespace RCEGuard.Service;

/// <summary>One row of the TCP connection table of Windows.</summary>
/// <param name="ProcessId">Pid of the process that owns the socket.</param>
/// <param name="Listening">True for a socket that waits for connections; it has no remote end.</param>
/// <param name="LocalPort">The local port.</param>
/// <param name="RemoteAddress">The remote address.</param>
/// <param name="RemotePort">The remote port.</param>
public readonly record struct TcpConnection(int ProcessId, bool Listening, int LocalPort, IPAddress RemoteAddress, int RemotePort);

/// <summary>
/// Reads the TCP connection table of Windows with the owning process of every connection
/// (GetExtendedTcpTable, what "netstat -o" shows). No process is opened for it: the guard gets no
/// handle to the game client and reads nothing from it.
/// </summary>
public static class TcpConnections
{
    private const int AddressFamilyV4 = 2;
    private const int AddressFamilyV6 = 23;
    private const int TableOwnerPidAll = 5;
    private const int ErrorInsufficientBuffer = 122;
    private const int StateListen = 2;

    /// <summary>Returns all TCP sockets of the machine, IPv4 and IPv6.</summary>
    public static IReadOnlyList<TcpConnection> Take()
    {
        var result = new List<TcpConnection>(256);
        Read(AddressFamilyV4, result);
        Read(AddressFamilyV6, result);
        return result;
    }

    /// <summary>
    /// The remote ends of the connections a process made itself: not its listening sockets, not
    /// connections it accepted on a port it listens on, not connections to this machine.
    /// </summary>
    public static IReadOnlyList<RemoteEndpoint> OutboundOf(int processId, IReadOnlyList<TcpConnection> table)
    {
        HashSet<int>? listening = null;
        foreach (var row in table)
        {
            if (row.ProcessId == processId && row.Listening)
            {
                (listening ??= []).Add(row.LocalPort);
            }
        }

        var result = new List<RemoteEndpoint>();
        foreach (var row in table)
        {
            if (row.ProcessId != processId || row.Listening || row.RemotePort == 0 || listening?.Contains(row.LocalPort) == true)
            {
                continue;
            }

            var address = RemoteAllowlist.Normalize(row.RemoteAddress);
            if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            {
                continue;
            }

            result.Add(new RemoteEndpoint(address, row.RemotePort));
        }

        return result;
    }

    private static void Read(int family, List<TcpConnection> result)
    {
        var size = 0;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            var buffer = size == 0 ? IntPtr.Zero : Marshal.AllocHGlobal(size);
            try
            {
                var error = GetExtendedTcpTable(buffer, ref size, sort: false, family, TableOwnerPidAll, 0);
                if (error == ErrorInsufficientBuffer)
                {
                    size += 4096; // the table grows between two calls
                    continue;
                }

                if (error != 0)
                {
                    throw new Win32Exception(error, $"The connection table could not be read (error {error}).");
                }

                Parse(buffer, size, family, result);
                return;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        throw new Win32Exception("The connection table could not be read: it kept growing.");
    }

    private static void Parse(IntPtr buffer, int size, int family, List<TcpConnection> result)
    {
        // MIB_TCPTABLE_OWNER_PID / MIB_TCP6TABLE_OWNER_PID: a count, then the rows.
        var rowSize = family == AddressFamilyV4 ? 24 : 56;
        if (buffer == IntPtr.Zero || size < 4)
        {
            return;
        }

        var count = Marshal.ReadInt32(buffer);
        for (var i = 0; i < count; i++)
        {
            var offset = 4 + (i * rowSize);
            if (offset + rowSize > size)
            {
                break;
            }

            var row = buffer + offset;
            if (family == AddressFamilyV4)
            {
                // dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid
                var address = new byte[4];
                Marshal.Copy(row + 12, address, 0, 4);
                result.Add(new TcpConnection(
                    Marshal.ReadInt32(row, 20),
                    Marshal.ReadInt32(row, 0) == StateListen,
                    Port(Marshal.ReadInt32(row, 8)),
                    new IPAddress(address),
                    Port(Marshal.ReadInt32(row, 16))));
            }
            else
            {
                // ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid
                var address = new byte[16];
                Marshal.Copy(row + 24, address, 0, 16);
                result.Add(new TcpConnection(
                    Marshal.ReadInt32(row, 52),
                    Marshal.ReadInt32(row, 48) == StateListen,
                    Port(Marshal.ReadInt32(row, 20)),
                    new IPAddress(address),
                    Port(Marshal.ReadInt32(row, 44))));
            }
        }
    }

    /// <summary>The table holds ports in network byte order in the low 16 bits.</summary>
    private static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    [DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern int GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sort, int addressFamily, int tableClass, int reserved);
}
