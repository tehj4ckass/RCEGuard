using System.Net;

namespace RCEGuard.Core.Rules;

/// <summary>The far end of a connection.</summary>
/// <param name="Address">The remote address.</param>
/// <param name="Port">The remote port.</param>
public readonly record struct RemoteEndpoint(IPAddress Address, int Port);

/// <summary>
/// Fills the gaps of the sensor: Sysmon does not record every connection of a client (measured on
/// 2026-11-15: 24 of 34), so the service also looks at the connection table of Windows. This class
/// decides which connections seen there are news: one the sensor has reported is not, and neither
/// is one that has only just appeared, because the sensor writes its event up to three seconds
/// late. A connection that is still open after the grace time and was never reported by the
/// sensor is handed out, once. Shorter connections are left to the sensor.
/// It keeps no clock of its own, so it can be tested. Not thread-safe.
/// </summary>
public sealed class ConnectionWatch
{
    /// <summary>Upper limit of endpoints remembered per process; beyond it nothing new is taken.</summary>
    public const int MaxEndpointsPerProcess = 4096;

    private readonly TimeSpan grace;
    private readonly Dictionary<string, State> processes = new(StringComparer.Ordinal);

    /// <summary>Creates the watch.</summary>
    /// <param name="grace">How long a connection must have been seen open before it counts as missed by the sensor.</param>
    public ConnectionWatch(TimeSpan grace) => this.grace = grace;

    /// <summary>Notes that the sensor reported a connection of a process: the table has nothing to add for it.</summary>
    /// <param name="key">Identifies the process (not just its pid: pids are reused).</param>
    /// <param name="address">The remote address.</param>
    /// <param name="port">The remote port.</param>
    public void SeenBySensor(string key, IPAddress address, int port)
    {
        var state = For(key);
        var endpoint = new RemoteEndpoint(RemoteAllowlist.Normalize(address), port);
        state.Pending.Remove(endpoint);
        if (state.Known.Count < MaxEndpointsPerProcess)
        {
            state.Known.Add(endpoint);
        }
    }

    /// <summary>
    /// Takes what the connection table shows for a process now. Returns the connections that have
    /// been open for the grace time without a report of the sensor; each is returned once.
    /// </summary>
    /// <param name="key">Identifies the process.</param>
    /// <param name="now">Time of the look.</param>
    /// <param name="open">The remote ends of the connections the process has open.</param>
    public IReadOnlyList<RemoteEndpoint> Poll(string key, DateTimeOffset now, IEnumerable<RemoteEndpoint> open)
    {
        var state = For(key);
        var current = new HashSet<RemoteEndpoint>();
        foreach (var raw in open)
        {
            current.Add(new RemoteEndpoint(RemoteAllowlist.Normalize(raw.Address), raw.Port));
        }

        // A connection that is gone again before the grace time was too short for the table: forget it.
        foreach (var gone in state.Pending.Keys.Where(endpoint => !current.Contains(endpoint)).ToList())
        {
            state.Pending.Remove(gone);
        }

        List<RemoteEndpoint>? missed = null;
        foreach (var endpoint in current)
        {
            if (state.Known.Contains(endpoint))
            {
                continue;
            }

            if (!state.Pending.TryGetValue(endpoint, out var since))
            {
                if (state.Pending.Count + state.Known.Count < MaxEndpointsPerProcess)
                {
                    state.Pending[endpoint] = now;
                }

                continue;
            }

            if (now - since >= grace)
            {
                state.Pending.Remove(endpoint);
                state.Known.Add(endpoint);
                (missed ??= []).Add(endpoint);
            }
        }

        return missed ?? (IReadOnlyList<RemoteEndpoint>)[];
    }

    /// <summary>Forgets a process that has ended.</summary>
    public void Forget(string key) => processes.Remove(key);

    private State For(string key)
    {
        if (!processes.TryGetValue(key, out var state))
        {
            state = new State();
            processes[key] = state;
        }

        return state;
    }

    private sealed class State
    {
        public HashSet<RemoteEndpoint> Known { get; } = [];

        public Dictionary<RemoteEndpoint, DateTimeOffset> Pending { get; } = [];
    }
}
