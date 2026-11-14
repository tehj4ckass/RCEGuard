using System.Net;
using System.Net.Sockets;
using RCEGuard.Core.Configuration;

namespace RCEGuard.Service;

/// <summary>
/// The addresses the allowed host names of the profiles resolve to. A host name that cannot be
/// resolved right now keeps the addresses it had: a short failure of name resolution must not
/// turn a known server into an unknown one (and, with the firewall on, cut the client off).
/// </summary>
internal sealed class HostAddressBook
{
    private readonly GuardConfig config;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> resolve;
    private readonly Dictionary<(string Profile, string Host), IPAddress[]> known = [];

    /// <summary>Creates the book. <paramref name="resolve"/> replaces the name resolution of Windows in tests.</summary>
    public HostAddressBook(GuardConfig config, Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null)
    {
        this.config = config;
        this.resolve = resolve ?? Dns.GetHostAddressesAsync;
    }

    /// <summary>Per profile name, the addresses of its host names as far as they are known.</summary>
    public IReadOnlyDictionary<string, IReadOnlyCollection<IPAddress>> ByProfile { get; private set; } =
        new Dictionary<string, IReadOnlyCollection<IPAddress>>();

    /// <summary>Resolves all host names again. Returns one line for every host name that could not be resolved.</summary>
    public async Task<IReadOnlyList<string>> RefreshAsync(CancellationToken cancellationToken)
    {
        var problems = new List<string>();
        var byProfile = new Dictionary<string, IReadOnlyCollection<IPAddress>>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in config.Profiles.Where(p => p.AllowedHostnames.Count > 0))
        {
            var addresses = new List<IPAddress>();
            foreach (var host in profile.AllowedHostnames)
            {
                try
                {
                    known[(profile.Name, host)] = await resolve(host, cancellationToken);
                }
                catch (Exception ex) when (ex is SocketException or ArgumentException)
                {
                    var kept = known.TryGetValue((profile.Name, host), out var before) ? before.Length : 0;
                    problems.Add(
                        $"Host name '{host}' of profile '{profile.Name}' could not be resolved: {ex.Message} " +
                        (kept > 0 ? $"Keeping the {kept} address(es) it had." : "No address is known for it."));
                }

                if (known.TryGetValue((profile.Name, host), out var current))
                {
                    addresses.AddRange(current);
                }
            }

            byProfile[profile.Name] = addresses;
        }

        ByProfile = byProfile;
        return problems;
    }
}
