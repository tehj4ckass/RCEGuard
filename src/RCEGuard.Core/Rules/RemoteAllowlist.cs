using System.Net;
using System.Net.Sockets;

namespace RCEGuard.Core.Rules;

/// <summary>A set of allowed remote addresses: single IPs and CIDR ranges, IPv4 and IPv6.</summary>
public sealed class RemoteAllowlist
{
    private readonly List<IpRange> ranges = [];

    /// <summary>Creates an allowlist from entries like "203.0.113.7" or "203.0.113.0/24". Invalid entries throw.</summary>
    public RemoteAllowlist(IEnumerable<string> entries)
    {
        foreach (var entry in entries)
        {
            if (!TryParseRange(entry, out var range))
            {
                throw new FormatException($"'{entry}' is not an IP address or CIDR range.");
            }

            ranges.Add(range);
        }
    }

    /// <summary>True if the address is inside one of the ranges.</summary>
    public bool Contains(IPAddress address)
    {
        var normalized = Normalize(address);
        foreach (var range in ranges)
        {
            if (range.Contains(normalized))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Parses "ip" or "ip/prefix".</summary>
    public static bool TryParseRange(string? text, out IpRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var parts = text.Trim().Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address))
        {
            return false;
        }

        address = Normalize(address);
        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maxPrefix;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > maxPrefix))
        {
            return false;
        }

        range = new IpRange(address, prefix);
        return true;
    }

    /// <summary>Treats IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) as IPv4.</summary>
    internal static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}

/// <summary>An address with a prefix length.</summary>
public readonly record struct IpRange(IPAddress Network, int PrefixLength)
{
    /// <summary>True if the address has the same family and the same leading bits.</summary>
    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != Network.AddressFamily)
        {
            return false;
        }

        var network = Network.GetAddressBytes();
        var candidate = address.GetAddressBytes();
        var fullBytes = PrefixLength / 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (network[i] != candidate[i])
            {
                return false;
            }
        }

        var remainingBits = PrefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (network[fullBytes] & mask) == (candidate[fullBytes] & mask);
    }
}
