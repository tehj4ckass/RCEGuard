using System.Net;
using System.Net.Sockets;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Prevention;

/// <summary>A run of addresses of one family, both ends included.</summary>
/// <param name="First">Lowest address of the run.</param>
/// <param name="Last">Highest address of the run.</param>
public readonly record struct AddressSpan(IPAddress First, IPAddress Last)
{
    /// <summary>
    /// "first-last", the form Windows Firewall takes for IPv4 and IPv6 and returns unchanged,
    /// also for a single address.
    /// </summary>
    public override string ToString() => $"{First}-{Last}";
}

/// <summary>
/// Turns a list of allowed addresses into the list of everything else. Windows Firewall has no
/// "allow only these": a block rule wins over every allow rule, and what no rule blocks is allowed
/// by default. So the block rule for a client names all addresses except the allowed ones.
/// </summary>
public static class AddressBlocks
{
    /// <summary>
    /// Loopback is never blocked: the rule engine allows it too (R2), and local helpers of the
    /// client are not what this is about.
    /// </summary>
    private static readonly IpRange[] AlwaysAllowed =
    [
        new(IPAddress.Parse("127.0.0.0"), 8),
        new(IPAddress.IPv6Loopback, 128),
    ];

    /// <summary>
    /// All addresses of one family that are in none of the allowed ranges, as few runs as possible,
    /// in ascending order. Ranges of the other family are ignored.
    /// </summary>
    /// <param name="allowed">The allowed ranges.</param>
    /// <param name="family">IPv4 (<see cref="AddressFamily.InterNetwork"/>) or IPv6.</param>
    public static IReadOnlyList<AddressSpan> Outside(IEnumerable<IpRange> allowed, AddressFamily family)
    {
        var bits = family switch
        {
            AddressFamily.InterNetwork => 32,
            AddressFamily.InterNetworkV6 => 128,
            _ => throw new ArgumentOutOfRangeException(nameof(family), family, "Only IPv4 and IPv6."),
        };
        var highest = bits == 128 ? UInt128.MaxValue : (UInt128.One << bits) - 1;

        var open = allowed.Concat(AlwaysAllowed)
            .Where(range => range.Network.AddressFamily == family)
            .Select(range => Bounds(range, bits))
            .OrderBy(bounds => bounds.First)
            .ToList();

        var result = new List<AddressSpan>();
        var next = UInt128.Zero;   // lowest address not yet decided
        foreach (var (first, last) in open)
        {
            if (first > next)
            {
                result.Add(Span(next, first - 1, bits));
            }

            if (last == highest)
            {
                return result;   // nothing above it
            }

            if (last + 1 > next)
            {
                next = last + 1;
            }
        }

        result.Add(Span(next, highest, bits));
        return result;
    }

    private static (UInt128 First, UInt128 Last) Bounds(IpRange range, int bits)
    {
        var hostBits = bits - range.PrefixLength;
        var hostMask = hostBits switch
        {
            0 => UInt128.Zero,
            128 => UInt128.MaxValue,
            _ => (UInt128.One << hostBits) - 1,
        };
        var first = ToNumber(range.Network) & ~hostMask;
        return (first, first | hostMask);
    }

    private static UInt128 ToNumber(IPAddress address)
    {
        var value = UInt128.Zero;
        foreach (var part in address.GetAddressBytes())
        {
            value = (value << 8) | part;
        }

        return value;
    }

    private static AddressSpan Span(UInt128 first, UInt128 last, int bits) => new(ToAddress(first, bits), ToAddress(last, bits));

    private static IPAddress ToAddress(UInt128 value, int bits)
    {
        var bytes = new byte[bits / 8];
        for (var i = bytes.Length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return new IPAddress(bytes);
    }
}
