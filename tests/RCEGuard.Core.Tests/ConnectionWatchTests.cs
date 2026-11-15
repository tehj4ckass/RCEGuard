using System.Net;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Tests;

/// <summary>Which connections seen in the connection table of Windows are news the sensor did not bring.</summary>
public class ConnectionWatchTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly RemoteEndpoint Server = new(IPAddress.Parse("203.0.113.9"), 3724);
    private static readonly RemoteEndpoint Other = new(IPAddress.Parse("198.51.100.7"), 443);

    private static ConnectionWatch Watch() => new(TimeSpan.FromSeconds(5));

    [Fact]
    public void A_connection_is_handed_out_once_when_it_has_been_open_for_the_grace_time()
    {
        var watch = Watch();

        Assert.Empty(watch.Poll("p", Start, [Server]));
        Assert.Empty(watch.Poll("p", Start.AddSeconds(2), [Server]));
        Assert.Empty(watch.Poll("p", Start.AddSeconds(4.9), [Server]));
        Assert.Equal([Server], watch.Poll("p", Start.AddSeconds(5), [Server]));
        Assert.Empty(watch.Poll("p", Start.AddSeconds(7), [Server]));
        Assert.Empty(watch.Poll("p", Start.AddSeconds(600), [Server]));
    }

    [Fact]
    public void A_connection_the_sensor_reported_is_never_handed_out()
    {
        var before = Watch();
        before.SeenBySensor("p", Server.Address, Server.Port);
        Assert.Empty(before.Poll("p", Start, [Server]));
        Assert.Empty(before.Poll("p", Start.AddSeconds(60), [Server]));

        // The usual order: the table shows it first, the event of the sensor comes two seconds later.
        var after = Watch();
        Assert.Empty(after.Poll("p", Start, [Server]));
        after.SeenBySensor("p", Server.Address, Server.Port);
        Assert.Empty(after.Poll("p", Start.AddSeconds(6), [Server]));
    }

    [Fact]
    public void A_connection_that_is_gone_before_the_grace_time_is_forgotten()
    {
        var watch = Watch();
        watch.Poll("p", Start, [Server]);

        Assert.Empty(watch.Poll("p", Start.AddSeconds(2), []));
        // Open again later: the time starts anew.
        Assert.Empty(watch.Poll("p", Start.AddSeconds(6), [Server]));
        Assert.Empty(watch.Poll("p", Start.AddSeconds(10), [Server]));
        Assert.Equal([Server], watch.Poll("p", Start.AddSeconds(11), [Server]));
    }

    [Fact]
    public void Each_connection_has_its_own_time()
    {
        var watch = Watch();
        watch.Poll("p", Start, [Server]);
        watch.Poll("p", Start.AddSeconds(3), [Server, Other]);

        Assert.Equal([Server], watch.Poll("p", Start.AddSeconds(5), [Server, Other]));
        Assert.Equal([Other], watch.Poll("p", Start.AddSeconds(8), [Server, Other]));
    }

    [Fact]
    public void The_same_address_written_two_ways_is_one_connection()
    {
        // Sysmon writes an IPv4 address of an IPv6 socket as "::ffff:1.2.3.4"; the table has the IPv4 address.
        var watch = Watch();
        watch.SeenBySensor("p", IPAddress.Parse("::ffff:203.0.113.9"), 3724);

        Assert.Empty(watch.Poll("p", Start, [Server]));
        Assert.Empty(watch.Poll("p", Start.AddSeconds(6), [Server]));

        var mapped = new RemoteEndpoint(IPAddress.Parse("::ffff:198.51.100.7"), 443);
        watch.Poll("p", Start, [mapped]);
        Assert.Equal([Other], watch.Poll("p", Start.AddSeconds(6), [mapped]));
    }

    [Fact]
    public void Another_port_of_the_same_address_is_another_connection()
    {
        var watch = Watch();
        watch.SeenBySensor("p", Server.Address, Server.Port);
        var world = Server with { Port = 8085 };

        watch.Poll("p", Start, [Server, world]);

        Assert.Equal([world], watch.Poll("p", Start.AddSeconds(5), [Server, world]));
    }

    [Fact]
    public void Processes_are_watched_apart_and_a_forgotten_one_starts_over()
    {
        var watch = Watch();
        watch.SeenBySensor("a", Server.Address, Server.Port);
        watch.Poll("a", Start, [Server]);
        watch.Poll("b", Start, [Server]);

        Assert.Empty(watch.Poll("a", Start.AddSeconds(5), [Server]));
        Assert.Equal([Server], watch.Poll("b", Start.AddSeconds(5), [Server]));

        // The pid is used by a new process: what the sensor said about the old one does not count.
        watch.Forget("a");
        watch.Poll("a", Start.AddSeconds(10), [Server]);
        Assert.Equal([Server], watch.Poll("a", Start.AddSeconds(15), [Server]));
    }

    [Fact]
    public void A_flood_of_connections_is_bounded()
    {
        var watch = Watch();
        var many = Enumerable.Range(0, ConnectionWatch.MaxEndpointsPerProcess + 500)
            .Select(i => new RemoteEndpoint(IPAddress.Parse($"10.{i / 65536}.{i / 256 % 256}.{i % 256}"), 80))
            .ToList();
        watch.Poll("p", Start, many);

        var handedOut = watch.Poll("p", Start.AddSeconds(5), many);

        Assert.Equal(ConnectionWatch.MaxEndpointsPerProcess, handedOut.Count);
        // What did not fit is taken once there is room again: never, for this process. Nothing breaks.
        Assert.Empty(watch.Poll("p", Start.AddSeconds(10), many));
    }
}
