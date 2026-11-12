using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

/// <summary>Shared test data: recorded fixtures, synthetic events and the test profile.</summary>
internal static class TestData
{
    /// <summary>Client path the fixtures were recorded with.</summary>
    public const string Client = @"C:\RCEGuardTest\Wow.exe";

    public const int ClientPid = 25544;

    public static string FixtureXml(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name + ".xml"));

    public static SysmonEvent Fixture(string name) => SysmonEventParser.Parse(FixtureXml(name));

    public static ClientProfile Profile(string clientPath = Client) =>
        new() { Name = "Test", ClientPath = clientPath };

    public static RuleEngine Engine(ClientProfile? profile = null) =>
        new(new GuardConfig { Profiles = [profile ?? Profile()] });

    /// <summary>Builds an event that never came from Sysmon, for cases the simulator cannot produce.</summary>
    public static SysmonEvent Event(int eventId, params (string Name, string Value)[] data)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in data)
        {
            values[name] = value;
        }

        return new SysmonEvent(eventId, RecordId: 1, new DateTimeOffset(2026, 11, 12, 14, 0, 0, TimeSpan.Zero), values);
    }
}
