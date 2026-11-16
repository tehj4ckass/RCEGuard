using RCEGuard.Core.Configuration;

namespace RCEGuard.Core.Tests;

/// <summary>The three modes of the guard, and the editor that sets them in a configuration file.</summary>
public class GuardModeTests
{
    private const string Two =
        """
        {
          // a comment that the editor may drop
          "KillEnabled": true,
          "lockdown": true,
          "somethingNew": { "kept": [1, 2] },
          "profiles": [
            { "name": "Warmane", "clientPath": "D:\\Games\\Warmane\\Wow.exe", "allowedRemote": ["203.0.113.0/24"], "firewall": true },
            { "name": "Jörg's", "clientPath": "D:\\Games\\Other\\Wow.exe", "learning": true, },
          ],
        }
        """;

    private static GuardConfig Config(bool kill, params bool[] learning) => new()
    {
        KillEnabled = kill,
        Profiles = [.. learning.Select((on, index) => new ClientProfile { Name = $"P{index}", ClientPath = $@"C:\G{index}\Wow.exe", Learning = on })],
    };

    [Fact]
    public void The_mode_is_read_from_the_two_settings()
    {
        Assert.Equal(GuardMode.Protect, GuardModes.Of(Config(kill: true, false, false)));
        Assert.Equal(GuardMode.ReportOnly, GuardModes.Of(Config(kill: false, false)));
        Assert.Equal(GuardMode.Learning, GuardModes.Of(Config(kill: true, true, true)));
        // Neither of the three: one profile learns and another does not, or learning with terminating turned off as well.
        Assert.Null(GuardModes.Of(Config(kill: true, true, false)));
        Assert.Null(GuardModes.Of(Config(kill: false, true)));
    }

    [Theory]
    [InlineData(GuardMode.Protect, "protect", "Protect")]
    [InlineData(GuardMode.ReportOnly, "report-only", "Report only")]
    [InlineData(GuardMode.Learning, "learning", "Learning")]
    public void Every_mode_has_an_argument_a_name_and_a_sentence(GuardMode mode, string argument, string name)
    {
        Assert.Equal((argument, name), (GuardModes.Argument(mode), GuardModes.Name(mode)));
        Assert.True(GuardModes.TryParse(argument.ToUpperInvariant(), out var parsed));
        Assert.Equal(mode, parsed);
        Assert.EndsWith(".", GuardModes.Describe(mode));
        Assert.False(GuardModes.TryParse("off", out _));
        Assert.False(GuardModes.TryParse(null, out _));
    }

    [Theory]
    [InlineData(GuardMode.Protect, true, false)]
    [InlineData(GuardMode.ReportOnly, false, false)]
    [InlineData(GuardMode.Learning, true, true)]
    public void Setting_a_mode_changes_the_two_settings_and_nothing_else(GuardMode mode, bool kill, bool learning)
    {
        var edited = GuardConfigEditor.SetMode(Two, mode);

        var config = GuardConfigJson.Parse(edited);
        Assert.Equal(mode, GuardModes.Of(config));
        Assert.Equal(kill, config.KillEnabled);
        Assert.All(config.Profiles, profile => Assert.Equal(learning, profile.Learning));
        Assert.True(config.Lockdown);
        Assert.Equal(("Warmane", @"D:\Games\Warmane\Wow.exe", true), (config.Profiles[0].Name, config.Profiles[0].ClientPath, config.Profiles[0].Firewall));
        Assert.Equal(["203.0.113.0/24"], config.Profiles[0].AllowedRemote);
        // The setting was written with another case: it is changed where it stands, not added a second time.
        Assert.Contains("\"KillEnabled\": " + (kill ? "true" : "false"), edited);
        Assert.DoesNotContain("\"killEnabled\"", edited);
        // What the editor does not know stays, and names stay readable.
        Assert.Contains("\"somethingNew\"", edited);
        Assert.Contains("\"kept\"", edited);
        Assert.Contains("Jörg's", edited);
        Assert.DoesNotContain("a comment", edited);
    }

    [Fact]
    public void A_configuration_without_a_file_is_written_from_its_profiles()
    {
        var json = GuardConfigEditor.ForProfiles([new ClientProfile { Name = "Default", ClientPath = @"D:\Games\Warmane\Wow.exe" }]);

        Assert.Equal(GuardMode.Protect, GuardModes.Of(GuardConfigJson.Parse(json)));
        var learning = GuardConfigJson.Parse(GuardConfigEditor.SetMode(json, GuardMode.Learning));
        Assert.Equal(("Default", @"D:\Games\Warmane\Wow.exe", true), (learning.Profiles[0].Name, learning.Profiles[0].ClientPath, learning.Profiles[0].Learning));
    }

    [Fact]
    public void An_address_is_added_to_the_profile_that_was_named()
    {
        var edited = GuardConfigEditor.AllowRemote(Two, "jörg's", " 198.51.100.7 ", out var added);

        Assert.True(added);
        var config = GuardConfigJson.Parse(edited);
        Assert.Equal(["198.51.100.7"], config.Profiles[1].AllowedRemote);
        Assert.Equal(["203.0.113.0/24"], config.Profiles[0].AllowedRemote);
        Assert.True(config.Profiles[1].Learning);

        var again = GuardConfigEditor.AllowRemote(edited, "Warmane", "2001:db8::/32", out added);
        Assert.True(added);
        Assert.Equal(["203.0.113.0/24", "2001:db8::/32"], GuardConfigJson.Parse(again).Profiles[0].AllowedRemote);
    }

    [Theory]
    [InlineData("203.0.113.9")]       // inside the range that is listed
    [InlineData("203.0.113.0/24")]    // the very entry
    [InlineData("::ffff:203.0.113.9")]
    public void An_address_the_list_covers_already_changes_nothing(string address)
    {
        var edited = GuardConfigEditor.AllowRemote(Two, "Warmane", address, out var added);

        Assert.False(added);
        Assert.Same(Two, edited);
    }

    [Fact]
    public void What_cannot_be_right_is_refused_with_the_reason()
    {
        Assert.Contains("'logon.example.org' is not an IP address or CIDR range", Assert.Throws<FormatException>(() => GuardConfigEditor.AllowRemote(Two, "Warmane", "logon.example.org", out _)).Message);
        Assert.Contains("There is no profile 'Other'. Profiles: 'Warmane', 'Jörg's'.", Assert.Throws<FormatException>(() => GuardConfigEditor.AllowRemote(Two, "Other", "198.51.100.7", out _)).Message);
        Assert.Throws<FormatException>(() => GuardConfigEditor.SetMode("{ not json", GuardMode.Protect));
        Assert.Throws<FormatException>(() => GuardConfigEditor.SetMode("""{ "profiles": [] }""", GuardMode.Protect));
    }
}
