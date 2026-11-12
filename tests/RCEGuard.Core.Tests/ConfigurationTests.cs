using System.Net;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

public class ConfigurationTests
{
    [Fact]
    public void Config_from_the_concept_is_read()
    {
        var config = GuardConfigJson.Parse(
            """
            {
              // comments and trailing commas are allowed
              "profiles": [
                {
                  "name": "Warmane",
                  "clientPath": "D:\\Games\\Warmane\\Wow.exe",
                  "allowedRemote": ["203.0.113.0/24", "2001:db8::/32"],
                  "allowedHostnames": ["logon.example.org"],
                },
              ],
            }
            """);

        var profile = Assert.Single(config.Profiles);
        Assert.Equal("Warmane", profile.Name);
        Assert.Equal(@"D:\Games\Warmane\", profile.GameDirectory);
        Assert.Equal(["logon.example.org"], profile.AllowedHostnames);
        Assert.False(profile.KillOnUnknownRemote);
        Assert.True(config.KillEnabled);
    }

    [Theory]
    [InlineData("{", "not valid JSON")]
    [InlineData("null", "empty")]
    [InlineData("{}", "no profiles")]
    [InlineData("""{"profiles":[{"clientPath":"C:\\a\\Wow.exe"}]}""", "no name")]
    [InlineData("""{"profiles":[{"name":"a","clientPath":"Wow.exe"}]}""", "full path")]
    [InlineData("""{"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.txt"}]}""", "full path")]
    [InlineData("""{"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe","allowedRemote":["1.2.3.4/33"]}]}""", "CIDR")]
    [InlineData("""{"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe"},{"name":"b","clientPath":"c:\\A\\wow.exe"}]}""", "more than one profile")]
    public void Invalid_config_is_rejected_with_a_reason(string json, string expectedReason)
    {
        var error = Assert.Throws<FormatException>(() => GuardConfigJson.Parse(json));

        Assert.Contains(expectedReason, error.Message);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0", false)]
    [InlineData("192.168.1.128/25", "192.168.1.129", true)]
    [InlineData("192.168.1.128/25", "192.168.1.127", false)]
    [InlineData("192.168.1.7", "192.168.1.7", true)]
    [InlineData("192.168.1.7", "192.168.1.8", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::5", true)]
    [InlineData("2001:db8::/32", "2001:db9::5", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("0.0.0.0/0", "2001:db8::1", false)] // other address family
    public void Allowlist_ranges(string range, string address, bool expected)
    {
        Assert.Equal(expected, new RemoteAllowlist([range]).Contains(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("example.org")]
    [InlineData("1.2.3.4/")]
    [InlineData("1.2.3.4/-1")]
    [InlineData("1.2.3.4/5/6")]
    [InlineData("::1/129")]
    public void Allowlist_rejects_invalid_entries(string entry)
    {
        Assert.False(RemoteAllowlist.TryParseRange(entry, out _));
        Assert.Throws<FormatException>(() => new RemoteAllowlist([entry]));
    }

    [Theory]
    [InlineData("<Event", "well-formed")]
    [InlineData("<Other/>", "System or EventData")]
    [InlineData("""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>x</EventID></System><EventData/></Event>""", "EventID")]
    [InlineData("""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System><EventData/></Event>""", "TimeCreated")]
    public void Parser_rejects_broken_events_with_a_reason(string xml, string expectedReason)
    {
        Assert.False(SysmonEventParser.TryParse(xml, out var result, out var error));
        Assert.Null(result);
        Assert.Contains(expectedReason, error);
        Assert.Throws<FormatException>(() => SysmonEventParser.Parse(xml));
    }
}
