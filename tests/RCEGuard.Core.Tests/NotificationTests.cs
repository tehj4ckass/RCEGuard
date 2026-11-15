using RCEGuard.Core.Configuration;
using RCEGuard.Core.Notifications;
using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Tests;

public class NotificationTests
{
    private static Finding Finding(Severity severity, FindingAction action, string profile = "Warmane") => new()
    {
        RuleId = "R1",
        Severity = severity,
        Action = action,
        Summary = @"The game client started another program: C:\Windows\System32\cmd.exe",
        Profile = profile,
        Time = new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero),
    };

    [Theory]
    [InlineData(FindingAction.Log, false)]
    [InlineData(FindingAction.Alert, true)]
    [InlineData(FindingAction.Kill, true)]
    public void The_owner_is_told_about_everything_that_alerts_or_terminates(FindingAction action, bool notifies)
    {
        Assert.Equal(notifies, NotificationText.Notifies(Finding(Severity.Medium, action)));
    }

    [Fact]
    public void A_finding_that_terminates_says_what_was_done()
    {
        var notification = NotificationText.ForFinding(
            Finding(Severity.Critical, FindingAction.Kill), "cmd.exe (4): terminated; Wow.exe (8): terminated", late: false, "GAMEPC");

        Assert.Equal("RCEGuard: R1 CRITICAL [Warmane]", notification.Title);
        Assert.Equal(NotificationPriority.Urgent, notification.Priority);
        var lines = notification.Body.Split('\n');
        Assert.Equal(@"The game client started another program: C:\Windows\System32\cmd.exe", lines[0]);
        Assert.Equal("Action: cmd.exe (4): terminated; Wow.exe (8): terminated", lines[1]);
        Assert.StartsWith("GAMEPC, 2026-11-15", lines[2]);
        Assert.Equal(3, lines.Length);
    }

    [Fact]
    public void A_finding_that_only_alerts_names_no_action_and_is_less_urgent()
    {
        var notification = NotificationText.ForFinding(Finding(Severity.High, FindingAction.Alert, profile: string.Empty), "none", late: false, "GAMEPC");

        Assert.Equal("RCEGuard: R1 HIGH", notification.Title);   // no profile: no brackets
        Assert.Equal(NotificationPriority.High, notification.Priority);
        Assert.DoesNotContain("Action:", notification.Body);
    }

    [Fact]
    public void A_finding_from_the_time_the_guard_was_down_says_so()
    {
        var notification = NotificationText.ForFinding(Finding(Severity.Critical, FindingAction.Alert), "none", late: true, "GAMEPC");

        Assert.Contains("while RCEGuard was not running", notification.Body);
    }

    [Fact]
    public void The_notifications_about_the_guard_itself_say_what_it_means_for_the_client()
    {
        var cannotRun = NotificationText.CannotRun("the Sysmon log does not exist.", "GAMEPC");
        Assert.Equal(NotificationPriority.Urgent, cannotRun.Priority);
        Assert.Contains("the Sysmon log does not exist.", cannotRun.Body);
        Assert.Contains("not watched", cannotRun.Body);

        var ended = NotificationText.EndedUnexpectedly(new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero), "GAMEPC");
        Assert.Equal(NotificationPriority.High, ended.Priority);
        Assert.Contains("last alive at 2026-11-15", ended.Body);
        Assert.DoesNotContain("last alive", NotificationText.EndedUnexpectedly(null, "GAMEPC").Body);

        var stopped = NotificationText.StoppedWhileClientRuns(["Wow.exe"], "GAMEPC");
        Assert.Equal(NotificationPriority.Urgent, stopped.Priority);
        Assert.Contains("Wow.exe is running", stopped.Body);

        Assert.Equal(NotificationPriority.Default, NotificationText.Test("GAMEPC").Priority);
        Assert.All(new[] { cannotRun, ended, stopped, NotificationText.Test("GAMEPC") }, n => Assert.Contains("GAMEPC", n.Body));
    }

    [Fact]
    public void The_ntfy_settings_are_read_from_the_configuration()
    {
        var config = GuardConfigJson.Parse(
            """
            {
              "notify": { "toast": true, "ntfy": { "url": "https://ntfy.example.org/my-topic", "token": "tk_example" } },
              "profiles": [ { "name": "a", "clientPath": "C:\\a\\Wow.exe" } ]
            }
            """);

        Assert.NotNull(config.Notify?.Ntfy);
        Assert.True(config.Notify.Ntfy.Enabled);   // filled in means on
        Assert.Equal("https://ntfy.example.org/my-topic", config.Notify.Ntfy.Url);
        Assert.Equal("tk_example", config.Notify.Ntfy.Token);
        Assert.Null(GuardConfigJson.Parse("""{"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe"}]}""").Notify);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ntfy.example.org/my-topic")]       // no scheme
    [InlineData("ftp://ntfy.example.org/my-topic")]
    [InlineData("https://ntfy.example.org")]        // a server, but no topic
    [InlineData("https://ntfy.example.org/")]
    public void An_ntfy_address_that_is_not_a_topic_is_rejected(string url)
    {
        var json = """{"notify":{"ntfy":{"url":"URL"}},"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe"}]}""".Replace("URL", url);

        var error = Assert.Throws<FormatException>(() => GuardConfigJson.Parse(json));

        Assert.Contains("notify.ntfy.url", error.Message);
    }

    [Fact]
    public void A_turned_off_ntfy_entry_is_not_checked()
    {
        var config = GuardConfigJson.Parse(
            """{"notify":{"ntfy":{"enabled":false,"url":""}},"profiles":[{"name":"a","clientPath":"C:\\a\\Wow.exe"}]}""");

        Assert.False(config.Notify!.Ntfy!.Enabled);
    }
}
