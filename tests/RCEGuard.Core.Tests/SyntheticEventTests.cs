using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

/// <summary>Rules for behaviour the simulator does not produce, with hand-built events.</summary>
public class SyntheticEventTests
{
    private const string Client = TestData.Client;

    private static SysmonEvent ImageLoad(string module, bool signed) => TestData.Event(
        SysmonEventIds.ImageLoad,
        ("Image", Client),
        ("ProcessId", "100"),
        ("ImageLoaded", module),
        ("Signed", signed ? "true" : "false"),
        ("SignatureStatus", signed ? "Valid" : "Unavailable"));

    private static SysmonEvent FileCreate(string file) => TestData.Event(
        SysmonEventIds.FileCreate, ("Image", Client), ("ProcessId", "100"), ("TargetFilename", file));

    private static SysmonEvent Connect(string ip, string initiated = "true") => TestData.Event(
        SysmonEventIds.NetworkConnect,
        ("Image", Client),
        ("ProcessId", "100"),
        ("DestinationIp", ip),
        ("DestinationPort", "3724"),
        ("Initiated", initiated));

    private static SysmonEvent Registry(string key, string eventType = "SetValue", string pid = "100") => TestData.Event(
        SysmonEventIds.RegistrySetValue, ("Image", Client), ("ProcessId", pid), ("TargetObject", key), ("EventType", eventType));

    // --- R5 ------------------------------------------------------------------------------------
    [Theory]
    [InlineData(@"C:\Users\player\AppData\Local\Temp\x.dll")]
    [InlineData(@"C:\Users\player\Downloads\x.dll")]
    [InlineData(@"C:\Users\player\AppData\Roaming\Thing\x.dll")]
    [InlineData(@"C:\ProgramData\Thing\x.dll")]
    [InlineData(@"C:\Windows\Temp\x.dll")]
    [InlineData(@"\\server\share\x.dll")]
    public void R5_unsigned_module_from_a_user_writable_folder_alerts(string module)
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(ImageLoad(module, signed: false)));

        Assert.Equal("R5", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(FindingAction.Alert, finding.Action);
        Assert.Equal(module, finding.Target);
    }

    [Fact]
    public void R5_unsigned_module_from_elsewhere_is_logged()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(ImageLoad(@"C:\Tools\Overlay\x.dll", signed: false)));

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingAction.Log, finding.Action);
    }

    [Theory]
    [InlineData(@"C:\Users\player\AppData\Roaming\Discord\overlay.dll", true)] // signed overlay
    [InlineData(@"C:\RCEGuardTest\fmod.dll", false)] // library shipped with the game
    [InlineData(@"c:\rceguardtest\Wow.exe", false)] // the client itself
    public void R5_signed_modules_and_the_games_own_files_are_fine(string module, bool signed)
    {
        Assert.Empty(TestData.Engine().Evaluate(ImageLoad(module, signed)));
    }

    [Fact]
    public void R5_signed_flag_alone_is_not_enough()
    {
        var e = TestData.Event(
            SysmonEventIds.ImageLoad,
            ("Image", Client),
            ("ImageLoaded", @"C:\Users\player\Downloads\x.dll"),
            ("Signed", "true"),
            ("SignatureStatus", "Expired"));

        Assert.Equal(Severity.High, Assert.Single(TestData.Engine().Evaluate(e)).Severity);
    }

    // --- R6 ------------------------------------------------------------------------------------
    [Fact]
    public void R6_remote_thread_kills_the_client()
    {
        var e = TestData.Event(
            SysmonEventIds.CreateRemoteThread,
            ("SourceImage", Client),
            ("SourceProcessId", "100"),
            ("TargetImage", @"C:\Windows\explorer.exe"),
            ("TargetProcessId", "200"));

        var finding = Assert.Single(TestData.Engine().Evaluate(e));

        Assert.Equal("R6", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Kill, finding.Action);
        Assert.Equal([new KillTarget(100, Client, true)], finding.KillTargets);
        Assert.Equal(@"C:\Windows\explorer.exe", finding.Target);
    }

    [Fact]
    public void A_kill_finding_without_a_pid_only_alerts()
    {
        var e = TestData.Event(SysmonEventIds.CreateRemoteThread, ("SourceImage", Client), ("TargetImage", @"C:\Windows\explorer.exe"));

        var finding = Assert.Single(TestData.Engine().Evaluate(e));

        Assert.Equal(FindingAction.Alert, finding.Action);
        Assert.Empty(finding.KillTargets);
    }

    // --- R3 ------------------------------------------------------------------------------------
    [Theory]
    [InlineData(@"C:\Users\player\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\notes.txt", Severity.High)]
    [InlineData(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk", Severity.High)]
    [InlineData(@"C:\RCEGuardTest\d3d9.dll", Severity.High)] // planted next to the client
    [InlineData(@"C:\RCEGuardTest\Data\patch.BAT", Severity.High)]
    [InlineData(@"C:\Users\player\Documents\x.ps1", Severity.High)]
    [InlineData(@"C:\Users\player\AppData\Local\Temp\wow.tmp", Severity.Medium)]
    public void R3_severity_depends_on_place_and_file_type(string file, Severity expected)
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(FileCreate(file)));

        Assert.Equal("R3", finding.RuleId);
        Assert.Equal(expected, finding.Severity);
        Assert.Equal(expected == Severity.High ? FindingAction.Alert : FindingAction.Log, finding.Action);
    }

    [Theory]
    [InlineData(@"C:\RCEGuardTest\Data\enUS\realmlist.wtf")]
    [InlineData(@"C:\RCEGuardTest\some.folder\file")]
    public void R3_data_files_inside_the_game_folder_are_fine(string file)
    {
        Assert.Empty(TestData.Engine().Evaluate(FileCreate(file)));
    }

    // --- R2 ------------------------------------------------------------------------------------
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    public void R2_loopback_is_never_a_finding(string ip)
    {
        Assert.Empty(TestData.Engine().Evaluate(Connect(ip)));
    }

    [Fact]
    public void R2_unreadable_address_fails_closed()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(Connect("not-an-ip")));

        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Alert, finding.Action);
    }

    [Fact]
    public void R2_inbound_connection_from_unknown_address_is_logged()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(Connect("203.0.113.9", initiated: "false")));

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingAction.Log, finding.Action);
    }

    [Fact]
    public void R2_ipv4_mapped_address_matches_an_ipv4_allowlist_entry()
    {
        var engine = TestData.Engine(TestData.Profile() with { AllowedRemote = ["203.0.113.0/24"] });

        Assert.Empty(engine.Evaluate(Connect("::ffff:203.0.113.9")));
        Assert.Single(engine.Evaluate(Connect("::ffff:203.0.114.9")));
    }

    // --- R4 ------------------------------------------------------------------------------------
    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater")]
    [InlineData(@"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\RunOnce\x")]
    [InlineData(@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\x")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger")]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\Evil\ImagePath")]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\Evil\Parameters\ServiceDll")]
    public void R4_persistence_locations_kill_the_client(string key)
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(Registry(key)));

        Assert.Equal("R4", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Kill, finding.Action);
        Assert.Equal([new KillTarget(100, Client, true)], finding.KillTargets);
    }

    [Fact]
    public void R4_other_writes_below_services_are_recorded_as_info()
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(Registry(@"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\x\Lease")));

        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal(FindingAction.Log, finding.Action);
    }

    [Theory]
    [InlineData(@"HKU\S-1-5-21-1-2-3-1001\Software\Blizzard Entertainment\World of Warcraft\Client\x")]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001\x")]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\dam\State\x")]
    [InlineData(@"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a")]
    public void R4_ordinary_registry_writes_are_fine(string key)
    {
        Assert.Empty(TestData.Engine().Evaluate(Registry(key)));
    }

    [Theory]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\Evil", "CreateKey", RegistryConcern.ServiceConfiguration)]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\Evil", "SetValue", RegistryConcern.ServicesOther)]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\Evil\Start", "SetValue", RegistryConcern.ServiceConfiguration)]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\Evil\a\b\Start", "SetValue", RegistryConcern.ServicesOther)]
    [InlineData(@"hklm\system\currentcontrolset\services\BAM\State\x", "SetValue", RegistryConcern.None)]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\x", "SetValue", RegistryConcern.Autostart)]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\x.exe\MonitorProcess", "SetValue", RegistryConcern.ImageFileExecutionOptions)]
    public void Registry_classification(string key, string eventType, RegistryConcern expected)
    {
        Assert.Equal(expected, RegistryRules.Classify(key, eventType));
    }

    // --- R7 ------------------------------------------------------------------------------------
    private const string Explorer = @"C:\WINDOWS\Explorer.EXE";

    private static SysmonEvent Access(string access, string target = Explorer, string targetGuid = "{22222222-0000-0000-0000-000000000002}") => TestData.Event(
        SysmonEventIds.ProcessAccess,
        ("SourceImage", Client),
        ("SourceProcessId", "100"),
        ("SourceProcessGUID", "{22222222-0000-0000-0000-000000000001}"),
        ("TargetImage", target),
        ("TargetProcessGUID", targetGuid),
        ("GrantedAccess", access));

    [Theory]
    [InlineData("0x1000", Severity.Info, FindingAction.Log, "opened another program (0x1000)")]                 // ask about it
    [InlineData("0x100000", Severity.Info, FindingAction.Log, "opened another program (0x100000)")]             // wait for it
    [InlineData("0x1410", Severity.Medium, FindingAction.Log, "to read its memory (0x1410)")]                   // what a scan needs
    [InlineData("0x0010", Severity.Medium, FindingAction.Log, "to read its memory (0x0010)")]
    [InlineData("0x0020", Severity.High, FindingAction.Alert, "with rights to change it (0x0020")]              // write memory
    [InlineData("0x0002", Severity.High, FindingAction.Alert, "with rights to change it (0x0002")]              // start a thread
    [InlineData("0x0008", Severity.High, FindingAction.Alert, "with rights to change it (0x0008")]              // change memory protection
    [InlineData("0x1F0FFF", Severity.High, FindingAction.Alert, "with rights to change it (0x1F0FFF")]          // all access (before Vista)
    [InlineData("0x1fffff", Severity.High, FindingAction.Alert, "with rights to change it (0x1fffff")]          // all access
    [InlineData("", Severity.High, FindingAction.Alert, "could not be read ('')")]                              // fail closed
    [InlineData("1410", Severity.High, FindingAction.Alert, "could not be read ('1410')")]
    [InlineData("0xZZ", Severity.High, FindingAction.Alert, "could not be read ('0xZZ')")]
    [InlineData("0x0", Severity.High, FindingAction.Alert, "could not be read ('0x0')")]
    public void R7_is_judged_by_what_the_access_rights_allow(string access, Severity severity, FindingAction action, string summaryPart)
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(Access(access)));

        Assert.Equal(("R7", severity, action), (finding.RuleId, finding.Severity, finding.Action));
        Assert.Contains(summaryPart, finding.Summary);
        Assert.Equal(Explorer, finding.Target);
        Assert.Empty(finding.KillTargets);   // R7 never terminates: asking for a handle changes nothing yet
    }

    [Theory]
    [InlineData("0x1000")]
    [InlineData("0x1410")]
    public void R7_looking_at_a_listed_program_is_expected(string access)
    {
        var engine = TestData.Engine(TestData.Profile() with { AllowedProcessAccess = [@"c:\windows\explorer.exe"] });

        Assert.Empty(engine.Evaluate(Access(access)));
        Assert.Single(engine.Evaluate(Access(access, target: @"C:\Windows\System32\lsass.exe")));   // another program is not covered
    }

    [Theory]
    [InlineData("0x1fffff")]
    [InlineData("0x0020")]
    [InlineData("garbage")]
    public void R7_rights_to_change_a_program_alert_even_if_it_is_listed(string access)
    {
        var engine = TestData.Engine(TestData.Profile() with { AllowedProcessAccess = [Explorer] });

        var finding = Assert.Single(engine.Evaluate(Access(access)));

        Assert.Equal((Severity.High, FindingAction.Alert), (finding.Severity, finding.Action));
    }

    [Fact]
    public void R7_the_client_opening_itself_is_nothing()
    {
        Assert.Empty(TestData.Engine().Evaluate(Access("0x1fffff", target: Client, targetGuid: "{22222222-0000-0000-0000-000000000001}")));
        // Another process running the same program (a second client) is another process.
        Assert.Single(TestData.Engine().Evaluate(Access("0x1fffff", target: Client)));
    }

    [Theory]
    [InlineData("explorer.exe")]
    [InlineData(@"\Windows\explorer.exe")]
    [InlineData("")]
    public void AllowedProcessAccess_takes_full_paths_only(string entry)
    {
        var config = new RCEGuard.Core.Configuration.GuardConfig { Profiles = [TestData.Profile() with { AllowedProcessAccess = [entry] }] };

        var error = Assert.Throws<FormatException>(() => RCEGuard.Core.Configuration.GuardConfigJson.Validate(config));

        Assert.Contains("allowedProcessAccess takes full paths", error.Message);
    }

    [Fact]
    public void Unknown_event_ids_are_ignored()
    {
        Assert.Empty(TestData.Engine().Evaluate(TestData.Event(22, ("Image", Client), ("QueryName", "example.org"))));
        Assert.Empty(TestData.Engine().Evaluate(TestData.Event(4, ("State", "Started"))));
    }
}
