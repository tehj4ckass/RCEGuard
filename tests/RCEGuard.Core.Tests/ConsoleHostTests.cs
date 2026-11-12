using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

/// <summary>
/// R1 and the console host. Windows starts conhost.exe as a child of every console program that
/// gets its own console; the acceptance test of M2 ran into that (the simulator is a console
/// program and was started hidden). One event is recorded (fixture r1-console-host), the others
/// are synthetic; "\??\C:\WINDOWS\system32\conhost.exe 0x4" is what Windows 11 showed for a
/// simulator started in a visible window.
/// </summary>
public class ConsoleHostTests
{
    private const string Client = TestData.Client;
    private const string ClientGuid = "{11111111-0000-0000-0000-000000000001}";
    private const string ChildGuid = "{11111111-0000-0000-0000-000000000002}";

    private static SysmonEvent ChildStart(string image, string commandLine) => TestData.Event(
        SysmonEventIds.ProcessCreate,
        ("RuleName", "R1"),
        ("ProcessGuid", ChildGuid),
        ("ProcessId", "9956"),
        ("Image", image),
        ("CommandLine", commandLine),
        ("ParentProcessGuid", ClientGuid),
        ("ParentProcessId", "20100"),
        ("ParentImage", Client));

    [Fact]
    public void Recorded_console_host_of_the_hidden_simulator_is_logged_and_nothing_is_terminated()
    {
        // Recorded in the acceptance run of M2: "\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1".
        var finding = Assert.Single(TestData.Engine().Evaluate(TestData.Fixture("r1-console-host")));

        Assert.Equal("R1", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingAction.Log, finding.Action);
        Assert.Empty(finding.KillTargets);
        Assert.Equal(@"C:\Windows\System32\conhost.exe", finding.Target);
    }

    [Theory]
    [InlineData(@"C:\WINDOWS\system32\conhost.exe", @"\??\C:\WINDOWS\system32\conhost.exe 0x4")]
    [InlineData(@"C:\Windows\System32\conhost.exe", @"\??\C:\WINDOWS\system32\conhost.exe 0x4")]
    [InlineData(@"C:\Windows\System32\conhost.exe", @"\??\C:\Windows\System32\conhost.exe 0xffffffff -ForceV1")]
    public void Console_host_started_by_Windows_is_logged_and_nothing_is_terminated(string image, string commandLine)
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(ChildStart(image, commandLine)));

        Assert.Equal("R1", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingAction.Log, finding.Action);
        Assert.Empty(finding.KillTargets);
    }

    [Theory]
    // conhost.exe can start other programs: that is the client starting a program.
    [InlineData(@"C:\Windows\System32\conhost.exe", @"conhost.exe --headless cmd.exe /c whoami")]
    [InlineData(@"C:\Windows\System32\conhost.exe", @"C:\Windows\System32\conhost.exe cmd.exe /c whoami")]
    [InlineData(@"C:\Windows\System32\conhost.exe", @"\??\C:\WINDOWS\system32\conhost.exe 0x4 cmd.exe")]
    [InlineData(@"C:\Windows\System32\conhost.exe", @"\??\C:\WINDOWS\system32\conhost.exe 0x4 -ForceV1 --headless cmd.exe")]
    [InlineData(@"C:\Windows\System32\conhost.exe", @"\??\C:\WINDOWS\system32\conhost.exe")]
    [InlineData(@"C:\Windows\System32\conhost.exe", "")]
    // A file that only carries the name, or the right command line on another program.
    [InlineData(@"C:\Users\player\AppData\Local\Temp\conhost.exe", @"\??\C:\WINDOWS\system32\conhost.exe 0x4")]
    [InlineData(@"C:\RCEGuardTest\conhost.exe", @"\??\C:\RCEGuardTest\conhost.exe 0x4")]
    [InlineData(@"D:\Windows\System32\conhost.exe", @"\??\D:\Windows\System32\conhost.exe 0x4")]
    [InlineData(@"C:\Windows\System32\cmd.exe", @"\??\C:\WINDOWS\system32\conhost.exe 0x4")]
    public void Anything_else_named_or_started_like_a_console_host_is_an_ordinary_R1(string image, string commandLine)
    {
        var finding = Assert.Single(TestData.Engine().Evaluate(ChildStart(image, commandLine)));

        Assert.Equal("R1", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingAction.Kill, finding.Action);
        Assert.Equal(2, finding.KillTargets.Count);
    }

    [Fact]
    public void The_system_directory_of_the_machine_decides_where_the_console_host_lives()
    {
        var engine = new RuleEngine(new() { Profiles = [TestData.Profile()] }, @"D:\Win\System32\");
        var onD = ChildStart(@"D:\Win\System32\conhost.exe", @"\??\D:\Win\System32\conhost.exe 0x4");
        var onC = ChildStart(@"C:\Windows\System32\conhost.exe", @"\??\C:\Windows\System32\conhost.exe 0x4");

        Assert.Equal(FindingAction.Log, Assert.Single(engine.Evaluate(onD)).Action);
        Assert.Equal(FindingAction.Kill, Assert.Single(engine.Evaluate(onC)).Action);
    }

    [Fact]
    public void A_miner_command_line_is_never_mistaken_for_a_console_host()
    {
        var findings = TestData.Engine().Evaluate(
            ChildStart(@"C:\Windows\System32\conhost.exe", @"conhost.exe --headless xmrig.exe -o stratum+tcp://pool.invalid:3333"));

        Assert.Equal(["R1", "R9"], findings.Select(f => f.RuleId));
        Assert.All(findings, f => Assert.Equal(FindingAction.Kill, f.Action));
    }

    [Fact]
    public void The_console_host_counts_as_the_clients_own_child_for_R7()
    {
        var engine = TestData.Engine();
        engine.Evaluate(ChildStart(@"C:\Windows\System32\conhost.exe", @"\??\C:\WINDOWS\system32\conhost.exe 0x4"));

        var access = TestData.Event(
            SysmonEventIds.ProcessAccess,
            ("SourceImage", Client),
            ("SourceProcessId", "20100"),
            ("TargetProcessGUID", ChildGuid),
            ("TargetImage", @"C:\Windows\System32\conhost.exe"),
            ("GrantedAccess", "0x1fffff"));

        Assert.Empty(engine.Evaluate(access));
    }
}
