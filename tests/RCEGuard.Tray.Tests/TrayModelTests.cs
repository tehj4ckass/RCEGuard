using System.IO;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Learning;
using RCEGuard.Core.Rules;
using RCEGuard.Core.State;
using RCEGuard.Service;
using RCEGuard.Tray.Model;

namespace RCEGuard.Tray.Tests;

/// <summary>A data folder as the service leaves it, written with the service's own code.</summary>
internal sealed class DataFolder : IDisposable
{
    public DataFolder()
    {
        Path = Directory.CreateTempSubdirectory("rceguard-tray-").FullName;
        File.WriteAllText(System.IO.Path.Combine(Path, "install-state.json"), """{"clientPath":"C:\\Games\\Warmane\\Wow.exe"}""");
    }

    public string Path { get; }

    public string Database => System.IO.Path.Combine(Path, "findings.db");

    public string SeenPath => System.IO.Path.Combine(Path, "user", "tray-state.txt");

    public long Add(string rule, Severity severity, FindingAction action, string summary, string taken = "none", string profile = "Default")
    {
        using var store = new FindingStore(Database);
        return store.Add(
            new Finding
            {
                RuleId = rule,
                Severity = severity,
                Action = action,
                Summary = summary,
                Profile = profile,
                Target = "target",
                Time = new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero),
            },
            taken);
    }

    public void Lock(string profile) => new LockdownFile(System.IO.Path.Combine(Path, LockdownFile.FileName)).Save(
        [new LockdownEntry(profile, new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero), "R1", "The game client started another program")]);

    /// <summary>A configuration with one profile "Warmane"; <paramref name="profileSettings"/> go into the profile.</summary>
    public void Configure(string profileSettings = "") => File.WriteAllText(
        System.IO.Path.Combine(Path, "appsettings.json"),
        $$"""{"cpuAlertCores": 2.0, "profiles":[{"name":"Warmane","clientPath":"C:\\Games\\Warmane\\Wow.exe" {{profileSettings}} }]}""");

    /// <summary>The headers of a 32-bit program laid out like the 3.3.5a client's; the fourth section is ".zdata".</summary>
    public static byte[] ClientFile(bool zdataExecutable)
    {
        var file = new byte[4096];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        const int pe = 0x110;
        BitConverter.GetBytes(pe).CopyTo(file, 0x3C);
        file[pe] = (byte)'P';
        file[pe + 1] = (byte)'E';
        (string Name, uint Flags)[] sections =
        [
            (".text", 0x60000020), (".rdata", 0x40000040), (".data", 0xC0000040),
            (".zdata", zdataExecutable ? 0xE0000040 : 0xC0000040), (".tls", 0xC0000040), (".rsrc", 0x40000040),
        ];
        BitConverter.GetBytes((ushort)sections.Length).CopyTo(file, pe + 6);
        BitConverter.GetBytes((ushort)0xE0).CopyTo(file, pe + 20);
        for (var i = 0; i < sections.Length; i++)
        {
            var at = pe + 24 + 0xE0 + (i * 40);
            System.Text.Encoding.ASCII.GetBytes(sections[i].Name).CopyTo(file, at);
            BitConverter.GetBytes(sections[i].Flags).CopyTo(file, at + 36);
        }

        return file;
    }

    /// <summary>
    /// A configuration whose client is a file in this folder with the headers of the 3.3.5a client;
    /// returns its path. <paramref name="zdataExecutable"/>: the section ".zdata" is writable and executable.
    /// </summary>
    public string ConfigureWithClientFile(bool zdataExecutable)
    {
        var client = System.IO.Path.Combine(Path, "Wow.exe");
        File.WriteAllBytes(client, DataFolder.ClientFile(zdataExecutable));
        File.WriteAllText(
            System.IO.Path.Combine(Path, "appsettings.json"),
            $$"""{"profiles":[{"name":"Warmane","clientPath":"{{client.Replace("\\", "\\\\")}}"}]}""");
        return client;
    }

    /// <summary>Notes of the learning mode as the service saves them.</summary>
    public void Learn(params LearnedProfile[] notes) =>
        new LearnedFile(System.IO.Path.Combine(Path, LearnedFile.FileName)).Save(notes);

    public MainViewModel ViewModel(ServiceState service = ServiceState.Running, Func<DateTimeOffset>? clock = null) =>
        new(Path, new StatusReader(Path, () => service), new SeenFile(SeenPath), clock);

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(Path, recursive: true);
    }
}

public sealed class TrayModelTests : IDisposable
{
    private readonly DataFolder data = new();

    public void Dispose() => data.Dispose();

    [Fact]
    public void Findings_written_by_the_service_are_read_newest_first()
    {
        var first = data.Add("R3", Severity.Medium, FindingAction.Log, "A file outside the game folder");
        var second = data.Add("R1", Severity.Critical, FindingAction.Kill, "The game client started another program", "cmd.exe (4): terminated");
        using (var store = new FindingStore(data.Database))
        {
            store.AddRepeat(first, DateTimeOffset.UtcNow);
            store.AddRepeat(first, DateTimeOffset.UtcNow);
        }

        var rows = FindingReader.ReadNewest(data.Database, 10);

        Assert.Equal([second, first], rows.Select(row => row.Id));
        Assert.Equal(("R1", "CRITICAL", "cmd.exe (4): terminated", "Default", true), (rows[0].Rule, rows[0].SeverityText, rows[0].ActionText, rows[0].Profile, rows[0].Notifies));
        Assert.Equal(("R3", "MEDIUM", "log", "+2", false), (rows[1].Rule, rows[1].SeverityText, rows[1].ActionText, rows[1].RepeatsText, rows[1].Notifies));
        Assert.Equal(new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero), rows[0].Time);
        Assert.Equal(second, FindingReader.MaxId(data.Database));
        Assert.Equal([second], FindingReader.ReadAfter(data.Database, first).Select(row => row.Id));
        Assert.Single(FindingReader.ReadNewest(data.Database, 1));
    }

    [Fact]
    public void A_data_folder_without_a_database_has_no_findings()
    {
        Assert.Empty(FindingReader.ReadNewest(data.Database, 10));
        Assert.Empty(FindingReader.ReadAfter(data.Database, 0));
        Assert.Equal(0, FindingReader.MaxId(data.Database));
    }

    [Fact]
    public void The_database_can_be_read_while_the_service_has_it_open()
    {
        using var store = new FindingStore(data.Database);
        store.Add(new Finding { RuleId = "R2", Severity = Severity.Critical, Action = FindingAction.Alert, Summary = "x", Time = DateTimeOffset.UtcNow }, "none");

        Assert.Single(FindingReader.ReadNewest(data.Database, 10));
    }

    [Fact]
    public void The_status_names_the_client_from_the_installation_and_the_profiles_in_lockdown()
    {
        data.Lock("Default");

        var status = new StatusReader(data.Path, () => ServiceState.Running).Read();

        Assert.Equal(@"C:\Games\Warmane\Wow.exe", Assert.Single(status.Profiles).ClientPath);
        Assert.Null(status.ConfigProblem);
        Assert.Equal("Default", Assert.Single(status.Locked).Profile);
        Assert.True(status.ToastEnabled);
    }

    [Fact]
    public void A_configuration_can_turn_the_pop_ups_off()
    {
        File.WriteAllText(Path.Combine(data.Path, "appsettings.json"), """{"notify":{"toast":false},"profiles":[{"name":"Warmane","clientPath":"C:\\Games\\Warmane\\Wow.exe"}]}""");

        var status = new StatusReader(data.Path, () => ServiceState.Running).Read();

        Assert.False(status.ToastEnabled);
        Assert.Equal("Warmane", Assert.Single(status.Profiles).Name);
    }

    [Fact]
    public void A_folder_that_is_not_there_or_holds_a_broken_configuration_is_a_problem_not_a_crash()
    {
        var missing = new StatusReader(Path.Combine(data.Path, "nope"), () => ServiceState.NotInstalled).Read();
        Assert.Contains("not installed", missing.ConfigProblem);
        Assert.Empty(missing.Profiles);
        Assert.Empty(missing.Locked);

        File.WriteAllText(Path.Combine(data.Path, "appsettings.json"), "{ not json");
        File.WriteAllText(Path.Combine(data.Path, LockdownFile.FileName), "{ not json");
        var broken = new StatusReader(data.Path, () => ServiceState.Running).Read();
        Assert.Contains("not valid JSON", broken.ConfigProblem);
        Assert.NotNull(broken.LockdownProblem);
    }

    private static GuardStatus Status(ServiceState service = ServiceState.Running, int locked = 0, string? lockdownProblem = null, int profiles = 1) => new(
        service,
        [.. Enumerable.Range(1, profiles).Select(n => new ClientProfile { Name = $"Client{n}", ClientPath = $@"C:\Games\{n}\Wow.exe" })],
        null,
        [.. Enumerable.Range(1, locked).Select(n => new LockdownEntry($"Client{n}", DateTimeOffset.UtcNow, "R1", "x"))],
        lockdownProblem,
        true);

    [Theory]
    [InlineData("Running", 0, 0, "Watching", "Watching 'Client1'")]
    [InlineData("Running", 0, 2, "Alert", "2 new findings")]
    [InlineData("Running", 0, 1, "Alert", "1 new finding")]
    [InlineData("Running", 1, 3, "Locked", "'Client1' is locked down")]            // a lockdown counts more than new findings
    [InlineData("Stopped", 1, 3, "NotWatching", "RCEGuard is not running")]        // and a guard that is down counts most
    [InlineData("NotInstalled", 0, 0, "NotWatching", "RCEGuard is not installed")]
    [InlineData("Changing", 0, 0, "NotWatching", "RCEGuard is starting or stopping")]
    public void The_state_shows_what_counts_most(string service, int locked, int unseen, string kind, string headline)
    {
        var state = TrayState.From(Status(Enum.Parse<ServiceState>(service), locked), unseen);

        Assert.Equal((Enum.Parse<TrayKind>(kind), headline), (state.Kind, state.Headline));
        Assert.StartsWith("RCEGuard", state.Tooltip);
        Assert.True(state.Tooltip.Length <= 100);
    }

    private static GuardStatus LearningStatus(ServiceState service = ServiceState.Running, int locked = 0, int learning = 1, int profiles = 1) => new(
        service,
        [.. Enumerable.Range(1, profiles).Select(n => new ClientProfile { Name = $"Client{n}", ClientPath = $@"C:\Games\{n}\Wow.exe", Learning = n <= learning })],
        null,
        [.. Enumerable.Range(1, locked).Select(n => new LockdownEntry($"Client{n}", DateTimeOffset.UtcNow, "R1", "x"))],
        null,
        true);

    [Fact]
    public void A_client_in_learning_mode_is_shown_as_watched_not_protected()
    {
        var state = TrayState.From(LearningStatus(), 0);

        Assert.Equal((TrayKind.Learning, "Learning mode: 'Client1' is watched, not protected"), (state.Kind, state.Headline));
        Assert.Equal("RCEGuard: learning mode for 'Client1' (not protected)", state.Tooltip);
        Assert.Contains("nothing is terminated, locked down or blocked", state.Detail);
        Assert.Contains("\"learning\": false", state.Detail);

        var two = TrayState.From(LearningStatus(learning: 2, profiles: 3), 0);
        Assert.Equal("Learning mode: 'Client1', 'Client2' are watched, not protected", two.Headline);
        Assert.True(two.Tooltip.Length <= 100);
    }

    [Fact]
    public void Learning_mode_counts_less_than_new_findings_a_lockdown_or_a_guard_that_is_down()
    {
        var findings = TrayState.From(LearningStatus(), 2);
        Assert.Equal((TrayKind.Alert, "2 new findings"), (findings.Kind, findings.Headline));
        // Still said: who reads about a finding must know that nothing was done about it.
        Assert.Contains("Learning mode is on for 'Client1': nothing is terminated or blocked there.", findings.Detail);

        Assert.Equal(TrayKind.Locked, TrayState.From(LearningStatus(locked: 1), 0).Kind);
        Assert.Equal(TrayKind.NotWatching, TrayState.From(LearningStatus(ServiceState.Stopped), 0).Kind);
        // Without a learning profile nothing changes.
        Assert.Equal(TrayKind.Watching, TrayState.From(LearningStatus(learning: 0), 0).Kind);
        Assert.DoesNotContain("Learning", TrayState.From(LearningStatus(learning: 0), 2).Detail);
    }

    [Fact]
    public void The_status_reads_which_profiles_learn_and_what_was_noted()
    {
        data.Configure(""", "learning": true """);
        data.Learn(new LearnedProfile { Profile = "Warmane", Sessions = 2 }, new LearnedProfile { Profile = "Other", Sessions = 1 });

        var status = new StatusReader(data.Path, () => ServiceState.Running).Read();

        Assert.Equal("Warmane", Assert.Single(status.Learning).Name);
        Assert.Equal(2, status.Learned!.Count);
        Assert.Equal(2.0, status.CpuAlertCores);

        // Notes that cannot be read are no notes, and no problem for the rest.
        File.WriteAllText(Path.Combine(data.Path, LearnedFile.FileName), "{ not json");
        var broken = new StatusReader(data.Path, () => ServiceState.Running).Read();
        Assert.Empty(broken.Learned!);
        Assert.Single(broken.Learning);
    }

    [Fact]
    public void A_learning_profile_is_listed_with_what_was_noted_and_the_suggestion()
    {
        data.Configure(""", "learning": true, "allowedRemote": ["198.51.100.0/24"] """);
        var viewModel = data.ViewModel();
        viewModel.Refresh();

        var nothing = Assert.Single(viewModel.Learning);
        Assert.True(viewModel.HasLearning);
        Assert.Equal(("Warmane", "'Warmane': nothing noted yet."), (nothing.Profile, nothing.Text));
        Assert.Contains("nothing was noted yet", nothing.Report);
        Assert.Equal(TrayKind.Learning, viewModel.State.Kind);

        data.Learn(new LearnedProfile
        {
            Profile = "warmane",
            Sessions = 2,
            Remotes = [new LearnedRemote { Address = "203.0.113.9", Port = 3724, Count = 3 }],
            Hosts = [new LearnedHost { Name = "logon.example.org", Addresses = ["203.0.113.9"], Count = 2 }],
            PeakCpuCores = 1.2,
        });
        viewModel.Refresh();

        var line = Assert.Single(viewModel.Learning);
        Assert.Equal("'Warmane': 2 starts of the client, 1 connection target, 0 other programs opened.", line.Text);
        Assert.Contains("\"allowedHostnames\": [\"logon.example.org\"],", line.Report);
        Assert.Contains("Highest processor load: 1.2 cores on average (R8 reports above 2.0: cpuAlertCores)", line.Report);

        // Learning turned off: the notes stay in the file, the window stops showing them.
        data.Configure();
        viewModel.Refresh();
        Assert.Empty(viewModel.Learning);
        Assert.False(viewModel.HasLearning);
        Assert.Equal(TrayKind.Watching, viewModel.State.Kind);
    }

    [Fact]
    public void A_client_file_with_a_writable_and_executable_section_is_noted_until_it_is_changed()
    {
        var client = data.ConfigureWithClientFile(zdataExecutable: true);
        var viewModel = data.ViewModel();
        viewModel.Refresh();

        Assert.True(viewModel.HasClientNote);
        Assert.Equal(
            "The client of 'Warmane' has a section that is both writable and executable (.zdata): code that gets written there can run. See \"Patching the client\" in the README.",
            viewModel.ClientNote);
        // Not an alarm: the icon stays as it is.
        Assert.Equal(TrayKind.Watching, viewModel.State.Kind);

        // The file was changed (as the patch does): the next look says nothing any more.
        var patched = DataFolder.ClientFile(zdataExecutable: false);
        File.WriteAllBytes(client, patched);
        File.SetLastWriteTimeUtc(client, DateTime.UtcNow.AddSeconds(5));
        viewModel.Refresh();

        Assert.False(viewModel.HasClientNote);
        Assert.Equal(string.Empty, viewModel.ClientNote);
    }

    [Fact]
    public void A_client_file_that_is_missing_or_fine_gives_no_note()
    {
        var viewModel = data.ViewModel();   // the client of the installation does not exist on this machine
        viewModel.Refresh();
        Assert.False(viewModel.HasClientNote);

        data.ConfigureWithClientFile(zdataExecutable: false);
        viewModel.Refresh();
        Assert.False(viewModel.HasClientNote);
    }

    [Fact]
    public void Several_clients_and_an_unreadable_lockdown_state_are_named_as_such()
    {
        Assert.Equal("Watching 2 clients", TrayState.From(Status(profiles: 2), 0).Headline);
        Assert.Equal("'Client1', 'Client2' are locked down", TrayState.From(Status(locked: 2, profiles: 2), 0).Headline);

        var unreadable = TrayState.From(Status(lockdownProblem: "not json"), 0);
        Assert.Equal((TrayKind.Locked, "Every client is locked down"), (unreadable.Kind, unreadable.Headline));
    }

    [Fact]
    public void The_pop_up_names_the_one_finding_or_the_most_serious_of_several()
    {
        FindingRow Row(long id, string rule, string severity, string summary) => new(id, DateTimeOffset.UtcNow, rule, severity, "Alert", "none", "Warmane", "t", summary, 0);

        var one = ToastText.For([Row(1, "R2", "Critical", "The game client connected to 203.0.113.9:443")]);
        Assert.Equal(("RCEGuard: R2 CRITICAL [Warmane]", "The game client connected to 203.0.113.9:443"), one);

        var several = ToastText.For([Row(1, "R3", "High", "A program file was created"), Row(2, "R1", "Critical", "The game client started cmd.exe"), Row(3, "R5", "High", "x")]);
        Assert.Equal("RCEGuard: 3 new findings", several.Title);
        Assert.StartsWith("Most serious: R1 CRITICAL [Warmane]. The game client started cmd.exe", several.Text);

        Assert.True(ToastText.For([Row(1, "R3", "High", new string('x', 500))]).Text.Length <= 200);
    }

    // --- the view model: what is announced ---------------------------------------------------------

    private static List<(string Title, string Text)> Toasts(MainViewModel viewModel)
    {
        var toasts = new List<(string, string)>();
        viewModel.ToastRequested += (title, text) => toasts.Add((title, text));
        return toasts;
    }

    [Fact]
    public void The_first_start_announces_nothing_that_is_already_there()
    {
        data.Add("R1", Severity.Critical, FindingAction.Kill, "old");
        var viewModel = data.ViewModel();
        var toasts = Toasts(viewModel);

        viewModel.Refresh();

        Assert.Empty(toasts);
        Assert.Single(viewModel.Findings);
        Assert.Equal(TrayKind.Watching, viewModel.State.Kind);
    }

    [Fact]
    public void A_new_finding_that_alerts_is_announced_once_and_counts_until_the_list_was_looked_at()
    {
        var viewModel = data.ViewModel();
        var toasts = Toasts(viewModel);
        viewModel.Refresh();

        data.Add("R3", Severity.Medium, FindingAction.Log, "only logged");
        viewModel.Refresh();
        Assert.Empty(toasts);
        Assert.Equal(TrayKind.Watching, viewModel.State.Kind);

        data.Add("R1", Severity.Critical, FindingAction.Kill, "The game client started another program", "cmd.exe (4): terminated");
        viewModel.Refresh();
        viewModel.Refresh();

        Assert.Equal("RCEGuard: R1 CRITICAL [Default]", Assert.Single(toasts).Title);
        Assert.Equal((TrayKind.Alert, "1 new finding"), (viewModel.State.Kind, viewModel.State.Headline));
        Assert.Equal(2, viewModel.Findings.Count);

        viewModel.MarkSeen();
        Assert.Equal(TrayKind.Watching, viewModel.State.Kind);
    }

    [Fact]
    public void What_happened_while_the_tray_application_was_not_running_is_announced_at_its_next_start()
    {
        data.ViewModel().Refresh();   // the first start notes where the user stands
        data.Add("R1", Severity.Critical, FindingAction.Kill, "first");
        data.Add("R4", Severity.Critical, FindingAction.Kill, "second");

        var later = data.ViewModel();
        var toasts = Toasts(later);
        later.Refresh();

        Assert.Equal("RCEGuard: 2 new findings", Assert.Single(toasts).Title);
        Assert.Equal("2 new findings", later.State.Headline);

        // And not again by the start after that.
        var again = data.ViewModel();
        var none = Toasts(again);
        again.Refresh();
        Assert.Empty(none);
    }

    [Fact]
    public void A_finding_that_arrives_while_the_list_is_open_is_announced_but_does_not_count_as_unseen()
    {
        var viewModel = data.ViewModel();
        var toasts = Toasts(viewModel);
        viewModel.Refresh(windowIsOpen: true);

        data.Add("R2", Severity.Critical, FindingAction.Alert, "x");
        viewModel.Refresh(windowIsOpen: true);

        Assert.Single(toasts);
        Assert.Equal(TrayKind.Watching, viewModel.State.Kind);
    }

    [Fact]
    public void A_burst_of_findings_gives_one_pop_up_now_and_one_for_the_rest_after_a_pause()
    {
        var time = new DateTimeOffset(2026, 11, 15, 17, 17, 48, TimeSpan.Zero);
        var viewModel = data.ViewModel(clock: () => time);
        var toasts = Toasts(viewModel);
        viewModel.Refresh();

        // As in the run of 2026-11-15: six findings that notify within 15 seconds.
        data.Add("R1", Severity.Critical, FindingAction.Kill, "first");
        viewModel.Refresh();
        Assert.Equal("RCEGuard: R1 CRITICAL [Default]", Assert.Single(toasts).Title);

        time = time.AddSeconds(2);
        data.Add("R2", Severity.Critical, FindingAction.Alert, "second");
        viewModel.Refresh();
        time = time.AddSeconds(4);
        data.Add("R5", Severity.High, FindingAction.Alert, "third");
        viewModel.Refresh();
        time = time.AddSeconds(2);
        viewModel.Refresh();

        Assert.Single(toasts);                                   // eight seconds after the first: still quiet
        Assert.Equal("3 new findings", viewModel.State.Headline); // but the icon and the count are up to date

        time = time.AddSeconds(3);
        viewModel.Refresh();                                      // no new finding is needed to end the wait
        Assert.Equal(2, toasts.Count);
        Assert.Equal("RCEGuard: 2 new findings", toasts[1].Title);
        Assert.StartsWith("Most serious: R2 CRITICAL", toasts[1].Text);

        time = time.AddSeconds(30);
        viewModel.Refresh();
        Assert.Equal(2, toasts.Count);                            // nothing is announced twice

        data.Add("R4", Severity.Critical, FindingAction.Kill, "later");
        viewModel.Refresh();
        Assert.Equal(3, toasts.Count);                            // after the pause a new finding comes at once
    }

    [Fact]
    public void With_pop_ups_turned_off_a_new_finding_still_changes_the_icon()
    {
        File.WriteAllText(Path.Combine(data.Path, "appsettings.json"), """{"notify":{"toast":false},"profiles":[{"name":"Warmane","clientPath":"C:\\Games\\Warmane\\Wow.exe"}]}""");
        var viewModel = data.ViewModel();
        var toasts = Toasts(viewModel);
        viewModel.Refresh();

        data.Add("R1", Severity.Critical, FindingAction.Kill, "x", profile: "Warmane");
        viewModel.Refresh();

        Assert.Empty(toasts);
        Assert.Equal(TrayKind.Alert, viewModel.State.Kind);
    }

    [Fact]
    public void A_new_database_after_a_new_installation_starts_the_count_again()
    {
        data.Add("R1", Severity.Critical, FindingAction.Kill, "one");
        data.Add("R1", Severity.Critical, FindingAction.Kill, "two");
        data.Add("R1", Severity.Critical, FindingAction.Kill, "three");
        data.ViewModel().Refresh();   // the user stands at id 3

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        File.Delete(data.Database);
        data.Add("R4", Severity.Critical, FindingAction.Kill, "after the new installation");   // id 1 again
        var viewModel = data.ViewModel();
        var toasts = Toasts(viewModel);
        viewModel.Refresh();

        Assert.Equal("RCEGuard: R4 CRITICAL [Default]", Assert.Single(toasts).Title);
    }

    [Fact]
    public void Lockdowns_are_listed_with_their_reason_and_a_stopped_service_shows_first()
    {
        data.Lock("Default");
        var viewModel = data.ViewModel();
        viewModel.Refresh();

        var line = Assert.Single(viewModel.Lockdowns);
        Assert.Equal("Default", line.Profile);
        Assert.Contains("after R1: The game client started another program", line.Text);
        Assert.True(viewModel.HasLockdowns);
        Assert.Equal(TrayKind.Locked, viewModel.State.Kind);

        var stopped = data.ViewModel(ServiceState.Stopped);
        stopped.Refresh();
        Assert.Equal(TrayKind.NotWatching, stopped.State.Kind);
        Assert.Single(stopped.Lockdowns);   // still listed
    }

    [Fact]
    public void An_unreadable_lockdown_state_offers_one_release_for_every_profile()
    {
        File.WriteAllText(Path.Combine(data.Path, LockdownFile.FileName), "{ not json");
        var viewModel = data.ViewModel();
        viewModel.Refresh();

        Assert.Equal(ReleaseAction.EveryProfile, Assert.Single(viewModel.Lockdowns).Profile);
        Assert.Equal("--release", ReleaseAction.Arguments(ReleaseAction.EveryProfile));
        Assert.Equal("--release \"My Client\"", ReleaseAction.Arguments("My Client"));
        Assert.Equal("--release \"ab\"", ReleaseAction.Arguments("a\"b"));   // a quote cannot break out of the argument
    }

    [Fact]
    public void Only_the_data_folder_of_the_installed_service_uses_the_users_own_mark()
    {
        var installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RCEGuard");

        Assert.Equal("tray-state.txt", Path.GetFileName(SeenFile.PathFor(installed)));
        Assert.Equal(SeenFile.PathFor(installed), SeenFile.PathFor(installed.ToUpperInvariant() + Path.DirectorySeparatorChar));
        Assert.Matches("^tray-state-[0-9a-f]{8}[.]txt$", Path.GetFileName(SeenFile.PathFor(data.Path)));
        Assert.NotEqual(SeenFile.PathFor(data.Path), SeenFile.PathFor(data.Path + "2"));
        Assert.Equal(Path.GetDirectoryName(SeenFile.PathFor(installed)), Path.GetDirectoryName(SeenFile.PathFor(data.Path)));
    }

    [Fact]
    public void The_release_command_is_only_ever_the_installed_service_in_Program_Files()
    {
        Assert.Equal(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RCEGuard", "RCEGuard.Service.exe"),
            ReleaseAction.ServiceExe);
    }
}
