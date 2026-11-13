# RCEGuard

A watchdog for *World of Warcraft* 3.3.5a clients on private servers. It observes the client
**from the outside** and reports behaviour that points to remote code execution: the client
starting a process, talking to unknown hosts, writing autostart entries and so on.

RCEGuard never touches the game process: no injection, no hooks, no patching, no memory
reading. It only uses operating system mechanisms (Sysmon, later Windows Firewall and
Exploit Protection). It is not an antivirus and does not protect against attackers who already
have admin or kernel rights.

The full concept (German) is in [docs/KONZEPT.md](docs/KONZEPT.md). Working title; the project
started under the name WowGuard.

## Status

| Milestone | Content | State |
| :--- | :--- | :--- |
| M1 | Sensor: Sysmon configuration, install and uninstall scripts, simulator | done; install (including the cleanup after a failed manifest registration), uninstall and all simulator scenarios verified with Sysmon 15.22. Not yet verified against the real Sysmon: the second install attempt after a failure in the same run, and the removal of the leftover `C:\Windows\Sysmon64.exe` on uninstall |
| M2 | Service and rule engine (R1–R6, R9), SQLite log | rule engine done and tested; service runs in a console. Acceptance test against Sysmon 15.22 passed on 2026-11-12: all simulator scenarios detected within 0.6–1.1 s of the log entry, the critical ones terminated. Installed as a Windows service (LocalSystem) the same test passed too, including the registration checks, the restart by Windows after the service process was ended, and terminating the program an exited child left behind. The build that saves its position in the Sysmon log passed the same test as installed service on 2026-11-12 21:59: all seven scenarios (0.1–1.1 s), among them `repeat` (three connections: one report, two counted), and all service checks, including the restart by Windows (after 62 s, from the third failure of a day on it takes that long) and the program started while the service was down (found 61 s later, right after the restart, child and client terminated). Two earlier runs of that day failed and were corrected: a first build received no event written after its start (wrong kind of subscription), and the test script counted old findings the service read at its start; see `docs/KONZEPT.md` section 14. After three reboots (2026-11-12 and 13, two of them for Windows updates, one cold start) the service started by itself 10–12 s after the kernel, continued in the Sysmon log where it had stopped, and then detected and terminated a simulator scenario within 0.8 s. Installing and removing again was checked on 2026-11-13 by comparing the machine before and after: after `uninstall.ps1` nothing of the installation was left (service, Program Files folder, data folder, Sysmon with its driver, event publisher and event log file, the note that the Sysinternals licence was accepted, the registrations of the service as a source of the Windows Application log). What stays are the entries the service wrote to the Application log. A service that cannot start is removed again: `scripts\install-test.ps1` showed that on 2026-11-13 for a service build with a missing file and for a configuration that is not valid JSON (service, folder and event sources gone, sensor still there, nothing restarted by Windows), and a normal installation worked right after. **The same run ended with a half-removed Sysmon:** the Sysmon service crashed while `sysmon -u` was uninstalling it. A second `sysmon -u` could not finish the job either: the service that was left is protected by Windows and can only be removed by itself. `uninstall.ps1` now checks on the machine whether Sysmon is gone, tries once more, and for this dead end has the switch `-RemoveStuckSysmonService`. That way out worked on the test machine on 2026-11-14 (switch, restart of Windows, `uninstall.ps1` again): nothing of RCEGuard and Sysmon was left. Right after that `install-test.ps1` passed completely (2026-11-14 00:24, 21 of 21 checks): both failed starts, the installation without a fault, and the removal, this time without a crash of Sysmon. **Not yet verified:** the service after the machine wakes from hibernation. **Known gap in the sensor:** Sysmon often does not record a connection of a client that ends within a few seconds, see "Running the guard". Toast moved to M4 |
| M3 | Prevention: firewall profiles, Exploit Protection, kill switch | open |
| M4 | Tray UI, toast, ntfy, heartbeat | open |
| M5 | Learning mode, R7, R8 | open |

Right now the guard evaluates events, terminates the client on critical findings and writes every
finding to a database and a log file. It can be installed as a Windows service. It does not notify
anyone yet, and nothing is blocked in advance.

## Requirements

- Windows 10/11 x64
- .NET 8 SDK (to build the simulator)
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) 15.0 or newer from
  Microsoft (the configuration uses schema 4.90). It is not part of this repository;
  `install.ps1` can download it from Microsoft for you.
- Admin rights for installing, uninstalling and reading the Sysmon log
- About 75 MB in `C:\Program Files\RCEGuard` for the service with its own .NET runtime

## Trying the sensor with the simulator

The simulator is a small console program that runs as `Wow.exe` and triggers one suspicious
behaviour per switch. Everything it does is harmless and undone before it exits.

Build it and copy it to a test folder:

```powershell
.\build.ps1
dotnet publish src\RCEGuard.FakeWow -c Release -o C:\RCEGuardTest
```

Install only the sensor for that test client, in a PowerShell **started as administrator**:

```powershell
.\scripts\install.ps1 -ClientPath C:\RCEGuardTest\Wow.exe -SkipService -DownloadSysmon -AcceptSysmonEula
```

Watch the events in the admin window:

```powershell
.\scripts\show-events.ps1 -Follow
```

Trigger scenarios from a normal window:

```powershell
C:\RCEGuardTest\Wow.exe --spawn
```

| Switch | What it does | Expected event |
| :--- | :--- | :--- |
| `--spawn` | starts `cmd.exe /c echo` | id 1, rule `R1` |
| `--connect [host:port]` | opens a TCP connection (default `1.1.1.1:443`) | id 3, rule `R2` |
| `--drop` | creates and deletes `%APPDATA%\rceguard-test.exe` | id 11, rule `R3` |
| `--runkey` | sets and removes an `HKCU\...\Run` value | id 13 (set) and id 12 (delete), rule `R4` |
| `--cpu [seconds]` | full load on all cores | none (R8 is polled by the service, M5) |
| `--miner-args` | starts a child with `stratum+tcp://` in its arguments | id 1, rule `R1` (Sysmon names only the first matching rule) |
| `--detach` | starts a child that starts a waiting program and exits at once; the program runs on for about 5 s | id 1, rule `R1` for the child only (Sysmon does not report what the child starts) |

Add `--repeat [count]` (default 3) to run a scenario several times in the same process, for
example `--connect --repeat 3`: the guard should report the alert once and count the rest.

Every child process also produces an id 10 event (rule `R7`, the client holds a handle to its
child) and an id 13 event for a Windows bookkeeping key under `Services\bam`. Both are expected.

Save the recorded events as XML, for example as raw material for test fixtures:

```powershell
.\scripts\show-events.ps1 -Last 200 -OutFile out\events.xml
```

`-Id` limits both the display and the saved file to some event ids, for example `-Id 3` for
network connections.

## Running the guard

`RCEGuard.Service` reads the Sysmon log, applies the rules and acts on the findings.

### As a Windows service

Publish the service (no admin rights needed), then install sensor and service in a PowerShell
**started as administrator**:

```powershell
.\build.ps1 -Publish
```

```powershell
.\scripts\install.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -DownloadSysmon -AcceptSysmonEula
```

`install.ps1` copies the published service to `C:\Program Files\RCEGuard` and registers it as the
Windows service `RCEGuard`:

- it runs as `LocalSystem` and starts with Windows, after Sysmon (it depends on the Sysmon service);
- Windows restarts it if its process ends unexpectedly (after 5 s, from the third failure on after 60 s);
- it only ever starts from Program Files, where a normal user cannot change its files;
- it writes its log to `C:\ProgramData\RCEGuard\guard.log` and its findings to `findings.db` in
  the same folder. Normal users can read that folder but not write to it;
- its warnings and findings also go to the Windows Application log (source `RCEGuard.Service`;
  starts and stops of the service under source `RCEGuard`). That comes with the .NET service
  host and was not a decision; whether it stays is open. Every local user can read that log;
- it notes the last event it handled in `sysmon-position.json` there and, when it starts again,
  first reads what Sysmon recorded in the meantime (see "After a restart").

The published service brings its own .NET runtime (about 75 MB), so it does not depend on a
runtime installed in a user profile. Running `install.ps1` again updates the service and points it
at another client; `-SkipService` installs only the sensor.

Stopping the Sysmon service also stops RCEGuard, because the guard depends on it.

### In a console

For development, start the build output in an administrator PowerShell instead (not while the
Windows service is running: two guards would both act on every event):

```powershell
.\src\RCEGuard.Service\bin\Release\net8.0-windows\RCEGuard.Service.exe
```

| Option | Effect |
| :--- | :--- |
| `--dry-run` | report findings, terminate nothing |
| `--config <file>` | configuration file, default `C:\ProgramData\RCEGuard\appsettings.json` |
| `--data-dir <folder>` | data folder, default `C:\ProgramData\RCEGuard` |
| `--replay <file>` | evaluate a saved events file instead of the live log, then exit; never terminates anything, needs no admin rights |

Without `appsettings.json` the client the sensor was installed for is the only profile, with an
empty allowlist: every connection of the client is then an R2 alert. A configuration looks like
this (`killOnUnknownRemote`, `killEnabled` and `repeatWindowSeconds` are optional; the values
shown for the last two are the defaults):

```json
{
  "killEnabled": true,
  "repeatWindowSeconds": 300,
  "profiles": [
    {
      "name": "Warmane",
      "clientPath": "D:\\Games\\Warmane\\Wow.exe",
      "allowedRemote": ["203.0.113.0/24"],
      "allowedHostnames": ["logon.example.org"],
      "killOnUnknownRemote": false
    }
  ]
}
```

What the rules do:

| Rule | Trigger | Severity | Action |
| :--- | :--- | :--- | :--- |
| R1 | the client starts any program | critical | terminate child and client |
| R1 | Windows attaches a console host (`conhost.exe`) to the client | medium | log |
| R2 | connection to an address that is not allowed (loopback is always allowed) | critical | alert; terminate only with `killOnUnknownRemote` |
| R3 | program file created anywhere, or any file in a Startup folder | high | alert |
| R3 | other file outside the game folder | medium | log |
| R4 | autostart, Winlogon, debugger hijack or service configuration written | critical | terminate client |
| R4 | such an entry removed / other write below `Services` | medium / info | log |
| R5 | unsigned module loaded from a user-writable folder outside the game folder | high | alert |
| R5 | unsigned module loaded from elsewhere outside the game folder | medium | log |
| R6 | the client starts a thread in another program | critical | terminate client |
| R7 | the client opens another program (not its own child) | medium | log |
| R9 | miner-like command line in a child of the client | critical | terminate child and client |
| R9 | miner-like command line in an unrelated process | critical | alert only: a string match is no reason to kill a process that is not tied to the client |

A process is only terminated if its pid still runs the program the event named. Findings go to
`findings.db` (SQLite) in the data folder. "Alert" currently means a line in the console; the
notification itself comes with the tray app in M4, because a service cannot show toasts.

**What a child leaves behind.** Sysmon only reports the programs the client starts itself, not
what those start. When the guard terminates a child that is still running, everything below it
goes with it. If the child has already exited by then (`cmd /c start payload` takes
milliseconds, the guard about a second), the guard looks for running programs that name the
child as their parent and were started after it, and terminates them with everything below
them. Limits: a program that was started by such a left-behind program which has itself exited
is not found, and neither is one whose parent was forged.

**After a restart.** The guard saves its position in the Sysmon log (at once after a finding,
otherwise once a second). When it starts again, after a crash, an update or a reboot, it first
reads the events written while it was not running; their findings carry the note "written while
RCEGuard was not running" in the log. Such an event can be old, so two extra checks apply before
anything is terminated: the process must have been started before the event (a pid that runs the
same program again in a newer process is left alone), and programs left behind by an exited
child are only searched for if the event is at most 30 seconds old. The very first start reads
nothing old. If the Sysmon log was cleared or replaced in the meantime, everything in it is
read; if events were overwritten before the guard could read them, it says how many. The rule
engine starts empty after a restart: what it knew about running children is gone.

**If the log goes quiet for the guard only.** A guard that is given no events watches nothing and
looks healthy. So a guard that has received nothing for 15 seconds looks into the log itself. If
an event has been there for more than 15 seconds without being delivered, the guard writes
"RCEGuard cannot run" with the record ids to its log and ends; Windows then restarts the service,
and the start reads what was missed.

**Repeated alerts.** The same alert (same rule, client process and target) is reported once
and then only counted for `repeatWindowSeconds`; the count is stored with the finding. Findings
that terminate a process are never held back.

The console host is only recognised in its exact form: `conhost.exe` from the Windows system
folder, started with nothing but a console handle on its command line. Windows starts it that way
for every console program that gets its own console. `conhost.exe` with any other arguments (it
can start other programs) is an ordinary R1.

Findings arrive 0.6 to 1.1 seconds after the log entry (measured in the acceptance test), because
Windows delivers log entries in batches. A child process therefore runs for about a second before it is terminated; stopping it
from starting at all is the job of M3.

**Connections (R2) are slower and can be missed.** Sysmon writes a network connection to its log
1.3 to 2.9 seconds after the connection was made (38 recorded events, 2.0 s on average), so an
R2 finding comes about 2 to 4 seconds after the connection; the "ms after the event" in the log
line counts from the log entry and does not show this. In tests on 2026-11-12 Sysmon did not
record a connection at all when the client ended soon afterwards: never when it ended within a
second (6 of 6 missing), in 2 of 6 runs when it lived 3 more seconds, always when it lived
8 seconds (4 of 4 recorded). The service is not the cause: it reported every connection event
Sysmon wrote (25 of 25). Sysmon is known to name the program of a connection as
`<unknown process>` when it can no longer look the process up; such an event does not match the
rule that selects the client, which would explain the gap, but this is not confirmed. The game
client itself runs for a long time, so its own connections are not affected; a short connection
right before the client ends may be. Blocking unknown addresses in advance is the job of the
firewall rules in M3.

The guard stops with an error instead of idling if it cannot read the Sysmon log.

### Acceptance test

Runs seven simulator scenarios against the running guard and checks that each one is detected
within 2 s of its log entry, that the critical ones are terminated, that a program left behind
by an exited child is gone (`detach`) and that three identical connections of one client are
reported once (`repeat`). In an administrator PowerShell, after
`.\build.ps1` and publishing the simulator:

```powershell
.\scripts\acceptance-test.ps1 -DownloadSysmon -AcceptSysmonEula
```

It installs the sensor for the test client if needed, starts a console instance of the guard for
the duration of the test and writes `out\m2-result.txt`, `out\m2-service.log` and the recorded
events as `out\m2-events.xml`.

To test the installed Windows service instead (after `.\build.ps1 -Publish`):

```powershell
.\scripts\acceptance-test.ps1 -InstalledService
```

This installs sensor and service for the test client, runs the same scenarios against the service,
checks how the service is registered (folder, account, start type, dependency) and ends the
service process once to see whether Windows restarts it. While the service is down, the client
starts a program; the restarted service must find that in the log and terminate the client.
Windows restarts the service after 5 s only the first two times within a day; from the third run
of this test on a day the restart takes 60 s, and the test waits for it. The
service stays installed for the test
client afterwards. The simulator switch `--hold [seconds]` used by the test keeps the client
(and for `--spawn` its child) alive, so the guard has something to terminate; a client that
survives exits with code 3.

### Install test

```powershell
.\scripts\install-test.ps1
```

Run in an administrator PowerShell on a machine **without** RCEGuard and without Sysmon (the test
removes both at the end, so it refuses to start otherwise). It installs three times and removes
once:

1. with a published service that lacks a file, so its process dies at once;
2. with a configuration file (`appsettings.json`) that is not valid JSON, so the service starts,
   reports that it cannot run, and ends;
3. without a fault: the service must run;
4. `uninstall.ps1`: the machine must look as it did before the test.

After 1 and 2 `install.ps1` must have failed with the reason, the service with its folder and its
event sources must be gone, the sensor must still be installed, and nothing may come back within
8 s: Windows restarts a failed service, and a service that cannot run would be started over and
over. The result goes to `out\install-test-result.txt`.

To only see what of an installation is on a machine (no admin rights needed, changes nothing):

```powershell
.\scripts\install-test.ps1 -ListOnly
```

## Monitoring the real client

To monitor the real client instead, run `install.ps1` again with its path, for example
`-ClientPath 'D:\Games\Warmane\Wow.exe'`.

Remove everything again:

```powershell
.\scripts\uninstall.ps1
```

This removes the service with its folder in Program Files and its registrations as a source of
the Application log, uninstalls Sysmon if RCEGuard installed it, and deletes the data folder
(log, findings, configuration). `sysmon -u` itself leaves two things behind, which the script
removes if this installation brought them: the file of Sysmon's event log with everything it
recorded (`C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`) and the
note in the registry of the installing user that the Sysinternals licence was accepted. With
`-KeepData` the data folder and that log file stay. **What stays in any case:** the entries the
service wrote to the Windows Application log; Windows keeps that log, and single entries cannot
be taken out of it.

`sysmon -u` can fail half way (seen once with Sysmon 15.22: its service crashed during the
uninstall and stayed registered without driver and event publisher). So `uninstall.ps1` does not
go by Sysmon's exit code: it looks whether service, driver and event publisher are gone, and if
not, runs `sysmon -u` once more. If something is still there after that, it stops with the
output of both attempts and removes nothing else, so that running it again after a restart of
Windows can finish the job. The reason is also written to `C:\ProgramData\RCEGuard\uninstall.log`.

**If only the Sysmon service is left** (stopped, without driver and event publisher), no second
attempt helps. Since version 15 the Sysmon service is a protected service: Windows lets only the
running service itself take that protection off and refuses everyone else who wants to delete it
("Access is denied", exit code 5), administrators included. A service that ended before it got
there is stuck. `uninstall.ps1` says so and names the way out, which it only takes when asked:

```powershell
.\scripts\uninstall.ps1 -RemoveStuckSysmonService   # deletes the registration of the service from the registry
# restart Windows ("Restart", not "Shut down")
.\scripts\uninstall.ps1                             # removes the rest
```

The switch deletes `HKLM\SYSTEM\CurrentControlSet\Services\<Sysmon service>` and nothing else,
and only if the service is stopped, protected, and its driver and event publisher are gone.
Windows reads its services from the registry when it starts, so the service is gone after the
restart. That is how the half-removed Sysmon of 2026-11-13 was cleared on the test machine: after
the restart Windows did not list the service any more and reported no error about it, and the
second `uninstall.ps1` removed the binary, Sysmon's log file, the licence note and the data folder.
Nothing was left after that, also not the entry Windows keeps for the event channel of Sysmon
(`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Microsoft-Windows-Sysmon-Operational`):
it is there while Sysmon is installed and `sysmon -u` removes it. `install-test.ps1` counts it as
part of an installation.

## If Sysmon is already installed

Sysmon has a single configuration per machine. `install.ps1` stops if it finds a Sysmon that
RCEGuard did not install, because loading the RCEGuard configuration would replace your rules.
Either merge the rendered configuration into your own, or pass `-ReplaceExistingConfig`. To
look at the configuration without installing anything (no admin rights needed):

```powershell
.\scripts\render-config.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -OutFile out\rceguard.rendered.xml
```

## If installing Sysmon fails

Sysmon 15 sometimes cannot register its event manifest on recent Windows builds. The output then
ends with `wevtutil.exe returned failure` and `Event manifest installation failed` (exit code 13),
and a half-registered event publisher stays behind. `install.ps1` handles this: it removes such
leftovers (`sysmon -u force`), tries once more, and removes everything again if the second attempt
fails too. In that case restart Windows and run the script again.

`install.ps1` never forces an uninstall while a Sysmon service or the driver `SysmonDrv` is
present.

## What the sensor records

Only events caused by the configured client, plus process starts anywhere whose command line
looks like a coin miner:

| Sysmon event | Scope | Rule |
| :--- | :--- | :--- |
| 1 ProcessCreate | children of the client, client start, miner-like command lines | R1, R9 |
| 3 NetworkConnect | every outbound connection of the client | R2 |
| 5 ProcessTerminate | client exit | – |
| 7 ImageLoad | modules loaded into the client | R5 |
| 8 CreateRemoteThread | client starts a thread in another process | R6 |
| 10 ProcessAccess | client opens another process | R7 |
| 11 FileCreate | files the client creates outside its data folders | R3 |
| 12–14 RegistryEvent | registry writes of the client | R4 |
| 22 DnsQuery | DNS queries of the client | – |

Differences to the concept, on purpose: the game folder itself is not treated as safe for R3,
only the data folders `Cache`, `WTF`, `Logs`, `Interface`, `Screenshots` and `Errors`. A DLL
dropped next to the client would otherwise go unnoticed. Sysmon can only filter on the direct
parent, so it does not record what the children of the client start; the service finds those
programs itself when it terminates a child (see "What a child leaves behind").

## Repository layout

```text
docs/KONZEPT.md                        concept and milestones (German)
sysmon/rceguard-sysmon.template.xml    Sysmon configuration template
scripts/render-config.ps1              renders the template for one client (no admin)
scripts/install.ps1                    installs Sysmon / loads the configuration (admin)
scripts/uninstall.ps1                  removes service and sensor again (admin)
scripts/SysmonTools.ps1                shared Sysmon helpers of the two scripts above
scripts/GuardServiceTools.ps1          shared helpers for the RCEGuard Windows service
scripts/show-events.ps1                prints or saves recorded events (admin)
scripts/acceptance-test.ps1            simulator scenarios against the running guard (admin)
scripts/install-test.ps1               install with a service that cannot start, uninstall, look for leftovers (admin; -ListOnly without)
src/RCEGuard.Core/                     rule engine, event parser, configuration (no OS dependencies)
src/RCEGuard.Service/                  guard: Sysmon log reader, actions, findings database
src/RCEGuard.FakeWow/                  simulator, builds as Wow.exe
tests/RCEGuard.Core.Tests/             unit tests, with recorded Sysmon events as fixtures
tests/RCEGuard.Service.Tests/          process killer against real, harmless processes; resuming in real Windows logs (read only; for new events the tests start Windows PowerShell)
build.ps1                              build wrapper that insists on a real .NET SDK; -Publish for the service
```

## License

MIT, see [LICENSE](LICENSE).
