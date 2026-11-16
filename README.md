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
| M3 | Prevention: firewall profiles, Exploit Protection, kill switch | built and accepted with the simulator; **not tried with a real client**. Built: the service writes one block rule per profile to Windows Firewall (`"firewall": true`), locks a profile down after a finding that terminates its client (`"lockdown": true`) and ends a lockdown with `RCEGuard.Service.exe --release`; `uninstall.ps1` removes the rules. Both switches are off by default. `scripts\prevention-test.ps1` passed on the installed service on 2026-11-15 (20 of 20 checks): Windows Firewall took the rule, the allowed address connected and the other one did not, the lockdown blocked everything and was still there after a restart of the service, `--release` ended it, and no rule was left at the end. **Seen in that run:** a connection the firewall blocks leaves no finding, see "Blocking in advance". Not verified: `uninstall.ps1` with rules in place; the real client. Exploit Protection: `install.ps1 -BlockChildProcesses` turns on "Do not allow child processes" for the client, `-AllowChildProcesses` takes it back. Checked with the simulator on 2026-11-15 15:56 as part of `prevention-test.ps1` (27 of 27 checks): Windows refused when the simulator started a program, and after taking the setting back no entry was left and the guard terminated the started program again. A first run that day failed at taking it back (the documented `Set-ProcessMitigation -Remove -Disable` reported no error and changed nothing) and led to the scripts reading every change back and removing their own entry from the registry. `uninstall.ps1` takes the setting back too: `install-test.ps1` passed completely on 2026-11-15 15:58 (23 of 23 checks) with an installation that had it on; afterwards nothing of the installation was on the machine. Not verified: the real client with the setting. Plan and decisions: `docs/KONZEPT.md` section 15 |
| M4 | Tray UI, toast, ntfy, heartbeat | started. Built: the service sends findings that alert or terminate to an ntfy topic, and reports about itself (cannot run, was ended unexpectedly, stopped while the client runs); `RCEGuard.Service.exe --notify-test` sends a test message. Tested with a stand-in for the network, and the published service sent a real test message to a listener on the test machine. **Not yet run:** the installed service with a real ntfy server. Also built: the tray application (`RCEGuard.Tray`): an icon in the notification area that shows whether the guard runs, a window with the findings, a pop-up for new findings, and "Release" for a lockdown, which asks Windows for an administrator. It only reads what the service stores. Tested without its user interface; the window and the icons were drawn into pictures and looked at, and the application was started once for a few seconds. `install.ps1` installs it to `C:\Program Files\RCEGuard Tray`, lets Windows start it for every user at sign-in and starts it; `uninstall.ps1` removes it. `install-test.ps1` confirmed that on 2026-11-15 17:12 (25 of 25 checks): installed, registered, running without administrator rights although it was started from an administrator console, and gone after the uninstall. Next to the installed service it showed the findings of `prevention-test.ps1` as Windows notifications (2026-11-15 17:17, seen by the owner). In that run the Snipping Tool could not be used while the notifications came; why is not known (the Windows logs show nothing that RCEGuard blocked), and since then the pop-ups are bundled. The release from the window was checked with `scripts\tray-test.ps1` on 2026-11-15 17:38 (9 of 9 checks; the owner clicked "Release ..." and confirmed the administrator question, the script checked): the lockdown ended, the release command had been started by the tray application, no firewall rule was left, the running service noticed 6 s later, and the test client started again. **Not yet done:** the start at sign-in; the real client. Plan and decisions: `docs/KONZEPT.md` section 16 |
| - | Client file: check and optional patch | built on 2026-11-16 by the owner's decision (the concept had kept patching outside the project). RCEGuard says when the client file has a section that is both writable and executable (at the end of `install.ps1` and on request with `--check-client`; a standing warning in `guard.log` and in the tray window was taken out again the same day), and `scripts\patch-client.ps1` takes the execute right away from the client's `.zdata` section or gives it back. Tested on made-up files and on a copy of a real client in a temp folder, in PowerShell 7 and 5.1 (26 checks: the patched copy differs in exactly one byte, undo gives back the identical file, six kinds of unexpected files are left alone). **Tried once with a real client (2026-11-16):** the patched copy starts and shows the login screen, and crashes right after the password is entered, twice in two tries, with an access violation at the first address of `.zdata`. The crash report shows code that was loaded at run time (it belongs to no file) calling into that section: on that server, logging in involves running code there, so **the patched client cannot be used on that server**. Whether the patch stops an exploit is still not known. See "Patching the client" |
| M5 | Learning mode, R7, R8 | started. Built: learning mode for a profile (`"learning": true`): for that client nothing is terminated, locked down or blocked by the firewall rule of the profile, a connection to an address that is not on the allowlist is noted instead of alerted, and the service collects where the client connects to, which host names it asks for, where it creates files outside the game folder and which other programs it opens. `RCEGuard.Service.exe --learned` shows the notes and suggests what to add to the allowlist; nothing is taken over automatically. Tested with unit tests and by replaying the events of the M2 acceptance run through the built service. Also built: R7 judges what the access rights allow. Opening another program with rights to change it (write its memory, start threads in it) is an alert, reading its memory a log entry, anything less an info entry; programs on `allowedProcessAccess` may be looked at without an entry, and the learning mode suggests that list too. The simulator has `--open-process` for it; the real Sysmon recorded its three variants with exactly the rights asked for (2026-11-15, seen through the installed service of the previous build). **Not yet run:** the installed service in learning mode and with the new R7; a name service event of the real Sysmon (the notes read it from the documented format); the real client, so nobody knows yet which programs it opens and with which rights. Also built: R8. The service measures the processor time of every running client (from the process list of Windows, without opening the client) and alerts when a client keeps more than `cpuAlertCores` cores (default 2.0) busy on average over `cpuAlertSeconds` (default 300); whether the client is in the foreground is not looked at. Tested with made-up processor times in the guard loop, and the reading of the process list against this machine. **Not yet run:** R8 on the installed service with the simulator's `--cpu`; how many cores the real client keeps busy is not known, the default is an assumption. `scripts\learning-test.ps1` checks all of this on the installed service. First run on 2026-11-15 20:08: 19 of 23 checks passed. Passed on the installed service: nothing terminated or locked down while learning, R1, R3, R7 (read: log, rights to change: alert) and R8 (13.1 cores over 10 s) reported, the Explorer suggested for `allowedProcessAccess`, and after learning an unknown address alerted and a started program was terminated again. **Failed, all four for one reason outside the guard:** Sysmon recorded neither of the two connections of the learning part (4 s and 12 s after it had loaded its configuration; each client stayed alive for 8 s), so there was nothing to note or suggest; later in the same run it recorded all three. Why is not known. The name query of that run was recorded, and replaying the run's events shows that the notes read it correctly and suggest the name. The test now asks Sysmon after every connection whether it recorded it, tries up to three times and lists what was missed. Second run on 2026-11-15 20:24: 23 of 24 checks passed. Learning worked from end to end on the installed service: both connections noted, the host name suggested as a name and the address as an address, and after the suggestion was taken over the learned address connected without a finding. **The one failed check is the sensor again:** Sysmon recorded only 4 of the 9 connections of that run, and none of the three tries for the host name after learning. The misses do not follow the loading of its configuration (the two connections right after it were recorded this time). **So the known gap is larger than measured before: about half of the connections of a client that lives 8 seconds were missing.** A measurement of its own followed (`scripts\sensor-probe.ps1`, 2026-11-15 20:38): of ten connections closed at once Sysmon recorded nine, of ten connections kept open for 8 s it recorded eight. **Keeping the connection open does not close the gap**; the guard reported every connection Sysmon recorded (17 of 17). The cause is not known. **Built against it:** the service also reads the connection table of Windows for every running client and takes from it what Sysmon did not record, once a connection has been open for 5 seconds; such a connection is judged and learned like a recorded one. Measured on the installed service on 2026-11-15 21:53 (`scripts\sensor-probe.ps1`): of ten connections kept open Sysmon recorded seven, and the guard saw all ten, three of them through the table, 7 to 9 seconds after the client had started; nothing was reported twice. Of ten connections closed at once Sysmon recorded nine and the guard saw those nine: a connection that is closed again within those seconds still depends on Sysmon alone. The tray application shows learning mode: a blue shield with a ring, a headline that says the client is watched, not protected, and per learning profile a button that shows what was learned, with the suggestion. Tested without the user interface, and the window and the icon were drawn into pictures and looked at; **not yet seen next to the installed service.** Taking the suggestion over stays an edit of `appsettings.json` as administrator. **Still open in M5:** a full session with the real client. `install.ps1 -Learning` sets it up; it ran as administrator on 2026-11-15 22:26 and the real client was then started once, for about two and a half minutes (start, login, realm): no finding alerted. Right after its start the client opened 36 other running programs with the right to read their memory (R7, logged; what the concept expected of an anti-cheat scan), it made four connections, two of which Sysmon did not record and the guard took from the connection table, and three of the four addresses had been asked for by name. A configuration taken from that start (three host names, one address, learning off, `killEnabled: false`) then ran for two real play sessions on 2026-11-16, about 25 minutes together: **no finding alerted**, no connection went to an address outside the allowlist, R8 did not report, and the client had used 0.98 processor cores on average over the 13 minutes of the second session (read from the process list of Windows), against the 2.0 cores R8 reports above. Still open: the two hours of normal play the concept asks for, and turning `killEnabled` on. Plan and decisions: `docs/KONZEPT.md` section 17 |

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
- About 75 MB in `C:\Program Files\RCEGuard` for the service and about 160 MB in
  `C:\Program Files\RCEGuard Tray` for the tray application, each with its own .NET runtime

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
| `--connect [host:port]` | opens a TCP connection (default `1.1.1.1:443`) and closes it at once; with `--keep-open` (and `--hold`) it stays open until the process ends | id 3, rule `R2` |
| `--drop` | creates and deletes `%APPDATA%\rceguard-test.exe` | id 11, rule `R3` |
| `--runkey` | sets and removes an `HKCU\...\Run` value | id 13 (set) and id 12 (delete), rule `R4` |
| `--cpu [seconds]` | full load on all cores (default 300 s) | none: R8 is not an event, the service measures the processor time of the client |
| `--miner-args` | starts a child with `stratum+tcp://` in its arguments | id 1, rule `R1` (Sysmon names only the first matching rule) |
| `--detach` | starts a child that starts a waiting program and exits at once; the program runs on for about 5 s | id 1, rule `R1` for the child only (Sysmon does not report what the child starts) |
| `--open-process [query/read/write]` | asks Windows for a handle to the Explorer of the session with rights to ask about it (`0x1000`), to read its memory (`0x1010`, default) or to write it and start threads (`0x102a`), and closes the handle again; nothing is read or written | id 10, rule `R7` |

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
| `--release [profile]` | end the lockdown of that profile (without a name: of every profile), then exit; see "Blocking in advance" |
| `--notify-test` | send a test notification to the configured ntfy topic, then exit; needs no admin rights; see "Notifications" |
| `--check-client [file]` | say whether that program file (without a file: the client of every profile) has a section that is both writable and executable, then exit; only reads the file, needs no admin rights; see "Patching the client" |
| `--learned [profile]` | show what the learning mode noted for that profile (without a name: for every profile) and what it suggests for the allowlist, then exit; changes nothing, needs no admin rights; see "Learning mode" |

Without `appsettings.json` the client the sensor was installed for is the only profile, with an
empty allowlist: every connection of the client is then an R2 alert. A configuration looks like
this (everything except `name` and `clientPath` is optional; the values shown for
`killEnabled`, `repeatWindowSeconds`, `lockdown`, `cpuAlertCores`, `cpuAlertSeconds`,
`killOnUnknownRemote`, `firewall` and `learning` are the defaults; `allowedProcessAccess` takes full paths and is empty by default). Profile names must be unique and must not contain `|`:

```json
{
  "killEnabled": true,
  "repeatWindowSeconds": 300,
  "lockdown": false,
  "cpuAlertCores": 2.0,
  "cpuAlertSeconds": 300,
  "profiles": [
    {
      "name": "Warmane",
      "clientPath": "D:\\Games\\Warmane\\Wow.exe",
      "allowedRemote": ["203.0.113.0/24"],
      "allowedHostnames": ["logon.example.org"],
      "allowedProcessAccess": ["C:\\Windows\\explorer.exe"],
      "killOnUnknownRemote": false,
      "firewall": false,
      "learning": false
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
| R2 | the same while the profile is in learning mode | info | log |
| R3 | program file created anywhere, or any file in a Startup folder | high | alert |
| R3 | other file outside the game folder | medium | log |
| R4 | autostart, Winlogon, debugger hijack or service configuration written | critical | terminate client |
| R4 | such an entry removed / other write below `Services` | medium / info | log |
| R5 | unsigned module loaded from a user-writable folder outside the game folder | high | alert |
| R5 | unsigned module loaded from elsewhere outside the game folder | medium | log |
| R6 | the client starts a thread in another program | critical | terminate client |
| R7 | the client opens another program (not its own child) with rights to change it: write its memory, change its memory protection or start threads in it ("all access" includes that), or with rights that cannot be read | high | alert, also for a program on `allowedProcessAccess` |
| R7 | the client opens another program to read its memory | medium | log; nothing for a program on `allowedProcessAccess` |
| R7 | the client opens another program for less (ask about it, wait for it) | info | log; nothing for a program on `allowedProcessAccess` |
| R8 | a client keeps more than `cpuAlertCores` processor cores busy on average over `cpuAlertSeconds` (1.0 = one core fully busy; `"cpuAlertCores": 0` turns the rule off) | medium | alert, once per stretch of high load |
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
8 seconds (4 of 4 recorded). On 2026-11-15 two connections of clients that lived 8 seconds were
missing as well, and in a second run 5 of 9 (in the first run the two right after Sysmon had
loaded its configuration, in the second run those two were recorded and later ones were not),
so staying alive is no guarantee either. Keeping the connection open does not help: measured
on 2026-11-15 with `scripts\sensor-probe.ps1`, Sysmon recorded 9 of 10 connections that were
closed at once and 8 of 10 that stayed open for the 8 seconds the client lived. The misses come
in clusters (two or more connections in a row, then none for a while).

**The connection table of Windows as a second source.** Because of this gap the service does
not rely on Sysmon alone. While a client runs, it reads the TCP connection table of Windows
every 2 seconds (what `netstat -o` shows: every connection with the process that owns it; the
client is not opened for this). A connection of the client that has been in the table for
5 seconds without an event of Sysmon counts as missed by Sysmon: the service says so in its log
("found in the connection table of Windows; Sysmon did not record it") and then judges and
learns it exactly like a recorded one. Sysmon gets those 5 seconds because it writes its event
up to 3 seconds late; a connection it did record is not reported a second time. What remains:
a connection that is closed again within about 5 to 7 seconds is only seen if Sysmon records
it, and a client that was already running when the service started is not looked at until it
is started again. The firewall rule of a profile depends on neither source. Measured on the
installed service on 2026-11-15: Sysmon recorded 7 of 10 connections that stayed open, the guard
saw 10 of 10. The service is not the cause: it reported every connection event
Sysmon wrote (25 of 25). Sysmon is known to name the program of a connection as
`<unknown process>` when it can no longer look the process up; such an event does not match the
rule that selects the client, which would explain the gap, but this is not confirmed. The game
client itself runs for a long time, so its own connections are not affected; a short connection
right before the client ends may be. Blocking unknown addresses in advance is the job of the
firewall rules in M3.

The guard stops with an error instead of idling if it cannot read the Sysmon log.

### Notifications (ntfy)

Without this the findings are only in `guard.log` and `findings.db`. With an
[ntfy](https://ntfy.sh) topic in the configuration the service also sends them to your phone:

```json
{
  "notify": { "ntfy": { "url": "https://ntfy.example.org/my-topic", "token": "tk_..." } },
  "profiles": [ { "name": "Warmane", "clientPath": "D:\\Games\\Warmane\\Wow.exe" } ]
}
```

`token` is only needed if the server asks for one; `"enabled": false` turns the entry off
without deleting it. Then, as any user:

```powershell
& 'C:\Program Files\RCEGuard\RCEGuard.Service.exe' --notify-test
```

It sends one test message and says whether the server took it. The service reads the
configuration when it starts, so restart it (or run `install.ps1` again) after changing it.

What is sent:

- every finding that alerts or terminates (severity high or critical), with the rule, the
  summary, what the guard did, the time and the name of the computer. Findings that are only
  logged are not sent, and a repeated alert is sent as often as it is reported, not as often as
  it happens (see "Repeated alerts");
- "RCEGuard cannot run", with the reason, before the guard ends because it cannot do its work;
- "RCEGuard was ended unexpectedly" at the next start, if the guard was not stopped the regular
  way (ended from outside, crashed, power lost). A guard that is ended like that cannot report
  it itself; it leaves a note in the data folder while it runs and finds it again;
- "RCEGuard is stopping while the client runs", if the service is stopped while a program with
  the name of a watched client is running.

What to know:

- **The message leaves the machine.** It names programs, files and addresses, which can
  contain your Windows user name, and the computer name. Use a server and a topic you trust. On
  a public server such as ntfy.sh everyone who knows the topic name can read along.
- **Every user of this PC can read the configuration**, the topic address and the token
  included (the data folder is readable for all, so that the tray application can show the
  findings). Someone with that can send messages to the topic. Use a token that may only
  publish to this one topic.
- The log names the server, never the topic or the token.
- A message that cannot be delivered is tried three times and then given up; the log says so
  once per outage and counts the rest. At most 100 messages wait at a time; when more pile up,
  the oldest are dropped. The findings themselves are always in the log and the database.
- Nothing is sent that tells you the guard is alive. If the service is disabled or removed by
  someone with administrator rights, no message comes.

### Tray application

`RCEGuard.Tray.exe` puts a shield into the notification area, next to the clock. It runs as the
logged-on user, needs no administrator rights and watches nothing itself: it reads what the
service stores in `C:\ProgramData\RCEGuard` (readable for every user) and asks Windows whether
the service runs.

`install.ps1` installs it with the service: it copies the published application
(`.\build.ps1 -Publish` writes it to `artifacts\tray`) to `C:\Program Files\RCEGuard Tray`,
registers it under `HKLM\...\CurrentVersion\Run` so that Windows starts it for every user at
sign-in, and starts it at once. `-SkipTray` leaves it out. It is started through Explorer, so
that it does not inherit the administrator rights of the console `install.ps1` runs in. To look
at it without installing anything:

```powershell
.\src\RCEGuard.Tray\bin\Release\net8.0-windows\RCEGuard.Tray.exe --show
```

| Icon | Meaning |
| :--- | :--- |
| green shield with a tick | the service runs, nothing new |
| orange shield with an exclamation mark | findings that alerted or terminated and that you have not looked at; opening the window marks them as seen |
| red shield with a bar | a profile is in lockdown |
| blue shield with a ring | a profile is in learning mode: its client is watched, but nothing is terminated or blocked for it |
| grey shield with a cross | the service is not running or not installed: the client is not watched |

What counts most is shown: a service that is down before a lockdown, a lockdown before new
findings, new findings before learning mode. A double click opens the window: the state, the
profiles in lockdown with the finding that caused each, the profiles in learning mode, and the
newest 200 findings (those that were only logged are grey). Closing
the window leaves the icon; "Exit" in the menu of the icon ends the tray application, not the
service.

- **Pop-ups.** A new finding that alerted or terminated is shown as a Windows notification;
  several at once as one, naming the most serious. There is at most one pop-up in ten seconds:
  what arrives in between is announced together afterwards, while the icon and the list are up
  to date at once. What happened while the tray application was
  not running is announced at its next start. `"notify": { "toast": false }` in the
  configuration turns the pop-ups off; the icon still changes.
- **Releasing a lockdown.** "Release ..." next to a profile starts
  `C:\Program Files\RCEGuard\RCEGuard.Service.exe --release <profile>` with administrator
  rights: Windows asks for an administrator (User Account Control). The tray application cannot
  release by itself, on purpose: if it could, so could any program that runs as you.
- **Learning mode.** For every profile with `"learning": true` the window says how much was
  noted so far; "What was learned ..." shows the notes and the suggestion as text to read and
  copy, the same as `RCEGuard.Service.exe --learned`. Nothing is taken over from there: the
  allowlist is changed in `appsettings.json`, as administrator. The tray application reads the
  configuration file itself, so after an edit it shows what the file says, also before the
  service was restarted and uses it.
- It remembers the newest finding it told you about in
  `%LOCALAPPDATA%\RCEGuard\tray-state.txt` of your Windows user. `uninstall.ps1` removes that
  file for every user of the machine, together with the application and its start at sign-in.
- It uses about 90 MB of memory, about 120 MB with the window open (measured once each), most
  of it the user interface libraries of .NET.

### Blocking in advance (firewall and lockdown)

Everything above reacts after the fact. Two switches make Windows Firewall block connections of
the client before they happen. Both are off unless the configuration turns them on. Both were
checked with the simulator on the installed service (see "Prevention test"), not yet with the
real client.

**`"firewall": true` on a profile.** The service keeps one outbound block rule for the client in
Windows Firewall (name `RCEGuard: <profile>`, group `RCEGuard`). The rule names every address
except the entries of `allowedRemote`, the addresses `allowedHostnames` resolve to, and loopback.
Windows Firewall has no "allow only these": a block rule wins over every allow rule, and what no
rule blocks is allowed by default. RCEGuard therefore adds no allow rules and does not change the
default policy; if outbound connections are blocked by default on your machine, the client needs
an allow rule of its own.

- The profile needs at least one allowed address or host name; without, the configuration is rejected.
- Host names are resolved at the start and every 10 minutes (every 30 seconds while one fails).
  A server that moves to a new address is blocked until the next refresh. A host name that
  cannot be resolved keeps the addresses it had; one that never resolved has none, so its server
  is blocked.
- The rule stays in place while the service is stopped. It is written again at every start of
  the service, so a rule changed by hand does not last.
- If Windows Firewall is turned off for the network in use, or a group policy overrides local
  rules, the rule blocks nothing; the guard writes a warning to its log.
- Only the client's own program file is covered. A program the client starts is not (R1
  terminates it; keeping it from starting is what `-BlockChildProcesses` below is for).
- **A blocked connection is not reported.** In the prevention test Sysmon recorded the
  connections that went through and none of the two the firewall blocked, so there was no R2
  finding for them: with the firewall on, RCEGuard does not show that the client tried to reach
  an address that is not allowed. The simulator got the refusal at once ("access to a socket
  forbidden by its access permissions"), without a wait.

**`"lockdown": true` (kill switch).** After a finding that terminates the client, the profile is
locked down: its rule blocks every outbound connection of the client, also to the allowed
addresses, until someone releases it. The lockdown is noted in
`C:\ProgramData\RCEGuard\lockdown.json` and survives restarts of the service and of Windows.
It goes with terminating: with `"killEnabled": false` or `--dry-run` nothing is locked down, the
log line of the finding only says that it would have been. A profile does not need `firewall`
for this.

A locked client starts but cannot connect to anything. Why is in `guard.log` (the line of the
finding ends with "locked down") and in `lockdown.json`. To release, in a console **started as
administrator**:

```powershell
& 'C:\Program Files\RCEGuard\RCEGuard.Service.exe' --release
```

It prints since when and after which finding each profile was locked, ends the lockdown and puts
the rule back to what the configuration asks for (`--release <profile>` for one profile only).
Look at the finding first: the lockdown is there because the client did something it never does.
Until the tray application exists (M4), this command is the only way to release.

If `lockdown.json` cannot be read, every profile is treated as locked down until `--release`
replaces the file.

**`install.ps1 -BlockChildProcesses` (Exploit Protection).** Rule R1 terminates a program the
client started about a second after it started. With this switch Windows itself refuses the
start: `install.ps1` turns on the Exploit Protection setting "Do not allow child processes"
(`DisallowChildProcessCreation`) for the full path of the client. Checked with the simulator
on 2026-11-15: its attempt to start `cmd.exe` ended with "process creation was blocked", and
after `-AllowChildProcesses` nothing of the setting was left. Not tried with the real client.

```powershell
.\scripts\install.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -BlockChildProcesses
```

- It is off unless you ask for it, because it can break things a client does on purpose:
  opening a link in the browser, a crash reporter, a launcher or patcher that starts the game.
  Try your client with it (start, log in, patch) before relying on it. The concept names this as
  an open point; it has not been tried with a real client.
- It applies from the next start of the client and is kept by Windows, also while the RCEGuard
  service is stopped.
- **A console program cannot get a console of its own under this setting:** Windows also refuses
  the console host (`conhost.exe`), and the program ends before it runs (exit code 0xC0000142).
  In a console that is already open it runs. The game client is a window program and needs no
  console host; the simulator is a console program, so `prevention-test.ps1` runs it in its own
  console for this part.
- Once on, it stays on when `install.ps1` is run again without the switch, and moves along when
  `-ClientPath` changes. `install.ps1 -ClientPath ... -AllowChildProcesses` takes it back;
  `uninstall.ps1` does so too. "Back" means the value from before: not set, or forced off if it
  was. If the setting was already on before RCEGuard touched it, RCEGuard leaves it alone, also
  when uninstalling.
- Only this one setting is used. `ArbitraryCodeGuard` / `BlockDynamicCode` are never turned on:
  they would break Warden.
- A refused start is not a finding of RCEGuard: no program was started, so Sysmon records
  nothing. Windows logs it itself (log `Microsoft-Windows-Security-Mitigations/KernelMode`,
  event 4, with the program that was refused and its command line; seen for the simulator).
  RCEGuard does not read that log.
- Taking the setting back: the documented command of Windows for it
  (`Set-ProcessMitigation -Remove -Disable`) had no effect for an entry by full path. So the
  scripts check after every step whether the setting is really off, and an entry that RCEGuard
  created (Windows had none for the client before) is removed from the registry directly, under
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`. An entry
  that was there before keeps everything else that is in it.
- Run the acceptance test (below) without the setting: its scenarios expect the started program
  to be terminated, not refused.

### Processor load (R8)

Code that mines in the client keeps every core busy for as long as it runs; the 3.3.5a client
itself works mostly on one. The service reads the processor time of every running client from
the process list of Windows (the numbers Task Manager shows; the client is not opened for it)
every 15 s and alerts when the average over `cpuAlertSeconds` is above `cpuAlertCores`. It
alerts once and again only after the load has been below the value in between. Nothing is
terminated.

- The default of 2.0 cores is an assumption about the client, not a measurement. Learning mode
  notes the highest load it saw (see below).
- Whether the client is in the foreground is not part of the rule (the concept asked for
  "in the background"): the service runs outside the user's session and cannot see that.
- The service knows which processes are clients from their start in the Sysmon log. A client
  that was already running when the service started is not measured until it is started again.
- On a machine with no more cores than `cpuAlertCores` the rule can never report; the service
  says so in its log.

### Learning mode

For the first sessions with a client nobody knows its servers yet. `"learning": true` on a
profile makes the service collect instead of judge. **While it is on, RCEGuard does not protect
that client:**

- Nothing is terminated and nothing is locked down for it. A finding that would terminate is
  still reported the same way (log, findings, tray, ntfy), with `not terminated (learning mode)`
  as the action taken.
- The firewall rule of the profile (`"firewall": true`) is not written: a connection the
  firewall blocks leaves no trace, so nothing could be learned about it. A lockdown from before
  stays until it is released.
- A connection to an address that is not on the allowlist is a log entry (R2, info) instead of
  an alert. All other rules alert as always.

The service says so with a warning in `guard.log` at every start. What it notes goes to
`C:\ProgramData\RCEGuard\learned.json`: every address and port the client connected to, the
host names it asked the name service for and their addresses, the folders outside the game
folder in which it created files, and other programs it opened (not the ones it started). After
a session or two:

```powershell
& 'C:\Program Files\RCEGuard\RCEGuard.Service.exe' --learned
```

shows the notes and, at the end, `allowedHostnames`, `allowedRemote` and `allowedProcessAccess`
as they would be with everything added that is not covered yet. Where the client asked for a
name that answered with the address, the name is suggested instead of the address. A program the
client only ever opened with rights to change it is not suggested: listing it would change
nothing, that is reported either way. **Nothing is taken over
automatically, and not everything in the notes is harmless:** whatever the client did while
learning is in there, wanted or not. Put what you recognise into `appsettings.json`, set
`"learning": false`, and restart the service. The notes stay in `learned.json` (and are
continued if the profile learns again) until the file is deleted; `uninstall.ps1` removes it
with the data folder.

The notes also hold the highest processor load of the client (cores on average over
`cpuAlertSeconds`), shown next to the value R8 reports above: if the client comes close to it in
normal play, raise `cpuAlertCores`.

Files are only shown; there is no allowlist for them (an ordinary file outside the game folder
is a log entry anyway). Each list takes at most 500 entries. A `--replay` with a learning profile adds to the notes of the data folder it
is given.

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
3. without a fault and with `-BlockChildProcesses`: the service must run, Exploit Protection
   must say that the client may not start other programs, and the tray application must be
   installed, registered to start at sign-in, and running without administrator rights;
4. `uninstall.ps1`: the machine must look as it did before the test, the Exploit Protection
   setting included.

After 1 and 2 `install.ps1` must have failed with the reason, the service with its folder and its
event sources must be gone, the sensor must still be installed, and nothing may come back within
8 s: Windows restarts a failed service, and a service that cannot run would be started over and
over. The result goes to `out\install-test-result.txt`.

The firewall rules of RCEGuard count as part of the service: after a failed start and after
`uninstall.ps1` none may be left.

To only see what of an installation is on a machine (no admin rights needed, changes nothing):

```powershell
.\scripts\install-test.ps1 -ListOnly
```

### Prevention test

```powershell
.\scripts\prevention-test.ps1 -DownloadSysmon -AcceptSysmonEula
```

Run in an administrator PowerShell with an internet connection, after `.\build.ps1 -Publish`.
It installs RCEGuard for the test client and checks on the installed service what the unit tests
cannot: that Windows Firewall takes the rule and that it blocks. In order: the test client
reaches two addresses while nothing is blocked; with the firewall on and only the first address
allowed, the first still connects and the second does not; after the simulator started a
program, the client is terminated and locked down, and not even the allowed address connects,
also after a restart of the service; after `--release` the allowed address connects again; at
the end the configuration is back as it was and no rule is left. Then Exploit Protection: with
`install.ps1 -BlockChildProcesses` the test client still runs and connects (in the console of
the test), Windows refuses when it starts a program, and after `-AllowChildProcesses` the
setting and its entry are gone, the program starts again and the guard terminates it. Only the
test client is ever blocked. The addresses are `1.1.1.1` and `1.0.0.1` on port 443 (`-AllowedAddress`,
`-OtherAddress`, `-Port`). The result goes to `out\m3-result.txt`. The service stays installed
for the test client afterwards.

### Tray test

```powershell
.\scripts\tray-test.ps1 -DownloadSysmon -AcceptSysmonEula
```

Run in an administrator PowerShell, after `.\build.ps1 -Publish`. Part of this test is done by
the person at the screen. The script installs RCEGuard for the test client (which also installs
and starts the tray application), checks that the tray application runs without administrator
rights, turns the lockdown on for the test client and lets the simulator start a program: the
guard terminates it and locks the profile down. Then it waits (`-WaitSeconds`, default 180):

1. double-click the shield next to the clock (it is red now),
2. click "Release ..." next to `TrayTest` and confirm,
3. confirm the administrator question of Windows.

After that the script checks that the lockdown is gone, that the release command was started by
the tray application (and not by hand in a console), that no firewall rule is left, that the
running service noticed, and that the test client starts again. At the end the configuration is
back as it was; if nobody released the lockdown, the script does that itself and the test fails.
Only the test client is ever blocked. The result goes to `out\m4-result.txt`. `-SkipInstall`
uses the installation that is there.

### Learning test

```powershell
.\scripts\learning-test.ps1 -DownloadSysmon -AcceptSysmonEula
```

Run in an administrator PowerShell with an internet connection, after `.\build.ps1 -Publish`
and with the current simulator in the test folder. It installs RCEGuard for the test client and
checks milestone M5 on the installed service, in two parts:

1. **Learning.** With `"learning": true` (and `lockdown` and `killOnUnknownRemote` on, to show
   that learning holds them back) the simulator connects to a host name and to an address,
   starts a program, opens the Explorer to read it and with rights to change it, creates a
   program file and keeps all processor cores busy for 25 s. Nothing may be terminated or
   locked down, the connections may only be noted, and R1, R3, R7 and R8 must report.
   `--learned` must then suggest the host name as a name, the address as an address and the
   Explorer for `allowedProcessAccess`, and show the highest processor load.
2. **Judging again.** The suggestion is taken over as printed and learning is turned off. What
   was learned must connect without a finding, an address that was not learned must alert,
   looking at the Explorer must be quiet while rights to change it still alert, and a started
   program must be terminated with the client.

After every connection the test asks the Sysmon log whether the connection is in there, and
tries up to three times: a connection Sysmon does not record cannot be noted or judged by the
guard (see "Running the guard"). The result lists every try under "Sensor", with the seconds
since Sysmon last loaded its configuration; a try Sysmon missed is not a failed check as long as
a later one was recorded.

At the end the configuration and the notes from before the test are back. The host name is
`one.one.one.one`, the addresses `9.9.9.9` and `8.8.8.8`, all on port 443 (`-HostName`,
`-OtherAddress`, `-UnknownAddress`, `-Port`). For R8 the test uses 1.5 cores over 10 s; the
machine needs at least two cores. The tray application shows notifications while the test runs.
The result goes to `out\m5-result.txt`, the Sysmon events of the run to `out\m5-events.xml`.

### Sensor probe

```powershell
.\scripts\sensor-probe.ps1
```

A measurement, not a test with a verdict: how reliably does Sysmon record the connections of
the test client, and what does the guard see in the end? Run in an administrator PowerShell with
an internet connection and RCEGuard installed for the test client; without `-Install` it
installs nothing and does not touch the configuration of Sysmon. With the test profile in learning mode (so that no alert comes up) the simulator
connects ten times and closes the connection at once, and ten times and keeps it open, taking
turns, each client alive for 12 s (`-Count`, `-HoldSeconds`, `-Addresses`). After each one the
script asks the Sysmon log whether the connection is in there, and at the end the log of the
guard which connections it took from the connection table of Windows instead. The result
(`out\sensor-probe-result.txt`) lists every connection with what Sysmon and what the guard saw
of it, and counts per kind. About six minutes. `-Install` runs `install.ps1` for the test client
first, to bring the installed service up to the last `.\build.ps1 -Publish`.

## Monitoring the real client

To monitor the real client instead, run `install.ps1` again with its path, for example
`-ClientPath 'D:\Games\Warmane\Wow.exe'`.

**The first sessions: start with learning mode.** Nobody knows yet which servers the client
talks to, which programs it opens and how much processor time it takes, and a rule that fires
on something the client does on purpose would end the game. So:

1. Close the game. (A client that is already running when the service starts is watched by
   Sysmon, but its processor load and the connections Sysmon misses are not looked at.)
2. In an administrator PowerShell:

   ```powershell
   .\scripts\install.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -Learning
   ```

   `-Learning` writes `C:\ProgramData\RCEGuard\appsettings.json` with this client as the only
   profile (`Default`) in learning mode. It does that only if there is no configuration yet; an
   existing one is never changed by the script.
3. Play as usual. The shield next to the clock is blue: the client is watched, **not
   protected**. Findings still come up as notifications (`"notify": { "toast": false }` in the
   configuration turns the pop-ups off).
4. Afterwards look at what was noted: "What was learned ..." in the window of the tray
   application, or `RCEGuard.Service.exe --learned`. Also look at the findings of the session:
   everything that alerted is something the rules would have acted on.
5. Put what you recognise into `appsettings.json` (as administrator), set `"learning": false`
   and run `Restart-Service RCEGuard`. From then on the guard terminates and, if turned on,
   blocks. See "Learning mode".

What the notes and the log of such a session hold are the addresses of the servers you play on
and paths with your Windows user name: keep them out of bug reports and repositories.

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

## Patching the client (optional)

Everything above watches the client from outside. This section is about the client file itself,
and it is the only place where RCEGuard offers to change it. **RCEGuard never does that by
itself:** the service, the tray application and `install.ps1` only read the header of the file.

**What it is about.** The 3.3.5a client (`Wow.exe`, build 12340) has one small section,
`.zdata`: 4096 bytes, empty in the file, writable **and** executable, and at the same address
at every start because the client has no address randomisation. Whatever gets written there can
be run. The well-known [RCEPatcher](https://github.com/stoneharry/RCEPatcher) takes the execute
right away from that section by changing one byte in the header of the file; according to its
authors a patched client crashes when a server tries the remote code exploit.

**Where RCEGuard tells you.** If the client has such a section, `install.ps1` says so once at
its end, and

```powershell
& 'C:\Program Files\RCEGuard\RCEGuard.Service.exe' --check-client
```

prints it for every profile whenever you ask. None of this changes anything. There is no
standing warning in the log or in the tray application: on a server where the section is
needed for logging in (see the real try below) it would be a warning nobody can act on.

**Changing the file** is done by `scripts\patch-client.ps1`, which you start yourself. It makes
the same one-byte change, but first checks that the file is what it expects (a 32-bit program
with exactly one writable and executable section, named `.zdata`, that is empty in the file and
that the program neither starts in nor keeps a table in), and it can undo the change. It needs
no administrator rights if you may write to the game folder.

```powershell
.\scripts\patch-client.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -CheckOnly
```

1. `-CheckOnly` shows the sections and says whether the script would change the file.
2. Without a switch it writes a copy `Wow_patched.exe` next to the client and leaves the
   original alone. Start the copy and go as far as the login screen: that shows whether the
   client still runs, without an account being involved.
3. `-InPlace` changes the file itself (the client must not be running) and keeps the unchanged
   file as `Wow.exe.unpatched`. Launchers and RCEGuard go on using the same path.
4. `-Undo` gives the execute right back; the file is then byte for byte what it was.

**One real try (2026-11-16, one server, build 12340).** The patched copy started and showed
the login screen. Right after the password was entered it crashed, in two of two tries, with
`ACCESS_VIOLATION at 00DD1000`: the first address of `.zdata`, where Windows now refuses to run
code. The crash report of the client shows the way there: code of the client called code that
had been loaded at run time and belongs to no file, and that code called into `.zdata`. So on
that server something that arrives at login runs code in this very section as a matter of
course. The patch cannot tell wanted code from unwanted code there: **with such a server a
patched client cannot log in.** It also shows what the section is used for in practice. Try the
copy first, as described above, before you change the client for good.

**What nobody here can tell you:**

- whether the change stops a particular exploit. RCEGuard contains no exploit and has not
  tested that; it is what the authors of the patcher say, and it fits what the file shows.
- whether a server minds a client file that was changed. Decide yourself whether to log in
  with it, and with which account.
- whether a client that is not build 12340 behaves the same. The script refuses a file that
  does not have the layout described above.

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
scripts/ExploitProtectionTools.ps1     shared helpers for the Exploit Protection setting of the client
scripts/TrayTools.ps1                  shared helpers for installing and removing the tray application
scripts/show-events.ps1                prints or saves recorded events (admin)
scripts/acceptance-test.ps1            simulator scenarios against the running guard (admin)
scripts/install-test.ps1               install with a service that cannot start, uninstall, look for leftovers (admin; -ListOnly without)
scripts/prevention-test.ps1            firewall rule, lockdown, release and Exploit Protection against the installed service (admin, needs internet)
scripts/tray-test.ps1                  tray application without administrator rights, release of a lockdown from its window (admin, with a person at the screen)
scripts/learning-test.ps1              learning mode with its suggestion, R7 and R8 against the installed service (admin, needs internet)
scripts/patch-client.ps1               takes the execute right from the client's ".zdata" section, or gives it back; started by hand only
scripts/ClientFileTools.ps1            shared helpers that read the header of a client file
scripts/sensor-probe.ps1               measures which connections of the test client Sysmon records: closed at once or kept open (admin, needs internet)
src/RCEGuard.Core/                     rule engine, event parser, configuration, firewall rule planning (no OS dependencies)
src/RCEGuard.Service/                  guard: Sysmon log reader, actions, findings database, firewall rules and lockdown, look at running clients (processor time, connection table)
src/RCEGuard.Tray/                     tray application: icon, findings window, pop-ups; only reads
src/RCEGuard.FakeWow/                  simulator, builds as Wow.exe
tests/RCEGuard.Core.Tests/             unit tests, with recorded Sysmon events as fixtures
tests/RCEGuard.Service.Tests/          process killer against real, harmless processes; resuming in real Windows logs (read only; for new events the tests start Windows PowerShell); firewall rules, lockdown and release against a stand-in for Windows Firewall (the real one is only read)
tests/RCEGuard.Tray.Tests/             the tray application without its user interface, on a data folder written by the service's own code; draws window and icons into pictures
build.ps1                              build wrapper that insists on a real .NET SDK; -Publish for the service and the tray application
```

## License

MIT, see [LICENSE](LICENSE).
