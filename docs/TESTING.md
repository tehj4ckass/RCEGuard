# Simulator and tests

[← Back to the README](../README.md)

Nothing here needs a game client or an exploit: the simulator stands in for the client, and the
repository contains no exploit code. The scripts marked "admin" change the machine (they install
Sysmon and the service for the test client) and are meant to be started by a person in a
PowerShell **started as administrator**.

## Unit tests

`.\build.ps1` builds everything and runs the three test projects: `RCEGuard.Core.Tests` (rule
engine, with recorded and anonymised Sysmon events as fixtures), `RCEGuard.Service.Tests` (guard
loop, process killer against real but harmless processes, firewall rules against a stand-in for
Windows Firewall) and `RCEGuard.Tray.Tests` (the tray application without its user interface;
it also draws the window and the icons into pictures). No admin rights needed.

## The simulator

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

## Acceptance test

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

## Install test

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

## Prevention test

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

## Tray test

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

## Learning test

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
guard (see [DETECTION.md](DETECTION.md#connections-r2-are-slower-and-can-be-missed)). The result lists every try under "Sensor", with the seconds
since Sysmon last loaded its configuration; a try Sysmon missed is not a failed check as long as
a later one was recorded.

At the end the configuration and the notes from before the test are back. The host name is
`one.one.one.one`, the addresses `9.9.9.9` and `8.8.8.8`, all on port 443 (`-HostName`,
`-OtherAddress`, `-UnknownAddress`, `-Port`). For R8 the test uses 1.5 cores over 10 s; the
machine needs at least two cores. The tray application shows notifications while the test runs.
The result goes to `out\m5-result.txt`, the Sysmon events of the run to `out\m5-events.xml`.

## Sensor probe

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
