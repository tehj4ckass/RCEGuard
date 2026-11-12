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
| M1 | Sensor: Sysmon configuration, install and uninstall scripts, simulator | done; install, uninstall and all simulator scenarios verified with Sysmon 15.22. Not yet verified against the real Sysmon: the retry after a failed manifest registration, and the removal of the leftover `C:\Windows\Sysmon64.exe` |
| M2 | Service and rule engine (R1–R6, R9), SQLite log | rule engine done and tested; service runs in a console. First live run against Sysmon: every scenario detected within 0.8–1.2 s, but 2 of 5 failed because the console host of the hidden simulator counted as a child process. **Fixed, rerun not yet done.** Not yet installed as a Windows service; toast moved to M4 |
| M3 | Prevention: firewall profiles, Exploit Protection, kill switch | open |
| M4 | Tray UI, toast, ntfy, heartbeat | open |
| M5 | Learning mode, R7, R8 | open |

Right now the guard has to be started by hand in an administrator console. It evaluates events,
terminates the client on critical findings and writes every finding to a database. It does not
notify anyone yet, and nothing is blocked in advance.

## Requirements

- Windows 10/11 x64
- .NET 8 SDK (to build the simulator)
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) 15.0 or newer from
  Microsoft (the configuration uses schema 4.90). It is not part of this repository;
  `install.ps1` can download it from Microsoft for you.
- Admin rights for installing, uninstalling and reading the Sysmon log

## Trying the sensor with the simulator

The simulator is a small console program that runs as `Wow.exe` and triggers one suspicious
behaviour per switch. Everything it does is harmless and undone before it exits.

Build it and copy it to a test folder:

```powershell
.\build.ps1
dotnet publish src\RCEGuard.FakeWow -c Release -o C:\RCEGuardTest
```

Install the sensor for that test client, in a PowerShell **started as administrator**:

```powershell
.\scripts\install.ps1 -ClientPath C:\RCEGuardTest\Wow.exe -DownloadSysmon -AcceptSysmonEula
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

Every child process also produces an id 10 event (rule `R7`, the client holds a handle to its
child) and an id 13 event for a Windows bookkeeping key under `Services\bam`. Both are expected.

Save the recorded events as XML, for example as raw material for test fixtures:

```powershell
.\scripts\show-events.ps1 -Last 200 -OutFile out\events.xml
```

## Running the guard

`RCEGuard.Service` reads the Sysmon log, applies the rules and acts on the findings. Until it is
installed as a Windows service (next step of M2), start it in an administrator PowerShell:

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
this (`killOnUnknownRemote` and `killEnabled` are optional):

```json
{
  "killEnabled": true,
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

The console host is only recognised in its exact form: `conhost.exe` from the Windows system
folder, started with nothing but a console handle on its command line. Windows starts it that way
for every console program that gets its own console. `conhost.exe` with any other arguments (it
can start other programs) is an ordinary R1.

Findings arrive about one second after the event, because Windows delivers log entries in
batches. A child process therefore runs for about a second before it is terminated; stopping it
from starting at all is the job of M3.

The guard stops with an error instead of idling if it cannot read the Sysmon log.

### Acceptance test

Runs all simulator scenarios against the running guard and checks that each one is detected
within 2 s and that the critical ones are terminated. In an administrator PowerShell, after
`.\build.ps1` and publishing the simulator:

```powershell
.\scripts\acceptance-test.ps1 -DownloadSysmon -AcceptSysmonEula
```

It installs the sensor for the test client if needed and writes `out\m2-result.txt`,
`out\m2-service.log` and the recorded events as `out\m2-events.xml`. The simulator switch `--hold [seconds]` used by the test keeps the client
(and for `--spawn` its child) alive, so the guard has something to terminate; a client that
survives exits with code 3.

## Monitoring the real client

To monitor the real client instead, run `install.ps1` again with its path, for example
`-ClientPath 'D:\Games\Warmane\Wow.exe'`.

Remove everything again:

```powershell
.\scripts\uninstall.ps1
```

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
parent, so grandchildren of the client have to be tracked by the service (M2).

## Repository layout

```text
docs/KONZEPT.md                        concept and milestones (German)
sysmon/rceguard-sysmon.template.xml    Sysmon configuration template
scripts/render-config.ps1              renders the template for one client (no admin)
scripts/install.ps1                    installs Sysmon / loads the configuration (admin)
scripts/uninstall.ps1                  removes the sensor again (admin)
scripts/SysmonTools.ps1                shared Sysmon helpers of the two scripts above
scripts/show-events.ps1                prints or saves recorded events (admin)
scripts/acceptance-test.ps1            simulator scenarios against the running guard (admin)
src/RCEGuard.Core/                     rule engine, event parser, configuration (no OS dependencies)
src/RCEGuard.Service/                  guard: Sysmon log reader, actions, findings database
src/RCEGuard.FakeWow/                  simulator, builds as Wow.exe
tests/RCEGuard.Core.Tests/             unit tests, with recorded Sysmon events as fixtures
build.ps1                              build wrapper that insists on a real .NET SDK
```

## License

MIT, see [LICENSE](LICENSE).
