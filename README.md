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
| M1 | Sensor: Sysmon configuration, install and uninstall scripts, simulator | written, **not yet verified on a machine with Sysmon** |
| M2 | Service and rule engine (R1–R6, R9), SQLite log, toast | open |
| M3 | Prevention: firewall profiles, Exploit Protection, kill switch | open |
| M4 | Tray UI, ntfy, heartbeat | open |
| M5 | Learning mode, R7, R8 | open |

Right now RCEGuard only **records** events. Nothing is evaluated, blocked or reported yet.

## Requirements

- Windows 10/11 x64
- .NET 8 SDK (to build the simulator)
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) from Microsoft. It is not
  part of this repository; `install.ps1` can download it from Microsoft for you.
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
| `--runkey` | sets and removes an `HKCU\...\Run` value | id 13, rule `R4` |
| `--cpu [seconds]` | full load on all cores | none (R8 is polled by the service, M5) |
| `--miner-args` | starts a child with `stratum+tcp://` in its arguments | id 1, rule `R1` or `R9` |

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
scripts/show-events.ps1                prints recorded events (admin)
src/RCEGuard.FakeWow/                  simulator, builds as Wow.exe
build.ps1                              build wrapper that insists on a real .NET SDK
```
