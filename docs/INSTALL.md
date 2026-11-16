# Installing, running and removing

[← Back to the README](../README.md)

The short way is in the README ("Quick start"). This page says what `install.ps1` and
`uninstall.ps1` do to the machine, how to run the guard in a console, and what to do when
Sysmon gets in the way.

## As a Windows service

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
  first reads what Sysmon recorded in the meantime (see [After a restart](DETECTION.md#after-a-restart)).

The published service brings its own .NET runtime (about 75 MB), so it does not depend on a
runtime installed in a user profile. Running `install.ps1` again updates the service and points it
at another client; `-SkipService` installs only the sensor.

Stopping the Sysmon service also stops RCEGuard, because the guard depends on it.

## In a console

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
| `--release [profile]` | end the lockdown of that profile (without a name: of every profile), then exit; see [PREVENTION.md](PREVENTION.md) |
| `--set-mode <mode>` | set how the guard acts (`protect`, `report-only`, `learning`): changes `killEnabled` and, on every profile, `learning` in the configuration, keeps the file from before as `appsettings.json.bak`, restarts the service, then exit; the tray application starts it for its mode buttons; see [TRAY.md](TRAY.md) |
| `--allow <profile> <address>` | add an IP address or CIDR range to `allowedRemote` of that profile, keep the file from before, restart the service, then exit; the tray application starts it for "Allow this address ..." |
| `--notify-test` | send a test notification to the configured ntfy topic, then exit; needs no admin rights; see [NOTIFICATIONS.md](NOTIFICATIONS.md) |
| `--check-client [file]` | say whether that program file (without a file: the client of every profile) has a section that is both writable and executable, then exit; only reads the file, needs no admin rights; see [CLIENT-PATCH.md](CLIENT-PATCH.md) |
| `--learned [profile]` | show what the learning mode noted for that profile (without a name: for every profile) and what it suggests for the allowlist, then exit; changes nothing, needs no admin rights; see [LEARNING.md](LEARNING.md) |

## Removing everything

In a PowerShell **started as administrator**:

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
