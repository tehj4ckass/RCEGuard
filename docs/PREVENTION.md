# Blocking in advance: firewall rule, lockdown, Exploit Protection

[← Back to the README](../README.md)

Detection reacts after the fact. Two switches make Windows Firewall block connections of
the client before they happen. Both are off unless the configuration turns them on. Both were
checked with the simulator on the installed service (see [Prevention test](TESTING.md#prevention-test)), not yet with the
real client.

## Firewall rule: `"firewall": true` on a profile

The service keeps one outbound block rule for the client in
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

## Lockdown: `"lockdown": true` (kill switch)

After a finding that terminates the client, the profile is
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
"Release ..." in the window of the [tray application](TRAY.md) starts the same command and
lets Windows ask for an administrator.

If `lockdown.json` cannot be read, every profile is treated as locked down until `--release`
replaces the file.

## Exploit Protection: `install.ps1 -BlockChildProcesses`

Rule R1 terminates a program the
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
- Run the [acceptance test](TESTING.md#acceptance-test) without the setting: its scenarios expect the started program
  to be terminated, not refused.
