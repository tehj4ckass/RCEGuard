# Learning mode and the first sessions with a real client

[← Back to the README](../README.md)

## The first sessions with a real client

Nobody knows yet which servers the client
talks to, which programs it opens and how much processor time it takes, and a rule that fires
on something the client does on purpose would end the game. So:

1. Close the game. (A client that is already running when RCEGuard is installed is watched by
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
5. Put what you recognise into `appsettings.json` (as administrator). Then leave learning
   mode: click "Report only" or "Protect" under "Mode" in the window of the tray application
   (Windows asks for an administrator; the service is restarted and reads the file anew). By
   hand it is `"learning": false` and `Restart-Service RCEGuard`. From "Protect" on the guard
   terminates and, if turned on, blocks. See "What learning mode does" below.

What the notes and the log of such a session hold are the addresses of the servers you play on
and paths with your Windows user name: keep them out of bug reports and repositories.

### A step in between: report only

Learning mode notes and does not judge connections. Before the guard is allowed to end the game,
it can run with the learned allowlist in the mode "Report only" (`"killEnabled": false` at the
top level of `appsettings.json`): every rule judges as in normal operation, an unknown address is an alert
again, but nothing is terminated and nothing is locked down. The shield of the tray application
is then blue with two bars. After a normal session without an alert that should not have been
one, switch to "Protect". A server the guard did not know yet (another realm, for example)
shows up as an R2 alert: double-click the finding and choose "Allow this address ..." if you
recognise it.

## What learning mode does

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
