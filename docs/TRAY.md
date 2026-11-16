# Tray application

[← Back to the README](../README.md)

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
| blue shield with two bars | report only: `"killEnabled": false` in the configuration, so findings are reported, but no client is terminated and no profile is locked down |
| grey shield with a cross | the service is not running or not installed: the client is not watched |

What counts most is shown: a service that is down before a lockdown, a lockdown before new
findings, new findings before "report only", that before learning mode. (The tray application
reads `killEnabled` from the configuration; a service started by hand with `--dry-run` does not
terminate either, and that it cannot see.) A double click opens the window: the state, the
profiles in lockdown with the finding that caused each, the profiles in learning mode, and the
newest 200 findings (those that were only logged are grey). Closing
the window leaves the icon; "Exit" in the menu of the icon ends the tray application, not the
service.

- **Mode.** The bar below the state has three buttons, and the menu of the icon has the same
  three under "Mode": "Protect" (findings are reported, and the critical ones terminate the
  client), "Report only" (everything is judged and reported, nothing is terminated or locked
  down) and "Learning" (every profile learns: watched, not protected). The one that is set
  stays pressed; none is pressed if the configuration is neither (learning for some profiles
  only, or learning together with `"killEnabled": false`). A click asks first and then starts
  `RCEGuard.Service.exe --set-mode <mode>` with administrator rights: Windows asks for an
  administrator. The command changes `killEnabled` and `learning` in `appsettings.json`, keeps
  the file from before as `appsettings.json.bak`, restarts the service and, if an ntfy topic is
  configured, reports the change there. A mode is set for every profile.
- **A finding in full.** A double click on a finding shows all of it as text (the columns of the
  list cut long lines), with "Copy".
- **Allowing an address.** For a finding about a connection (R2) that window has "Allow this
  address ...". It starts `RCEGuard.Service.exe --allow <profile> <address>` the same way:
  the address is added to `allowedRemote` of the profile and the service is restarted. Do this
  only for an address you recognise as a server of your game: connections to it are not
  reported any more. The finding itself stays in the list.
- **A restart while the game runs.** Changing the mode or the allowlist restarts the service.
  It finds the running client again (it keeps a list of the clients it knows to be running) and
  goes on measuring its processor load and reading its connections; the average for R8 starts
  anew, and connections that are open at that moment are listed once in the log as "found in
  the connection table". If an ntfy topic is configured, "RCEGuard is stopping while the client
  runs" is sent as well.
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
