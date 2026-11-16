# Notifications to your phone (ntfy)

[← Back to the README](../README.md)

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

- every finding that alerts or terminates, with the rule, the
  summary, what the guard did, the time and the name of the computer. Findings that are only
  logged are not sent, and a repeated alert is sent as often as it is reported, not as often as
  it happens (see [Repeated alerts](DETECTION.md#repeated-alerts));
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
