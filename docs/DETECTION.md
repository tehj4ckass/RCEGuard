# Detection in detail

[← Back to the README](../README.md)

The rules are listed in the README ("What it detects"). This page says what the sensor records,
how the guard acts on a finding, how fast it is, and where it is known to miss things.

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
programs itself when it terminates a child (see [What a child leaves behind](#what-a-child-leaves-behind)).

## Acting on a finding

A process is only terminated if its pid still runs the program the event named. Findings go to
`findings.db` (SQLite) in the data folder. "Alert" means: a line in `guard.log`, an entry in
the database, a pop-up of the [tray application](TRAY.md) and, if configured, a message to an
[ntfy topic](NOTIFICATIONS.md).

## A scan is one finding

Right after its start the real client opens every running program to
read its memory (seen: 36 programs within a second). The guard holds the R7 findings that are
only logged back until the client has opened nothing more for 3 seconds (60 at most) and then
reports them together: "The game client opened 36 other programs to read their memory (0x10;
100 accesses within 1 s): chrome.exe, ... and 31 more". A single access is reported as before,
only those few seconds later. An access with rights to change a program (R7 high) is never held
back.

## What a child leaves behind

Sysmon only reports the programs the client starts itself, not
what those start. When the guard terminates a child that is still running, everything below it
goes with it. If the child has already exited by then (`cmd /c start payload` takes
milliseconds, the guard about a second), the guard looks for running programs that name the
child as their parent and were started after it, and terminates them with everything below
them. Limits: a program that was started by such a left-behind program which has itself exited
is not found, and neither is one whose parent was forged.

## The console host

The console host is only recognised in its exact form: `conhost.exe` from the Windows system
folder, started with nothing but a console handle on its command line. Windows starts it that way
for every console program that gets its own console. `conhost.exe` with any other arguments (it
can start other programs) is an ordinary R1.

## After a restart

The guard saves its position in the Sysmon log (at once after a finding,
otherwise once a second). When it starts again, after a crash, an update or a reboot, it first
reads the events written while it was not running; their findings carry the note "written while
RCEGuard was not running" in the log. Such an event can be old, so two extra checks apply before
anything is terminated: the process must have been started before the event (a pid that runs the
same program again in a newer process is left alone), and programs left behind by an exited
child are only searched for if the event is at most 30 seconds old. The very first start reads
nothing old. If the Sysmon log was cleared or replaced in the meantime, everything in it is
read; if events were overwritten before the guard could read them, it says how many. The rule
engine starts empty after a restart: what it knew about running children is gone.

## If the log goes quiet for the guard only

A guard that is given no events watches nothing and
looks healthy. So a guard that has received nothing for 15 seconds looks into the log itself. If
an event has been there for more than 15 seconds without being delivered, the guard writes
"RCEGuard cannot run" with the record ids to its log and ends; Windows then restarts the service,
and the start reads what was missed.

The guard stops with an error instead of idling if it cannot read the Sysmon log.

## Repeated alerts

The same alert (same rule, client process and target) is reported once
and then only counted for `repeatWindowSeconds`; the count is stored with the finding. Findings
that terminate a process are never held back.

## How fast findings arrive

Findings arrive 0.6 to 1.1 seconds after the log entry (measured in the acceptance test), because
Windows delivers log entries in batches. A child process therefore runs for about a second before it is terminated; stopping it
from starting at all is what `install.ps1 -BlockChildProcesses` is for (see [PREVENTION.md](PREVENTION.md)).

## Connections (R2) are slower and can be missed

Sysmon writes a network connection to its log
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

## The connection table of Windows as a second source

Because of this gap the service does
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
firewall rule of a profile (see [PREVENTION.md](PREVENTION.md)).

## Processor load (R8)

Code that mines in the client keeps every core busy for as long as it runs; the 3.3.5a client
itself works mostly on one. The service reads the processor time of every running client from
the process list of Windows (the numbers Task Manager shows; the client is not opened for it)
every 15 s and alerts when the average over `cpuAlertSeconds` is above `cpuAlertCores`. It
alerts once and again only after the load has been below the value in between. Nothing is
terminated.

- The default of 2.0 cores is an assumption about the client, not a measurement. Learning mode
  notes the highest load it saw (see [LEARNING.md](LEARNING.md)).
- Whether the client is in the foreground is not part of the rule (the concept asked for
  "in the background"): the service runs outside the user's session and cannot see that.
- The service knows which processes are clients from their start in the Sysmon log. A client
  that was already running when the service started is not measured until it is started again.
- On a machine with no more cores than `cpuAlertCores` the rule can never report; the service
  says so in its log.
