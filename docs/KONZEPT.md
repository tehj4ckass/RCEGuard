# RCEGuard – Konzept für einen RCE-Wächter für WoW-Private-Server-Clients

> Übergabedokument für Claude Code. Zielplattform: **Windows 10/11 x64**, Client `Wow.exe` 3.3.5a (z. B. Warmane).
> „RCEGuard“ ist der Arbeitstitel; das Konzept entstand unter dem Namen WowGuard. Umsetzungsstand und bewusste
> Abweichungen stehen in der [`README.md`](../README.md).

## 1. Ziel

Eine kleine Windows-App, die den WoW-Client **von außen** überwacht. Sie meldet verdächtiges Verhalten, das auf eine Remote Code Execution hindeutet (z. B. über einen Client-Exploit oder ein bösartiges Warden-Modul), und blockiert es nach Möglichkeit.

**Grundidee:** Eingeschleuster Schadcode muss früher oder später etwas tun, was der WoW-Client nie tut: einen Prozess starten, unbekannte IPs kontaktieren, Autostart-Einträge anlegen usw. Genau auf diese Verhaltensmuster wird überwacht, nicht auf den Code im Speicher.

## 2. Nicht-Ziele (wichtig!)

- **Kein Eingriff in `Wow.exe`**: kein DLL-Injection, kein Hooking, kein Patchen und kein Lesen des Prozessspeichers. Das würde Warden auslösen und zu einem **Ban** führen. Die App beobachtet ausschließlich über Betriebssystem-Mechanismen.
- Keine Erkennung von Warden-Modulen oder Lua-Payloads im Speicher. Dynamisch geladener Code ist bei Warden normal und würde nur Fehlalarme erzeugen.
- Kein Schutz gegen Angreifer mit Kernel- oder Admin-Rechten.
- Kein Antivirus-Ersatz.

## 3. Architektur

```
┌────────────────────┐   Event Log    ┌──────────────────────────┐
│ Sysmon (Microsoft) │ ─────────────▶ │ RCEGuard.Service         │
│ Kernel-Sensor      │                │ (Windows-Dienst, SYSTEM) │
└────────────────────┘                │ - Rule Engine            │
                                      │ - Actions (Kill/Block)   │
┌────────────────────┐                │ - SQLite-Log             │
│ Windows Firewall   │ ◀───────────── │ - Notifier (Toast/ntfy)  │
│ Exploit Protection │   Konfig       └───────────┬──────────────┘
└────────────────────┘                            │ Named Pipe
                                      ┌───────────▼──────────────┐
                                      │ RCEGuard.Tray (User-UI)  │
                                      │ Status, Alerts, Settings │
                                      └──────────────────────────┘
```

- **Sensor: Sysmon.** Ausgereift, läuft als Kernel-Treiber und kann von einem normalen User nicht beendet werden. Kein eigener Treiber nötig.
- **Dienst** läuft als `LocalSystem`. Malware mit den Rechten des Users kann ihn daher nicht stoppen.
- **Tray-App** läuft als normaler User, dient nur zur Anzeige und Konfiguration und hat keine Sicherheitslogik.
- **Empfohlener Betrieb:** Gespielt wird mit einem Windows-User **ohne Admin-Rechte**.

### Tech-Stack

- C# / .NET 8
- Dienst: `Microsoft.Extensions.Hosting.WindowsServices`
- Event-Log lesen: `System.Diagnostics.Eventing.Reader.EventLogWatcher` auf `Microsoft-Windows-Sysmon/Operational`
- Firewall: COM `HNetCfg.FwPolicy2` oder PowerShell `New-NetFirewallRule`
- Exploit Protection: PowerShell `Set-ProcessMitigation`
- UI: WPF (Tray via `H.NotifyIcon`) und Windows-Toasts
- Persistenz: SQLite (`Microsoft.Data.Sqlite`)
- Konfiguration: `appsettings.json` unter `C:\ProgramData\RCEGuard\`, nur mit Admin-Rechten beschreibbar (ACL)

## 4. Erkennungsregeln

Alle Regeln gelten nur für Prozesse, deren Image dem konfigurierten Client-Pfad entspricht (z. B. `D:\Games\Warmane\Wow.exe`), **sowie für alle Prozesse, die von ihm abstammen**.

| ID | Sysmon-Event | Regel | Schwere | Standard-Aktion |
|---|---|---|---|---|
| R1 | 1 ProcessCreate | `ParentImage` = Wow.exe (jeder Kindprozess) | KRITISCH | Kill Kind + Wow, Alarm |
| R2 | 3 NetworkConnect | Ziel-IP nicht in der Allowlist des Server-Profils | KRITISCH | Alarm, optional Kill |
| R3 | 11 FileCreate | Datei außerhalb des Spielordners, besonders `.exe/.dll/.ps1/.bat/.vbs/.lnk` oder Startup-Ordner | HOCH | Alarm |
| R4 | 12/13 Registry | Schreibzugriff auf `Run`/`RunOnce`, `Winlogon`, `Services`, `Image File Execution Options` | KRITISCH | Kill Wow, Alarm |
| R5 | 7 ImageLoad | DLL wird aus User-Pfaden geladen (`%TEMP%`, `%APPDATA%`, `Downloads`), unsigniert | HOCH | Alarm |
| R6 | 8 CreateRemoteThread | Wow.exe erzeugt einen Thread in einem anderen Prozess | KRITISCH | Kill Wow, Alarm |
| R7 | 10 ProcessAccess | Wow.exe öffnet andere Prozesse mit Schreib- oder Thread-Rechten (`0x1F0FFF`, `0x0020`, `0x0002`) | MITTEL* | Nur loggen |
| R8 | (Polling) | Wow.exe läuft im Hintergrund (nicht im Vordergrund) länger als 5 Min. mit > 50 % CPU auf mehreren Kernen | MITTEL | Alarm |
| R9 | 1 ProcessCreate | Neuer Prozess mit einem Miner-typischen Namen oder Argumenten (`stratum+tcp`, `xmrig`, `--donate-level`) | KRITISCH | Kill, Alarm |

\* **R7**: Warden scannt eventuell andere Prozesse nach Cheat-Tools. Deshalb wird R7 zunächst nur geloggt und erst im Lernmodus bewertet.

Der Spielordner gilt für R3 als sicher, z. B. `Cache\`, `WTF\`, `Logs\`, `Interface\`, `Screenshots\`, `Errors\`.

## 5. Präventionsmaßnahmen

Der Dienst richtet diese Maßnahmen beim Setup ein und kann sie auf Knopfdruck wieder entfernen:

1. **Exploit Protection für `Wow.exe`**
   - `Set-ProcessMitigation -Name Wow.exe -Enable DisallowChildProcessCreation`
   - ⚠️ **Nicht** `ArbitraryCodeGuard` / `BlockDynamicCode` aktivieren, das bricht Warden.
   - Vor dem Aktivieren testen, ob sich der Client startet, einloggt und patcht.
2. **Firewall pro Server-Profil**
   - Eine Regel, die ausgehenden Verkehr von `Wow.exe` grundsätzlich blockiert.
   - Allow-Regeln nur für die IPs/Ranges des Profils (Login- und Realm-Server).
   - Windows Firewall: Eine Block-Regel schlägt eine Allow-Regel. Deshalb stattdessen die Standard-Outbound-Policy des Programms nutzen oder mit `RemoteAddress`-Ausschlussbereichen arbeiten. Claude Code soll die korrekte Umsetzung prüfen.
3. **Kill-Switch:** Bei einem KRITISCH-Treffer werden der Prozessbaum von Wow.exe beendet und die Firewall-Regel für Wow.exe auf „block all“ gesetzt, bis der User das Ereignis in der Tray-App freigibt.

## 6. Server-Profile und Lernmodus

```json
{
  "profiles": [
    {
      "name": "Warmane",
      "clientPath": "D:\\Games\\Warmane\\Wow.exe",
      "allowedRemote": ["<IP/CIDR>", "..."],
      "allowedHostnames": ["logon.warmane.com"]
    }
  ],
  "notify": {
    "toast": true,
    "ntfy": { "enabled": true, "url": "http://motherpi.local:8080/rceguard" }
  }
}
```

- **Lernmodus** (pro Profil, z. B. für die ersten 2 Sessions): Es wird nichts blockiert, nur gesammelt, welche IPs, Dateipfade und ProcessAccess-Ziele normal sind. Danach zeigt die Tray-App einen Vorschlag für die Allowlist, die der User bestätigt.
- Hostnamen werden beim Start und dann periodisch aufgelöst und in die IP-Allowlist übernommen.

## 7. Benachrichtigung und Logging

- Jeder Treffer landet in SQLite: Zeit, Regel, Schwere, Prozess, PID, Kommandozeile, Ziel (IP/Datei/Key), ausgeführte Aktion.
- Windows-Toast an die Tray-App.
- Push über **ntfy** (selbst gehostet auf dem Homeserver), damit Alarme auch ankommen, wenn die Tray-App gekillt wurde.
- **Heartbeat:** Läuft Wow.exe, der Dienst sendet aber keine Events mehr oder Sysmon ist gestoppt, folgt ein Alarm über ntfy.

## 8. Testbarkeit (ohne echten Exploit!)

Ein **Simulator** `FakeWow.exe` (eigenes kleines Konsolenprojekt), der unter dem Namen `Wow.exe` in einen Testordner kopiert wird und per Parameter jeweils ein Verhalten auslöst:

- `--spawn` startet `cmd.exe /c echo test` → R1
- `--connect 1.1.1.1:443` → R2
- `--drop` schreibt `%APPDATA%\test.exe` → R3
- `--runkey` legt einen harmlosen Run-Key an und löscht ihn wieder → R4
- `--cpu` erzeugt 5 Min. Volllast → R8
- `--miner-args` startet einen Dummy-Prozess mit `stratum+tcp://` im Argument → R9

Dazu Unit-Tests für die Rule Engine mit aufgezeichneten Sysmon-Event-XMLs als Fixtures.

## 9. Projektstruktur

```
RCEGuard/
├─ src/
│  ├─ RCEGuard.Core/        # Rule Engine, Modelle, Konfiguration (testbar, ohne OS-Abhängigkeiten)
│  ├─ RCEGuard.Service/     # Windows-Dienst, Sysmon-Reader, Actions, Notifier
│  ├─ RCEGuard.Tray/        # WPF-Tray-UI
│  └─ RCEGuard.FakeWow/     # Simulator
├─ tests/RCEGuard.Core.Tests/
├─ sysmon/rceguard-sysmon.xml   # Sysmon-Config, nur Wow.exe-relevante Events
├─ scripts/
│  ├─ install.ps1           # Sysmon installieren, Config laden, Dienst registrieren, ACLs setzen
│  └─ uninstall.ps1         # alles sauber zurückbauen (inkl. Firewall/Exploit Protection)
└─ README.md
```

## 10. Meilensteine

1. **M1 – Sensor:** Sysmon-Config plus `install.ps1`, die nur relevante Events für Wow.exe erfasst. Ziel: wenig Rauschen und Performance-neutral, also kein globales ImageLoad-Logging.
2. **M2 – Dienst und Rule Engine:** R1–R6 und R9, SQLite-Log, Toast. Tests mit FakeWow.
3. **M3 – Prävention:** Firewall-Profile, Exploit Protection, Kill-Switch und Freigabe-Workflow.
4. **M4 – Tray-UI und ntfy:** Status, Alarmliste, Profilverwaltung, Heartbeat.
5. **M5 – Lernmodus,** R7, R8.

## 11. Akzeptanzkriterien

- Alle FakeWow-Szenarien werden innerhalb von < 2 s erkannt, die KRITISCH-Fälle werden beendet.
- Eine normale Spielsession von 2 h auf Warmane (Login, Realmwechsel, BG, Raid, Addons) erzeugt **0 Alarme** der Stufe HOCH oder KRITISCH.
- Der Dienst kann von einem Nicht-Admin-User nicht gestoppt oder umkonfiguriert werden.
- Kein messbarer FPS-Verlust im Spiel.
- `uninstall.ps1` stellt den Ausgangszustand vollständig wieder her.

## 12. Offene Punkte / Risiken

- Die echten Warmane-IPs und -Hostnamen werden über den Lernmodus ermittelt und nicht fest einprogrammiert.
- Es ist zu prüfen, ob Exploit Protection `DisallowChildProcessCreation` den Client oder Launcher stört, z. B. beim Öffnen von Links aus dem Spiel oder beim Fehlerreporter.
- Sysmon-Events sind nachträglich, also „detect & respond“: Eine Aktion ist zum Zeitpunkt der Meldung bereits passiert. Echtes Vorab-Blocken leisten nur Firewall und Exploit Protection.
- Optionale Ergänzung: Der Client wird mit dem stoneharry-RCEPatcher gepatcht. Das liegt außerhalb dieses Projekts, wird aber im README empfohlen.

## 13. Erkenntnisse aus M1 (Sensor-Test mit dem Simulator, Sysmon 15.22)

Alle Szenarien des Simulators wurden aufgezeichnet (R1, R2, R3, R4). Für die Regel-Engine in M2 folgt daraus:

- **R4, Fehlalarm über `Services`:** Startet der Client einen Kindprozess, schreibt Windows unter dem Namen des Clients
  nach `HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\<SID>\…` (Background Activity Moderator). Ein
  Muster „enthält `\Services\`“ wäre falsch. R4 braucht genaue Schlüssel (z. B. `Services\<Name>\ImagePath`, `Start`) und
  schließt `Services\bam\` aus.
- **R4, Schreibweise:** `HKCU` erscheint als `HKU\<SID>\…`. Abgeglichen wird das Ende des Pfads
  (`\Software\Microsoft\Windows\CurrentVersion\Run\<Wert>`), nicht der Wurzelname. Setzen kommt als Ereignis 13, Löschen als 12.
- **R7, erwarteter Zugriff:** Jeder Kindprozess erzeugt zusätzlich einen ProcessAccess des Clients auf das Kind mit
  `GrantedAccess=0x1fffff`. R7 muss den Zugriff auf eigene Kinder aus R1 zuordnen, statt ihn getrennt zu melden.
- **R9, Regelname:** Ein Kindprozess mit Miner-Kommandozeile trägt den Regelnamen `R1`, weil Sysmon nur die erste
  passende Regel nennt. Die Engine prüft die Kommandozeile deshalb selbst und verlässt sich nicht auf `RuleName`.
  R9 für Prozesse, die nicht vom Client abstammen, ist noch nicht getestet.
- **R5, Client-Image:** Das Laden der eigenen `Wow.exe` kommt als ImageLoad; beim Simulator ohne Signatur
  (`SignatureStatus=Unavailable`). R5 nimmt das Client-Image aus und vergleicht Pfade ohne Groß-/Kleinschreibung
  (`C:\Windows\System32` und `C:\WINDOWS\SYSTEM32` kommen beide vor).
- **R2, Hostname:** Bei einer Verbindung auf eine IP steht `DestinationHostname=-`; ein DNS-Ereignis gibt es dann nicht.
- **Neue Regelidee:** ProcessCreate enthält `IntegrityLevel`. Läuft der Client mit `High` (als Administrator gestartet),
  ist das eine eigene Warnung, weil eingeschleuster Code dann den Dienst angreifen könnte.
- **Menge:** Rund 33 ImageLoad-Ereignisse je Start des Simulators, sonst nur einzelne Ereignisse je Szenario.
- **Testdaten:** Die Ereignisse enthalten Benutzername, SID und Anmelde-IDs. Fixtures werden vor dem Einchecken anonymisiert.
- **Installation, Manifest-Fehler (12.11.2026):** Die zweite Installation nach einer Deinstallation scheiterte mit
  Exit-Code 13 („wevtutil.exe returned failure“, „Event manifest installation failed“; Sysmon 15.22, Windows 11
  Build 26300). Danach war der Ereignis-Publisher halb registriert (Registry-Schlüssel vorhanden, Kanal nicht lesbar),
  Dienst und Treiber fehlten, `C:\Windows\Sysmon64.exe` lag da. Derselbe Fehler ist für Sysmon 15 auf Windows Server 2025
  beschrieben; eine Ursache nennt Microsoft nicht, ein zweiter Versuch nach `sysmon -u force` soll gelingen.
  `install.ps1` räumt solche Reste deshalb weg und versucht es genau einmal neu; scheitert auch das, bleibt nichts zurück.
  `-u force` läuft nie, wenn ein Sysmon-Dienst oder der Treiber `SysmonDrv` vorhanden ist (erzwungenes Entladen eines
  Treibers hat laut Berichten Rechner neu gestartet). Der Weg „Reste wegräumen, dann installieren“ hat am 12.11.2026 am
  echten Sysmon funktioniert; der Neuversuch innerhalb desselben Laufs ist nur gegen einen Ersatz-Sysmon geprüft.

## 14. Entscheidungen bei der Umsetzung von M2

- **R9 außerhalb des Clients nur Alarm.** Die Sysmon-Regel für Miner-Kommandozeilen gilt maschinenweit. Beendet wird nur ein
  Prozess, den der Client gestartet hat; bei fremden Prozessen ist der Treffer ein Textvergleich ohne Bezug zum Client
  (ein Editor mit einer Datei `xmrig-notizen.txt` würde sonst beendet).
- **R3 und R5 abgestuft.** Programmdateien und Startup-Ordner alarmieren (HOCH), sonstige Dateien außerhalb des Spielordners
  werden nur protokolliert (MITTEL), bis der Lernmodus zeigt, was der echte Client schreibt. Unsignierte Module aus dem
  Spielordner sind kein Befund (die Bibliotheken des Clients sind oft unsigniert); das Ablegen dort fängt R3 ab.
- **R2 ohne Allowlist alarmiert jede Verbindung**, beendet aber nur mit `killOnUnknownRemote`. Loopback ist immer erlaubt.
- **Beenden nur nach Prüfung.** Ein Prozess wird nur beendet, wenn seine PID noch das Programm aus dem Ereignis ausführt.
  Geprüft wird über `QueryFullProcessImageName` mit eingeschränktem Handle, ohne den Speicher des Prozesses zu lesen.
- **Fail closed.** Kann der Dienst das Sysmon-Log nicht lesen (fehlt, kein Zugriff, Abo bricht ab), endet er mit Fehler,
  statt ohne Ereignisse weiterzulaufen. Eine nicht lesbare Zieladresse gilt bei R2 als nicht erlaubt.
- **Toast erst in M4.** Ein Dienst in Sitzung 0 kann keine Toasts anzeigen; das übernimmt die Tray-App. Bis dahin steht ein
  Alarm in der Konsole bzw. im Log und in `findings.db`.
- **R1, Konsolen-Host (erster Live-Lauf, 12.11.2026).** Windows startet für jedes Konsolenprogramm mit eigener Konsole
  `conhost.exe` als dessen Kindprozess (`\??\C:\WINDOWS\system32\conhost.exe 0x4`). Der Simulator ist ein Konsolenprogramm
  und wurde im Abnahmetest versteckt gestartet; R1 beendete ihn deshalb in jedem Szenario, auch in denen, die nur alarmieren
  sollen (2 von 5 fehlgeschlagen). Genau diese Form (Image im Systemordner, Kommandozeile nur NT-Pfad und Handle, optional
  `-ForceV1`) wird jetzt als R1 MITTEL protokolliert und beendet nichts. `conhost.exe` mit anderen Argumenten bleibt ein
  normales R1, weil es selbst Programme starten kann (`conhost.exe --headless cmd …`). Der echte Client ist ein
  Fensterprogramm und bekommt keinen Konsolen-Host; taucht einer auf, steht er im Log.
- **Abnahme bestanden (12.11.2026, Sysmon 15.22).** Zweiter Live-Lauf mit der Korrektur: alle fünf Szenarien erkannt,
  `spawn`, `miner-args` und `runkey` beendet, `connect` und `drop` nur alarmiert. Der aufgezeichnete Konsolen-Host
  (`… conhost.exe 0xffffffff -ForceV1`) ist als Fixture `r1-console-host.xml` übernommen.
- **Replay fragt keine laufenden Prozesse ab.** Beim Auswerten des Laufs meldete das Replay zu einer alten PID „läuft jetzt
  ein anderes Programm“ (die Prüfung vor dem Beenden hatte gegriffen). Im Replay wird der Beender jetzt gar nicht aufgerufen.
- **Reaktionszeit.** In beiden Live-Läufen lagen zwischen Ereignis und Befund 0,65 bis 1,15 s; das Ereignisprotokoll liefert in
  Schüben. Ein Kindprozess läuft also rund eine Sekunde, bevor er beendet wird. Das Abnahmekriterium (2 s) ist erfüllt,
  verhindern kann den Start aber nur M3 (`DisallowChildProcessCreation`). Ob ein eigener ETW-Abnehmer schneller wäre, ist
  offen.
- **Regelidee „Client läuft als Administrator“** (Abschnitt 13) ist nicht umgesetzt und wartet auf eine Entscheidung.
- **Windows-Dienst (12.11.2026).** Abnahme mit `acceptance-test.ps1 -InstalledService` bestanden: alle fünf Szenarien
  wie im Konsolenlauf (0,68 bis 1,08 s), Dienst läuft aus `C:\Program Files\RCEGuard` als `LocalSystem`, Start
  automatisch, abhängig von `Sysmon64`, und Windows hat ihn 5 s nach dem Beenden seines Prozesses neu gestartet. Noch
  nicht bestätigt: Start nach einem Neustart des Rechners, Entfernen durch `uninstall.ps1`, das Aufräumen bei
  gescheitertem Start. Die damals bekannte Lücke (Ereignisse aus der Zeit, in der der Dienst nicht läuft, wurden nicht
  nachgeholt) schließt die gespeicherte Position im Sysmon-Log, siehe unten.
  - *Ort:* `install.ps1` kopiert den veröffentlichten Dienst nach `C:\Program Files\RCEGuard`. Ein Dienst mit
    `LocalSystem` darf nie aus einem Ordner starten, den ein normaler Benutzer ändern kann (Repo, `artifacts\`), sonst
    wäre er selbst der Weg zu Systemrechten. Der Dienstpfad steht in Anführungszeichen.
  - *Laufzeit:* self-contained veröffentlicht (`build.ps1 -Publish`, rund 75 MB). Das SDK liegt hier im Benutzerprofil;
    darauf darf ein Systemdienst nicht angewiesen sein. Preis: Die mitgelieferte .NET-Laufzeit bekommt keine Updates
    über Windows Update, sondern nur mit einer neuen Veröffentlichung.
  - *Start und Ausfall:* automatischer Start, abhängig vom Sysmon-Dienst. Endet der Prozess unerwartet, startet Windows
    ihn neu (5 s, 5 s, danach alle 60 s). Kann der Dienst nicht arbeiten (Sysmon-Log fehlt, Konfiguration ungültig),
    beendet er den Prozess mit Fehler, statt sich sauber abzumelden; nur so greifen die Neustart-Regeln. Wird Sysmon
    gestoppt, stoppt Windows auch RCEGuard: Der Schutz ist dann sichtbar aus, statt still nichts zu sehen.
  - *Log:* `C:\ProgramData\RCEGuard\guard.log` (5 MB, eine Vorgängerdatei), weil ein Dienst keine Konsole hat. Der
    Ordner ist für Benutzer lesbar, aber nicht schreibbar; darauf baut später die Tray-App auf.
  - *Scheitert der Start bei der Installation*, wird der Dienst wieder entfernt, damit Windows ihn nicht endlos neu
    startet; der Sensor bleibt.
  - *Abnahme:* `acceptance-test.ps1 -InstalledService` prüft Szenarien, Registrierung und den Neustart nach Abbruch.
- **Enkelprozesse (12.11.2026): beim Beenden gesucht, nicht fortlaufend verfolgt.** Sysmon meldet nur direkte Kinder des
  Clients. Läuft das Kind beim Beenden noch, geht sein ganzer Baum mit. Ist es schon beendet (`cmd /c start payload`
  dauert Millisekunden, der Dienst braucht rund eine Sekunde; der alte Dienst meldete dann nur „already exited“ und ließ
  das Programm laufen), sucht der Dienst in der Prozessliste von Windows nach laufenden Programmen, die die PID des Kindes
  als Elternprozess nennen und nach ihm gestartet wurden, und beendet sie samt Baum. Die Startzeit des Kindes kommt aus
  dem Ereignis (`UtcTime`); ohne sie wird nicht gesucht, weil eine PID allein wiederverwendet sein kann. Gehört die PID
  inzwischen einem anderen Programm, bleibt alles unberührt, was nach dessen Start entstand.
  - *Grenzen:* Ein Programm, dessen Elternprozess selbst ein schon beendeter Enkel ist, wird nicht gefunden. Ein
    gefälschter Elternprozess (PPID-Spoofing) entgeht der Suche und schon der Sysmon-Regel.
  - *Verworfen für jetzt:* alle Prozessstarts des Rechners in Sysmon aufzeichnen. Das würde die Abstammung lückenlos
    machen, schriebe aber die Kommandozeilen aller Programme ins Sysmon-Log und widerspräche der Zusage, nur den Client
    zu beobachten. Das ist eine Entscheidung des Inhabers. Wirklich schließen kann die Lücke nur M3
    (`DisallowChildProcessCreation`): Dann entsteht das Kind gar nicht erst.
  - *Test:* Simulator-Szenario `--detach`; `tests/RCEGuard.Service.Tests` prüft den Beender gegen echte Prozesse.
- **Entprellen (12.11.2026).** Derselbe Alarm (Regel, Schwere, Client-Prozess, Ziel) wird einmal gemeldet und danach für
  `repeatWindowSeconds` (Standard 300, 0 schaltet ab) nur gezählt; Zähler und letzter Zeitpunkt stehen am Befund in
  `findings.db` (`repeats`, `last_time_utc`). Nach dem Fenster wird neu gemeldet, mit der Zahl der zurückgehaltenen
  Wiederholungen. Befunde mit Beenden werden nie zurückgehalten. Ein neuer Start des Clients ist ein neuer Prozess und
  alarmiert wieder. Gerechnet wird mit der Zeit der Ereignisse, damit ein Replay sich wie der Live-Lauf verhält.
- **Abnahme im installierten Dienst (12.11.2026, dritter Lauf mit `-InstalledService`).** Alle sechs Szenarien bestanden
  (0,57 bis 1,09 s), dazu Registrierung und Neustart. `detach`: `cmd.exe (36060): already exited, left behind:
  cmd.exe (544) terminated`, kein Programm mit der Testmarke lief weiter. Die Spalten `repeats` und `last_time_utc`
  wurden in der vorhandenen `findings.db` ergänzt.
- **Entprellen im installierten Dienst (12.11.2026, ohne Admin-Rechte direkt mit dem Simulator geprüft).** Neuer Schalter
  `--repeat [Anzahl]` wiederholt ein Szenario im selben Prozess. Drei Verbindungen zu derselben Adresse bei laufendem
  Client: eine Meldung im Log, `repeats = 2` am Befund. Das Abnahmeskript hat dafür das siebte Szenario `repeat`
  (genau eine R2-Meldung); es lief bisher nur gegen den Ersatz-Dienst (PowerShell 7 und 5.1, dazu eine Fehlvariante mit
  drei Meldungen, die durchfällt), noch nicht als Administrator.
- **R2: Verbindungen kommen spät und manchmal gar nicht (12.11.2026).** Zwei Beobachtungen aus dieser Prüfung:
  - *Verzögerung im Sensor.* Sysmon schreibt eine Verbindung 1,3 bis 2,9 s nach dem Verbindungsaufbau ins Log (38
    aufgezeichnete Ereignisse, im Mittel 2,0 s; `UtcTime` gegen `TimeCreated`), in Schüben im Sekundentakt. Der Befund
    entsteht also rund 2 bis 4 s nach der Verbindung. Die Angabe „ms after the event“ im Log rechnet ab dem Log-Eintrag und zeigt das nicht; das
    Abnahmekriterium (2 s) gilt bei R2 deshalb nur für die Strecke ab dem Log-Eintrag.
  - *Fehlende Meldungen.* Eine einzelne Verbindung wurde nicht gemeldet, wenn der Client kurz danach endete: sofort
    oder nach 1 s in 6 von 6 Versuchen, nach 3 s in 2 von 6, nach 8 s nie (4 von 4 gemeldet). Bei mehreren Verbindungen
    ohne Wartezeit fehlte jeweils genau eine (3 → 2, 6 → 5). Im M1-Mitschnitt wurde eine solche Verbindung dagegen
    aufgezeichnet, ebenso eine im zweiten Abnahmelauf, obwohl der Client dort rund eine Sekunde nach dem Start beendet
    wurde.
  - *Ursache liegt im Sensor (bestätigt mit `show-events.ps1 -Last 80 -Id 3`).* Im Sysmon-Log stehen für die
    betroffenen Prozesse keine Verbindungsereignisse. Der Dienst hat alle 25 Ereignisse gemeldet oder gezählt, die Sysmon
    seit seinem Start geschrieben hat (Abgleich je PID gegen `findings.db`). Warum Sysmon sie nicht schreibt, ist nicht
    belegt. Bekannt ist, dass Sysmon bei Ereignis 3 als Programm `<unknown process>` einträgt, wenn es den Prozess nicht
    mehr zuordnen kann; ein solches Ereignis passt nicht auf die Regel `Image is <Client>` und würde verworfen. Dazu
    passt nicht alles (zwei Aussetzer bei 3 s Restlaufzeit, zwei Treffer trotz beendetem Client).
  - *Nicht gebaut:* eine zweite Regel, die auch Verbindungen von `<unknown process>` aufzeichnet. Sie würde die
    Vermutung prüfen, schriebe aber Verbindungen fremder Programme ins Log, die der Dienst keinem Client zuordnen kann.
    Entscheidung des Inhabers.
  - *Folge.* Der echte Client läuft lange, seine eigenen Verbindungen sind davon nicht betroffen; eine kurze Verbindung
    unmittelbar vor dem Ende des Clients kann fehlen. R2 mit `killOnUnknownRemote` käme in jedem Fall erst nach rund 3 s.
    Verhindern können unbekannte Verbindungen nur die Firewall-Regeln aus M3.
- **Position im Sysmon-Log (12.11.2026): Ereignisse aus der Ausfallzeit werden nachgeholt.** Der Dienst merkt sich
  Record-ID und Zeit des zuletzt verarbeiteten Ereignisses in `sysmon-position.json` im Datenordner (nach einem Befund
  sofort, sonst höchstens einmal je Sekunde, dazu beim Beenden; Schreiben über eine Zwischendatei). Beim Start liest er
  zuerst alles, was danach ins Log geschrieben wurde, und danach wie bisher die neuen Ereignisse.
  - *Gespeichert wird Record-ID plus Zeit, nicht das Windows-Lesezeichen (`EventBookmark`) selbst.* Die Zeit erkennt
    ein ersetztes Log: Gibt es den Record mit der gespeicherten ID nicht mehr oder trägt er eine andere Zeit (Sysmon
    neu installiert, Log geleert), wird das ganze Log gelesen. Sind Ereignisse nach der Position schon überschrieben,
    meldet der Dienst, wie viele fehlen. Der allererste Start liest nichts Altes und speichert die Position des
    neuesten Eintrags.
  - *Das Abo setzt über ein Lesezeichen des gespeicherten Records fort, nicht über eine Abfrage auf die Record-ID
    (Befund 12.11.2026, 21:17).* Der erste Stand abonnierte mit der Abfrage `EventRecordID > N` und „vorhandene
    Ereignisse mitlesen“. Im Abnahmelauf fielen damit alle sieben Szenarien durch: Der Dienst bekam nach dem Start
    kein einziges neues Ereignis (2,5 Minuten lang, ohne Fehlermeldung), das Nachholen nach dem Neustart
    funktionierte dagegen (321 Ereignisse, 18 Befunde, Client beendet). Nachgestellt ohne Admin-Rechte am Kanal
    `Microsoft-Windows-PowerShell/Operational`, der wie das Sysmon-Log von einem Anbieter mit Manifest beschrieben
    wird: Mit der Abfrage auf die Record-ID kommen die vorhandenen Ereignisse (5 von 5) und danach keines der neu
    geschriebenen (0 von 3); mit einem Lesezeichen kommen beide (5 von 5, 3 von 3), ebenso ohne Abfrage wie im Stand
    davor. Am Application-Log liefern beide Formen auch neue Ereignisse, deshalb liefen die Tests des ersten Stands
    durch. Warum Windows sich so verhält, ist nicht geklärt; gemessen auf Windows 11 (Build 26300). Jetzt liest der
    Dienst den Record mit der gespeicherten ID, nimmt dessen Lesezeichen und abonniert ohne Abfrage ab dort. Gibt es
    den Record nicht, liest er das Log von vorn.
  - *Selbstprüfung gegen ein stummes Abo.* Der Fehler oben blieb 2,5 Minuten unbemerkt, und der Dienst sah dabei
    gesund aus. Deshalb sieht der Dienst selbst ins Log, wenn 15 s lang nichts kam: Liegt dort ein Ereignis, das
    neuer ist als das zuletzt gelieferte und älter als 15 s, schreibt er „RCEGuard cannot run“ mit beiden Record-IDs
    und beendet sich mit Fehler. Windows startet den Dienst neu, und der Start holt das Verpasste nach. Kosten: ein
    Lesezugriff auf den neuesten Eintrag alle 15 s im Leerlauf. Bliebe ein Abo dauerhaft stumm, liefe der Dienst
    dadurch als Abfrage im Takt der Neustarts weiter (5 s, 5 s, dann 60 s), statt blind zu sein.
  - *Nachgeholte Ereignisse lösen dieselben Aktionen aus*, im Log mit dem Zusatz „written while RCEGuard was not
    running“. Weil sie alt sein können, gilt zusätzlich: Ein Prozess wird nur beendet, wenn er vor dem Ereignis
    gestartet wurde (Startzeit über ein Handle mit eingeschränkten Rechten; gleiche PID und gleiches Programm in einem
    jüngeren Prozess bleibt unberührt, etwa ein neu gestarteter Client). Die Suche nach zurückgelassenen Programmen
    läuft nur, wenn das Ereignis höchstens 30 s alt ist: Sie setzt voraus, dass die PID des beendeten Kindes
    inzwischen niemand anderem gehört hat, und das gilt nur für kurze Zeit. Die Startzeit-Prüfung gilt auch im
    laufenden Betrieb und kostet dort nichts.
  - *Folge der Entscheidung:* Lief derselbe Client während eines langen Ausfalls weiter und hat in dieser Zeit etwas
    Kritisches getan, wird er beim Start des Dienstes beendet. Das ist gewollt: Die Regel galt auch, als niemand
    hinsah.
  - *Grenzen:* Der Zustand der Regeln (bekannte Kinder für R7, Zähler fürs Entprellen) lebt im Speicher und beginnt
    nach einem Neustart leer. Wird der Dienst innerhalb der Sekunde zwischen zwei Speicherungen hart beendet, liest er
    bis zu eine Sekunde an Ereignissen ohne Befund noch einmal. Kann die Datei nicht geschrieben werden, läuft der
    Dienst weiter und warnt einmal.
  - *Test:* Entscheidungslogik in `LogResumeTests`; Abo, Positionsdatei und die ganze Dienstschleife über Stoppen und
    Starten in `tests/RCEGuard.Service.Tests` gegen das Application-Log dieses Rechners (nur lesend), weil das
    Sysmon-Log Admin-Rechte braucht. Der Beender mit Startzeit-Prüfung und Altersgrenze gegen echte Prozesse.
    Seit dem Befund oben zusätzlich gegen `Microsoft-Windows-PowerShell/Operational` (Kanal derselben Bauart wie das
    Sysmon-Log, für normale Benutzer lesbar; ein Start der Windows PowerShell 5.1 schreibt dort Ereignisse): Ereignisse,
    die nach dem Start des Abos geschrieben werden, kommen an, nach den vorhandenen, in Reihenfolge und ohne
    Doppelte; die Dienstschleife verarbeitet ein solches Ereignis und rückt die Position vor; ein Abo, das nichts
    liefert, während das Log wächst, beendet den Dienst; ein stilles Log beendet ihn nicht. Gegenprobe: Mit dem alten
    Abo fallen vier dieser Tests durch. Lehre: Ein Ersatz-Log muss von derselben Bauart sein wie das echte, und ein
    Test des Abos muss Ereignisse enthalten, die nach dem Abonnieren entstehen.
  - *Abnahme:* Das Abnahmeskript startet während des Ausfalls des Dienstes ein Szenario und verlangt Befund und
    Beenden danach. Im Lauf vom 12.11.2026, 21:17 bestand genau dieser Teil gegen Sysmon (Befund 60 s nach dem
    Ereignis, mit Zusatz im Log, Client beendet; `sysmon-position.json` geschrieben; erster Start: „No saved
    position“). Die Prüfung „Neustart nach Abbruch“ fiel im selben Lauf durch, weil das Skript 30 s wartete, Windows
    den Dienst nach dem dritten Abbruch des Tages aber erst nach 60 s neu startet (so eingestellt: 5 s, 5 s, dann
    60 s; Zähler für einen Tag). Das Skript wartet jetzt bis 90 s und nennt die Dauer.
  - *Abnahme mit dem korrigierten Abo (12.11.2026, 21:49, installierter Dienst):* Der Dienst setzte nach Record 5084
    fort, holte 124 Ereignisse nach (6 Befunde, alle Prozesse längst beendet, nichts angefasst) und bekam danach die
    neuen Ereignisse. Sechs von sieben Szenarien bestanden mit 342 bis 1015 ms, darunter `repeat` zum ersten Mal als
    Administrator (ein Befund, `repeats = 2` in `findings.db`) und `detach` (zurückgelassenes Programm beendet). Alle
    Dienstprüfungen bestanden: Neustart nach 61 s (dritter Abbruch des Tages), danach 40 Ereignisse nachgeholt, das
    während des Ausfalls gestartete Programm 60 s nach dem Ereignis gefunden, Kind und Client beendet. Die
    Selbstprüfung schlug in den Minuten danach nicht fälschlich an.
  - *Das eine FAIL (`spawn`) war ein Fehler des Skripts:* Der Dienst fand das Szenario nach 1052 ms und beendete
    Kind und Client. Das Skript zählte aber auch die drei alten R1-Befunde mit, die der Dienst direkt nach seinem
    Start nachholte (Ereignisse aus Trockenläufen, 1179 s alt), und nahm deren Alter als Reaktionszeit. Es
    überspringt jetzt Zeilen mit dem Zusatz „written while RCEGuard was not running“; geprüft an den echten Logzeilen
    dieses Laufs in PowerShell 7 und 5.1 (13 Zeilen, ein gezählter Befund: R1 mit 1052 ms).
  - *Abnahme bestanden (12.11.2026, 21:59, installierter Dienst, korrigiertes Skript):* alle sieben Szenarien mit
    118 bis 1136 ms, alle sieben Dienstprüfungen. Start: ein Ereignis nachgeholt, kein Befund. Neustart nach 62 s
    (vierter Abbruch des Tages), danach 39 Ereignisse nachgeholt, das während des Ausfalls gestartete Programm 61 s
    nach dem Ereignis gefunden, Kind und Client beendet. `sysmon-position.json` stand danach auf dem letzten Record.
- **Start nach Rechner-Neustart (12./13.11.2026): geprüft.** Drei Systemstarts laut System-Log: 12.11. 22:54:39 und
  22:55:46 (Neustart durch den Inhaber, der zweite von Windows Update ausgelöst), danach heruntergefahren, Kaltstart am
  13.11. 13:27:14. Der Dienst startete jedes Mal von selbst, 12 s, 10 s und 10 s nach dem Kernel, im dritten Fall
  0,2 s nach dem Sysmon-Dienst (Prozessstartzeiten). Er setzte jeweils an der gespeicherten Position fort (nach Record
  5853, 5855, 5858) und holte die zwei Ereignisse nach, die Sysmon bei seinem eigenen Start schreibt; beim ersten
  Start war nichts nachzuholen. Keine Zeile „cannot run“. Danach ohne Admin-Rechte mit dem Simulator geprüft:
  `--spawn` nach 831 ms erkannt, Kind und Client beendet; `--connect` nach 1586 ms gemeldet, Client läuft weiter.
  Der Schnellstart von Windows ist auf dem Testrechner eingeschaltet; ob der Dienst nach einem Aufwachen aus dem
  Ruhezustand (Herunterfahren mit Schnellstart, Energiesparen) weiter Ereignisse bekommt, ist damit nicht geprüft:
  Die Prozessstartzeit zeigt, dass der Dienst am 13.11. neu gestartet und nicht aufgeweckt wurde.
- **Entfernen mit `uninstall.ps1` (13.11.2026, erster Lauf mit installiertem Dienst): fast alles weg, drei Reste.**
  Verglichen wurde ohne Admin-Rechte vor und nach dem Lauf. Weg waren: Dienst `RCEGuard` samt Registry-Eintrag,
  `C:\Program Files\RCEGuard` (225 Dateien), `C:\ProgramData\RCEGuard`, Dienst `Sysmon64`, Treiber `SysmonDrv`
  (Registry-Eintrag und `C:\Windows\SysmonDrv.sys`), `C:\Windows\Sysmon64.exe`, Ereignis-Anbieter und -Kanal von
  Sysmon in der Registry, alle Prozesse. Geblieben sind:
  - *Die Logdatei von Sysmon* (`…\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`, 7,2 MB). `sysmon -u`
    entfernt den Kanal, nicht die Datei; darin steht alles Aufgezeichnete (Befehlszeilen, Benutzername, Ziele).
    Eine spätere Neuinstallation schreibt in derselben Datei weiter (die Record-IDs liefen am 12.11. über mehrere
    Installationen durch).
  - *Der Vermerk über die Sysinternals-Lizenz* (`HKCU\Software\Sysinternals\System Monitor`, `EulaAccepted=1`), den
    `sysmon -accepteula` in die Registry des installierenden Benutzers schreibt.
  - *Zwei Ereignisquellen* unter `HKLM\…\Services\EventLog\Application`: `RCEGuard` und `RCEGuard.Service`. Die legt
    nicht `install.ps1` an, sondern der laufende Dienst: Der .NET-Diensthost (`AddWindowsService`) schreibt Start und
    Stopp des Dienstes und alle Meldungen ab Warnung ins Windows-Anwendungslog. Das war keine Entscheidung und stand
    nirgends: Im Anwendungslog dieses Rechners liegen 112 Einträge der Quelle `RCEGuard.Service` (93 Befunde als
    „Fehler“, 19 Warnungen) und 18 Start-/Stopp-Einträge.
  - *Umsetzung (Regel: Was `install.ps1` anlegt, entfernt `uninstall.ps1`):* `Uninstall-GuardService` entfernt die
    beiden Ereignisquellen. `install.ps1` hält in `install-state.json` fest, ob es Logdatei und Lizenzvermerk vor der
    Installation schon gab (`sysmonLogFileCreated`, `sysmonEulaKeyCreated`) und unter welchem Benutzer installiert
    wurde (`installedBySid`). `uninstall.ps1` entfernt die Logdatei nur, wenn die Installation sie gebracht hat und
    `-KeepData` fehlt (wie beim Datenordner), den Lizenzvermerk nur, wenn die Installation ihn gebracht hat und
    derselbe Benutzer deinstalliert; sonst nennt es den Rest. Lässt sich die Logdatei nicht löschen (noch geöffnet),
    warnt das Skript und bricht nicht ab. Scheitert schon die Installation von Sysmon, räumt `install.ps1` beides
    wieder ab. Eine Statusdatei ohne die neuen Werte zählt als „nicht von uns“.
  - *Was bleibt:* Die Einträge im Anwendungslog selbst lassen sich nicht einzeln löschen.
  - *Offene Entscheidung des Inhabers:* ob der Dienst weiter ins Anwendungslog schreiben soll. Dafür spricht: Dort
    suchen Administratoren, und die Einträge überleben das Löschen von `guard.log`. Dagegen: Es war nicht geplant,
    die Einträge bleiben nach dem Entfernen zurück, und das Anwendungslog kann jeder lokale Benutzer lesen (das gilt
    für `guard.log` allerdings auch). Bis zur Entscheidung bleibt es an und ist in der README beschrieben.
  - *Test:* Die neuen Funktionen (`Remove-SysmonTraces`, `Get-StateValue`, `Remove-GuardEventSources`) liefen ohne
    Admin-Rechte gegen Stellvertreter (Datei im Temp-Ordner, Schlüssel unter `HKCU`) in PowerShell 7 und 5.1, auch mit
    geöffneter Datei, mit belegtem Nachbarschlüssel und mit einer alten Statusdatei. `install.ps1` und `uninstall.ps1`
    selbst liefen mit den Änderungen noch nicht.
  - *Lauf mit den geänderten Skripten (13.11.2026, 13:40, als Administrator):* Die Reste des ersten Laufs wurden
    einmalig von Hand gelöscht, dann `install.ps1` (mit `-DownloadSysmon -AcceptSysmonEula`) und `uninstall.ps1`.
    Der Dienst lief laut Anwendungslog von 13:40:30 bis 13:40:42. Danach war bei derselben Prüfung ohne Admin-Rechte
    nichts mehr vorhanden: keine Dienste, kein Treiber, keine Ordner, keine Sysmon-Dateien im Windows-Ordner, kein
    Anbieter und kein Kanal, keine Logdatei von Sysmon, kein Lizenzvermerk (auch der dann leere Schlüssel
    `HKCU\Software\Sysinternals` nicht), keine Ereignisquellen, keine Prozesse, kein Download-Ordner. Die Logdatei
    ließ sich also direkt nach `sysmon -u` löschen. Geblieben sind wie beschrieben die Einträge im Anwendungslog;
    ohne die Ereignisquelle zeigt Windows deren Text nicht mehr an.
  - *Nicht geprüft:* `-KeepData`; Entfernen unter einem anderen Benutzer als dem installierenden; eine Installation
    auf einem Rechner, auf dem Logdatei oder Lizenzvermerk schon vorher da waren (dort müssen beide bleiben; das
    lief nur gegen Stellvertreter).
- **Dienst kann nicht starten (13.11.2026): Entfernen gehärtet, eigener Test, noch nicht als Administrator gelaufen.**
  `install.ps1` entfernt einen Dienst wieder, der nicht startet (`Install-GuardService`); der Sensor bleibt, und
  `install-state.json` sagt „kein Dienst“. Zwei Ursachen ließen sich ohne Admin-Rechte in der Konsole nachstellen:
  ein Dienst-Build, dem `RCEGuard.Core.dll` fehlt (Prozess endet nach 0,65 s mit unbehandelter Ausnahme, kein Log),
  und eine `appsettings.json`, die kein gültiges JSON ist (nach 1 s „RCEGuard cannot run: Configuration is not valid
  JSON“, Exit-Code 1).
  - *Lücke beim Lesen des Skripts:* Im zweiten Fall beendet sich der Dienst selbst, und Windows startet ihn nach 5 s
    neu. `Uninstall-GuardService` stoppte erst und löschte dann; trifft das Stoppen einen Dienst, der gerade stirbt
    oder gerade wieder startet, schlägt es fehl, die Registrierung bleibt, und Windows startet einen
    LocalSystem-Dienst, der nicht laufen kann, immer wieder. Ob das auf diesem Rechner wirklich eintritt, ist nicht
    gemessen; die Reihenfolge ist jetzt so, dass es nicht darauf ankommt: erst den Dienst deaktivieren (einen
    deaktivierten Dienst startet auch die Wiederherstellung nicht), dann regulär stoppen (ein Fehlschlag ist kein
    Abbruch), dann Prozesse beenden, die aus `C:\Program Files\RCEGuard` laufen, dann löschen. Der Ordner wird bis zu
    10 s lang wiederholt gelöscht, weil ein eben beendeter Prozess seine Dateien noch kurz hält. Scheitert auch das
    Entfernen, sagt die Fehlermeldung das und nennt `uninstall.ps1`.
  - *Test `scripts\install-test.ps1`:* installiert auf einem Rechner ohne RCEGuard und ohne Sysmon dreimal (Build
    ohne `RCEGuard.Core.dll`, kaputte `appsettings.json`, fehlerfrei) und entfernt einmal. Nach den beiden
    Fehlschlägen müssen Dienst, Ordner und Ereignisquellen weg sein, der Sensor noch da, die Statusdatei „kein
    Dienst“ sagen und nach 8 s nichts zurückgekommen sein; am Ende muss der Rechner aussehen wie vorher. Was schon
    vorher da war (Logdatei oder Lizenzvermerk eines früheren Sysmon), muss bleiben. `-ListOnly` listet ohne
    Admin-Rechte, was von einer Installation auf dem Rechner ist; das ersetzt den Vergleich von Hand vom Vormittag.
  - *Geprüft:* das Testskript mit Stellvertretern für `install.ps1` und `uninstall.ps1` in PowerShell 7 und 5.1
    (jede Zeile läuft unter Strict Mode; die Prüfungen zu Sysmon und zum laufenden Dienst fallen dabei wie erwartet
    durch, die zur Fehlermeldung bestehen, mit „Entfernen fehlgeschlagen“ als Meldung fallen auch sie durch).
    `-ListOnly` in beiden Versionen auf dem leeren Rechner.
  - *Nicht geprüft:* das gehärtete `Uninstall-GuardService` und der Test selbst als Administrator. Dienste lassen
    sich ohne Admin-Rechte nicht anlegen, einen Stellvertreter dafür gibt es nicht.
  - *Lauf als Administrator (13.11.2026, 13:51): Fehlstart-Fälle bestanden, Entfernen von Sysmon gescheitert.*
    Schritte A, B und C: alle 18 Prüfungen bestanden. Nach beiden Fehlschlägen waren Dienst, Ordner und
    Ereignisquellen weg, der Sensor blieb, die Statusdatei sagte „kein Dienst“, nach 8 s kam nichts zurück; die
    Installation danach lief (Dienst „Running“, Autostart). Das System-Log bestätigt die vermutete Lücke: Im Fall B
    meldete Windows um 13:50:50 „unerwartet beendet, Neustart in 5000 ms“, in derselben Sekunde stellte das Skript
    den Dienst auf „deaktiviert“.
  - *Dabei gesehen:* Der Build ohne `RCEGuard.Core.dll` scheitert nicht beim Starten selbst. Windows meldet den
    Dienst als gestartet, der Prozess stirbt, und Windows startet ihn neu (13:50:08, :17, :25); `install.ps1` merkte
    das erst nach 30 s Wartezeit. `Start-GuardService` sieht jetzt auch auf den Zustand des Dienstes und meldet
    „ended right after it was started“, sobald er zwischen zwei Neustarts gestoppt ist.
  - *Schritt D gescheitert: Sysmon ist beim Entfernen abgestürzt.* Zeitablauf: 13:51:01 Konfiguration neu geladen
    (`sysmon -c`), 13:51:04 Dienst abonniert, 13:51:05 Dienst gestoppt, 13:51:06 Anwendungsfehler `Sysmon64.exe`
    15.22 (Ausnahme 0xc0000005 in `ntdll.dll`), `sysmon -u` endete mit Exit-Code 5, Windows meldete „Sysmon64
    unerwartet beendet“. Danach: Treiber, Ereignis-Anbieter und -Kanal weg; Dienst `Sysmon64` noch registriert
    (gestoppt, Autostart), `Sysmon64.exe`, Logdatei, Lizenzvermerk und Datenordner noch da. `uninstall.ps1` brach an
    der Stelle ab; die Statusdatei blieb, ein zweiter Lauf ist also möglich. Die beiden Läufe davor (13:35, 13:40)
    gingen durch. Warum Sysmon abstürzte, ist nicht geklärt; auffällig ist nur der Abstand: `sysmon -u` kam 5 s nach
    einem `sysmon -c` und 1 s nach dem Ende des Abos, in den Läufen davor nach 12 s oder mehr und ohne `sysmon -c`.
  - *Umsetzung:* `Uninstall-Sysmon` in `SysmonTools.ps1` glaubt dem Exit-Code nicht mehr. Es sieht nach (bis 10 s),
    ob Dienst, Treiber und Ereignis-Anbieter weg sind. Wenn nicht, versucht es `sysmon -u` nach 3 s noch einmal:
    mit `force`, wenn der Treiber schon weg ist (Sysmon macht dann weiter, obwohl Teile fehlen), ohne `force`,
    solange der Treiber da ist (die Regel aus M1 bleibt: kein erzwungenes Entfernen eines geladenen Treibers). Ist
    danach noch etwas da, bricht `uninstall.ps1` mit der Ausgabe beider Versuche ab und entfernt sonst nichts, damit
    ein weiterer Lauf nach einem Neustart weitermachen kann. Den Treiber erkennt `Test-SysmonDriverPresent` jetzt
    auch an seinem Registry-Eintrag; ohne Admin-Rechte listet Windows ihn nicht. `install-test.ps1` schreibt die
    vollständigen Meldungen der Skripte in die Ergebnisdatei (im Lauf oben ging Sysmons Ausgabe verloren).
  - *Geprüft:* `Uninstall-Sysmon` und `Start-GuardService` mit Stellvertretern für Sysmon und für den Dienst in
    PowerShell 7 und 5.1 (sauber; Exit-Code 5 ohne Rest; halb entfernt mit und ohne Treiber; zweimal gescheitert;
    Exit-Code 0 mit Rest; Dienst stirbt wortlos, mit Grund, ist weg).
  - *Nicht geprüft:* ob `sysmon -u force` den halb entfernten Zustand auf dem Testrechner wirklich abräumt.
  - *Zweiter Lauf von `uninstall.ps1` (13.11.2026, gegen 15:03): nichts entfernt.* Der Zustand war danach
    unverändert, in den Windows-Logs steht zu dem Lauf nichts, und die Ausgabe des Skripts liegt nicht vor (sie
    stand nur im Fenster). Deshalb schreibt `uninstall.ps1` jetzt bei einem Fehlschlag beide Sysmon-Aufrufe mit
    Ausgabe und den Grund nach `C:\ProgramData\RCEGuard\uninstall.log`.
  - *Ursache der Sackgasse (aus dem Zustand und der Windows-Dokumentation, nicht aus der Ausgabe von Sysmon):*
    Der Dienst `Sysmon64` ist als geschützter Dienst registriert (`sc qprotection`: „Antischadsoftware, gering“,
    Registry-Wert `LaunchProtected = 3`). Windows erlaubt bei einem solchen Dienst nur `sc start`, `sc qc`,
    `sc config start=auto`, `sc interrogate` und `sc sdshow`; Löschen, Stoppen und Umkonfigurieren sind jedem
    ungeschützten Prozess verwehrt, auch einem Administrator. Zum Deinstallieren muss der laufende Dienst den Schutz
    selbst ablegen („Protecting anti-malware services“, Abschnitt „Unregistering the service“). Sysmon ist am 13.11.
    um 13:51:06 abgestürzt, bevor es dazu kam; `sysmon -u` endete mit Exit-Code 5 (das ist „Zugriff verweigert“).
    Jeder weitere `sysmon -u` läuft gegen dieselbe Wand. In Microsofts Forum ist dasselbe Bild mehrfach beschrieben
    („DeleteService failed: Access is denied“, auch mit `-u force`), ohne bestätigte Lösung.
  - *Dabei gesehen:* Sysmon ist auf diesem Rechner (Windows 11, Build 26300) öfter beim Entfernen abgestürzt als
    bemerkt: Windows führt Absturzberichte für `Sysmon64.exe` 15.22 auch vom 12.11. 15:00 (0xc0000409 im Programm
    selbst, aus dem Download-Ordner gestartet) und vom 13.11. 13:35 (0xc0000005 in `ntdll.dll`). Der Lauf um 13:35
    ging trotzdem durch; der Absturz kam dort offenbar erst, nachdem der Dienst sich ausgetragen hatte.
  - *Umsetzung:* `Uninstall-Sysmon` erkennt die Sackgasse (nur noch der Dienst da, gestoppt, geschützt, Treiber und
    Ereignis-Anbieter weg) und sagt, was los ist. Der Ausweg ist ein eigener Schalter,
    `uninstall.ps1 -RemoveStuckSysmonService`: Er löscht die Registrierung des Dienstes aus der Registry
    (`HKLM\SYSTEM\CurrentControlSet\Services\<Dienst>`), sonst nichts, und nur in genau diesem Zustand. Windows
    liest seine Dienste beim Start aus der Registry; nach einem Neustart ist der Dienst weg, und ein weiterer Lauf
    von `uninstall.ps1` räumt den Rest ab (Sysmon wird dann nicht mehr aufgerufen, weil nichts mehr registriert
    ist). Vor dem Neustart sagt ein weiterer Lauf nur, dass der Neustart fehlt. Ohne Schalter fasst das Skript die
    Registry nicht an: Das ist ein Eingriff von Hand in Sysmons Installation, den der Inhaber auslöst, nicht das
    Skript von sich aus.
  - *Geprüft:* mit Stellvertretern in PowerShell 7 und 5.1 (Sysmon und Dienstliste gestellt, Registry-Schlüssel
    unter `HKCU`): Sackgasse ohne und mit Schalter, Lauf vor und nach dem „Neustart“, Schalter in jedem anderen
    Zustand wirkungslos (Dienst nicht geschützt, läuft noch, mehr als der Dienst übrig, Treiber registriert), dazu
    eine Kopie von `uninstall.ps1` ohne Administrator-Zwang gegen einen Stellvertreter-Datenordner über alle vier
    Läufe. Die neue Zustandsabfrage liest den echten Rechner richtig (gestoppt, geschützt, Schlüssel da).
  - *Nicht geprüft:* ob Windows den Dienst nach dem Löschen des Schlüssels und einem Neustart wirklich fallen lässt;
    ob ein Administrator den Schlüssel löschen darf (die Zugriffsliste sagt ja). Offen ist auch, ob der
    Registry-Schlüssel `Control\WMI\Autologger\EventLog-Microsoft-Windows-Sysmon-Operational` ein Rest des
    Absturzes ist oder nach jedem `sysmon -u` bleibt; er ist ohne Admin-Rechte nicht lesbar.
  - *Lauf als Administrator (14.11.2026): der Ausweg trägt.* Der Inhaber hat `uninstall.ps1
    -RemoveStuckSysmonService` ausgeführt, Windows neu gestartet (00:19:05 angefordert, 00:19:29 gestartet) und
    `uninstall.ps1` noch einmal ausgeführt. Stand um 00:21: Windows führt den Dienst `Sysmon64` nicht mehr, im
    System-Log steht seit dem Start kein Fehler zu Sysmon, und weg sind `Sysmon64.exe`, die Logdatei von Sysmon,
    der Lizenzvermerk (samt leerem Schlüssel `HKCU:\Software\Sysinternals`) und der Datenordner;
    `install-test.ps1 -ListOnly` meldet „Nothing of an RCEGuard installation is on this machine“. Damit ist
    bestätigt: Ein Administrator darf den Schlüssel löschen, und Windows lässt den geschützten Dienst nach dem
    Neustart fallen. Die Ausgabe der beiden Läufe liegt nicht vor; `uninstall.log` ist mit dem Datenordner
    entfernt worden, wie vorgesehen.
  - *Berichtigung: kein Rest.* Zunächst stand hier, der Registry-Schlüssel
    `Control\WMI\Autologger\EventLog-Microsoft-Windows-Sysmon-Operational` sei übrig geblieben. Das war ein
    Fehler der Abfrage, kein Befund: `Test-Path` antwortet ohne Admin-Rechte unterhalb von
    `HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger` für jeden Namen mit „True“, auch für einen
    erfundenen (geprüft in PowerShell 7 und 5.1; `reg query` und `OpenSubKey` sagen richtig „nicht da“). An den
    anderen Stellen, die die Auflistung liest (`Services`, `EventLog\Application`, `WINEVT\Channels` und
    `Publishers`, `HKCU:\Software\Sysinternals`), antwortet `Test-Path` für einen erfundenen Namen richtig mit
    „False“. Ob der Schlüssel am 13.11. nach dem Absturz noch da war, lässt sich deshalb nicht mehr sagen.
    Lehre: Eine Abfrage, die „da“ meldet, einmal mit einem Namen gegenprüfen, den es sicher nicht gibt.
  - *Vollständiger Lauf von `install-test.ps1` (14.11.2026, 00:24): ALL PASSED, 21 von 21.* Schritt A: Der Build
    ohne `RCEGuard.Core.dll` wurde nach rund 3 s als Fehlschlag gemeldet („ended right after it was started“:
    Dienst installiert 00:24:22, abgestürzt 00:24:23, deaktiviert 00:24:25) statt nach 30 s wie am 13.11.
    Schritt B: Meldung mit dem Grund aus dem Log des Dienstes („not valid JSON“); auch hier meldete Windows
    „unerwartet beendet, Neustart in 5000 ms“, zwei Sekunden bevor das Skript den Dienst deaktivierte, und nichts
    kam zurück. Schritt C: Dienst „Running“, Autostart. Schritt D: `uninstall.ps1` ohne Fehler, der Rechner sah
    aus wie vor dem Test; kein Absturzbericht für Sysmon, Treiber um 00:24:52 entladen.
  - *Aus dem Lauf:* Der Autologger-Schlüssel war (mit Admin-Rechten gelesen) vor dem Test nicht da, während der
    Installation da, nach dem Entfernen nicht da: `sysmon -u` räumt ihn ab, `uninstall.ps1` muss nichts tun.
    `install-test.ps1` zählt ihn jetzt als Teil der Installation und fragt ihn über `OpenSubKey` ab
    (`Test-MachineKey`). Und: `sysmon -u` kam in diesem Lauf rund 3 s nach der Installation und ging durch. Der
    kurze Abstand, der am 13.11. als einzige Auffälligkeit notiert wurde, erklärt den Absturz also nicht; die
    Ursache bleibt offen.
- **Offen in M2:** Verhalten nach dem Aufwachen aus dem Ruhezustand; Entscheidung des Inhabers, ob der Dienst
  weiter ins Windows-Anwendungslog schreibt. Die Selbstprüfung gegen ein stummes Abo hat im echten Dienst noch nie ausgelöst (das Abo liefert);
  sie ist nur in den Tests mit einem stummen Ersatz-Abo geprüft.

## 15. Entscheidungen bei der Umsetzung von M3

**Schritte.** (1) Firewall-Regeln berechnen und Konfiguration, im Kern, ohne Betriebssystem. (2) Der Dienst schreibt die
Regeln in die Windows-Firewall, hält sie aktuell, sperrt nach einem Befund mit Beenden und gibt wieder frei; `uninstall.ps1`
entfernt die Regeln. (3) Exploit Protection (`DisallowChildProcessCreation`) in `install.ps1` und `uninstall.ps1`.
(4) Abnahme mit dem Simulator als Administrator.

- **Schritt 1 (15.11.2026): Regeln berechnen.** `RCEGuard.Core/Prevention`.
  - *Eine Sperr-Regel je Profil, mit dem Komplement der Allowlist.* Abschnitt 5 lässt die Umsetzung offen („Block
    schlägt Allow“). Gewählt ist: Die Regel sperrt ausgehende Verbindungen des Clients zu allen Adressen, die nicht
    erlaubt sind (`AddressBlocks.Outside`), als möglichst wenige Bereiche „von-bis“ für IPv4 und IPv6. Was keine
    Regel sperrt, lässt die Firewall in der Standardeinstellung durch; RCEGuard legt keine Allow-Regeln an und ändert
    die Standardrichtlinie nicht. Loopback (`127.0.0.0/8`, `::1`) ist nie gesperrt, wie bei R2. Erlaubt sind die
    Einträge aus `allowedRemote` und die Adressen, zu denen `allowedHostnames` gerade auflösen.
  - *Fail closed.* Lösen die Hostnamen eines Profils nicht auf und nennt es keine Adressen, sperrt die Regel alles
    außer Loopback. Ein Profil mit `firewall`, das weder Adressen noch Hostnamen nennt, ist ein Konfigurationsfehler.
  - *Sperre (Kill-Switch).* Ein gesperrtes Profil bekommt dieselbe Regel mit Adresse `*` (alles), unabhängig davon,
    ob seine Firewall eingeschaltet ist.
  - *Wiedererkennen.* Alle Regeln tragen die Gruppe `RCEGuard` und heißen `RCEGuard: <Profilname>`. Die Beschreibung
    endet mit einem Fingerabdruck aus Pfad und Adressen: Stimmt die Beschreibung einer vorhandenen Regel, ist es die
    gewünschte Regel und muss nicht neu geschrieben werden. Profilnamen müssen deshalb eindeutig sein und dürfen kein
    `|` enthalten (das nimmt die Firewall in Regelnamen nicht); beides prüft die Konfiguration jetzt.
  - *Geprüft an der Windows-Firewall, ohne etwas zu ändern (COM-Objekt `HNetCfg.FWRule`, nicht gespeichert):* Die
    berechneten Adresslisten werden angenommen und unverändert zurückgegeben, auch IPv6-Bereiche ab `::` und einzelne
    Adressen als „a-a“ (eine einzelne IPv4-Adresse ohne Bereich käme als `a/255.255.255.255` zurück). Eine Regel nimmt
    2000 Bereiche. Die Richtlinie ist ohne Admin-Rechte lesbar: Firewall in allen Profilen an, ausgehend „zulassen“.
    Das Objekt prüft nur die Schreibweise; ob die Firewall die Regel beim Speichern annimmt, zeigt erst Schritt 2.
- **Alles in M3 ist zunächst abgeschaltet und wird je Konfiguration eingeschaltet** (`"firewall": true` am Profil,
  `"lockdown": true` global). Das weicht von Abschnitt 5 ab, wo der Kill-Switch Standard ist. Grund: Eine Firewall-Regel
  mit unvollständiger Allowlist und eine Sperre machen den Client stumm, und bis zur Tray-App (M4) steht der Grund nur
  in `guard.log`; freigeben kann bis dahin nur ein Administrator auf der Kommandozeile. Was der Standard wird, wenn die
  Tray-App da ist, entscheidet der Inhaber.
- **Die Sperre hängt an `killEnabled`.** Mit `killEnabled: false` (empfohlen für die erste Beobachtung des echten
  Clients) wird weder beendet noch gesperrt, nur gemeldet. Ein Schalter für beides.
- **Schritt 2 (15.11.2026): Der Dienst schreibt die Regeln, sperrt und gibt frei.** Abnahme am installierten Dienst
  bestanden (siehe unten); die Warnung „wird noch nicht angewendet“ aus Schritt 1 ist entfallen.
  - *Zugriff auf die Firewall:* COM (`HNetCfg.FwPolicy2`) über `dynamic`, hinter der Schnittstelle `IFirewall`.
    Lesen geht für jeden Benutzer, Schreiben braucht Admin-Rechte oder `LocalSystem`. Eine vorhandene Regel wird an
    Ort und Stelle geändert, damit es keinen Moment ohne Regel gibt; die Beschreibung mit dem Fingerabdruck wird
    zuletzt gesetzt, damit eine halb geänderte Regel nicht wie die gewünschte aussieht. Angefasst werden nur Regeln
    der Gruppe `RCEGuard`.
  - *Abgleich (`FirewallGuard.Apply`):* beim Start (dann wird jede gewünschte Regel neu geschrieben, damit eine von
    Hand geänderte nicht bleibt), nach jedem Auflösen der Hostnamen, nach einer Sperre und wenn sich `lockdown.json`
    von außen ändert. Sonst wird nur geschrieben, was abweicht (Beschreibung, eingeschaltet, ausgehend sperrend,
    Programmpfad). Regeln der Gruppe, die niemand mehr verlangt, werden entfernt.
  - *Die Sperre steht in `lockdown.json` im Datenordner, die Regeln werden daraus abgeleitet.* So übersteht sie einen
    Neustart des Dienstes und von Windows, und Dienst und Freigabe-Befehl können beide schreiben, ohne sich
    abzustimmen: Beide rechnen aus derselben Datei dasselbe aus. Ist die Datei nicht lesbar, gelten alle Profile als
    gesperrt (eine unlesbare Datei könnte eine Sperre verbergen); `--release` ersetzt sie.
  - *Wann gesperrt wird:* nach jedem Befund, der den Client beendet (auch R2 mit `killOnUnknownRemote`, auch bei
    nachgeholten Ereignissen), sofern der Befund einem Profil gehört. R9 bei fremden Prozessen sperrt nichts. Der
    erste Befund bleibt als Grund stehen; ein weiterer meldet „already in lockdown“.
  - *Freigabe:* `RCEGuard.Service.exe --release [Profil]` für einen Administrator. Der Befehl leert die Datei, löst
    die Hostnamen selbst auf und schreibt die Regeln selbst, damit er auch ohne laufenden Dienst wirkt; der laufende
    Dienst sieht die geänderte Datei spätestens nach 15 s und gleicht noch einmal ab.
  - *Firewall nicht änderbar:* Der Dienst meldet einen Fehler („… NOT be blocked“) und beobachtet weiter, statt zu
    enden. Abweichung von „fail closed“ aus M2, bewusst: Ein Wächter, der wegen der Firewall gar nicht läuft, erkennt
    auch nichts mehr. Die Sperre bleibt in der Datei vermerkt und greift beim nächsten Abgleich, der die Firewall
    erreicht. Ist die Firewall für das aktive Netzwerkprofil aus oder überschreibt eine Gruppenrichtlinie lokale
    Regeln, steht einmal eine Warnung im Log.
  - *Hostnamen (`HostAddressBook`):* je Hostname gemerkt. Scheitert das Auflösen, behält der Name seine bisherigen
    Adressen, und es wird nach 30 s statt nach 10 min neu versucht. Vorher ersetzte ein teilweiser Fehlschlag die
    Adressen des ganzen Profils; mit eingeschalteter Firewall hätte das einen bekannten Server gesperrt.
  - *`--dry-run`:* schreibt weder Regeln noch die Sperrdatei und sagt, welche Regeln es gäbe.
  - *Entfernen:* `Uninstall-GuardService` löscht die Regeln der Gruppe (also auch nach einem gescheiterten Start bei
    der Installation); `install-test.ps1` zählt sie als Teil des Dienstes. `lockdown.json` liegt im Datenordner und
    geht mit ihm (bleibt mit `-KeepData`).
  - *Geprüft:* 67 Dienst-Tests (31 neue) gegen eine Stellvertreter-Firewall, darunter die Wächter-Schleife mit einem
    eingespielten R1-Ereignis (Prozess-IDs, die es nicht geben kann): Sperre, kein Sperren ohne Schalter und im
    Trockenlauf, Regel beim Start, Sperre nach Neustart, Freigabe bei laufendem Wächter. Die echte Firewall wird in
    einem Test nur gelesen (alle Regeln durchlaufen, Zustand der Netzwerkprofile); das zeigt, dass die COM-Aufrufe
    stimmen. Der veröffentlichte Dienst hat ohne Admin-Rechte `--release` gegen einen Datenordner in TEMP
    ausgeführt: Lesen ging, das Schreiben wurde mit „Zugriff verweigert“ sauber gemeldet, keine Regel entstand.
  - *Abnahme:* `scripts/prevention-test.ps1` (Administrator, Internet). Trockenlauf mit Stellvertretern für Dienst,
    Firewall, Simulator und Freigabe in PowerShell 7 und 5.1: 20 von 20; die Fehlvariante „Firewall sperrt nichts“
    fällt mit 4 FAIL durch und räumt trotzdem auf. Der Trockenlauf fand einen Fehler im Skript (`$Port?` liest
    PowerShell 7 als Variablenname). Die beiden Testadressen sind von diesem Rechner aus erreichbar.
  - *Lauf als Administrator (15.11.2026, 00:22): ALL PASSED, 20 von 20.* `prevention-test.ps1` am installierten
    Dienst. Die Regel stand 0,6 s nach dem Start des Dienstes in der Firewall (5 Bereiche, Lücke bei `1.1.1.1`), die
    erlaubte Adresse verband, die andere nicht. Nach `--spawn`: Kind und Client beendet, Regel auf `*` (00:22:47.331,
    8 ms vor der Zeile des Befunds), `lockdown.json` mit dem Profil, auch die erlaubte Adresse gesperrt; nach dem
    Neustart des Dienstes unverändert. `--release` als Administrator: Exit-Code 0, Regel zurück auf die Allowlist,
    der laufende Dienst hat die Änderung unter einer Sekunde später bemerkt. Am Ende Konfiguration wie vorher, keine
    Regel der Gruppe mehr. Eine gesperrte Verbindung kommt beim Simulator sofort als Fehler an („Der Zugriff auf
    einen Socket war aufgrund der Zugriffsrechte des Sockets unzulässig“), nicht als Zeitüberschreitung.
  - *Aus dem Lauf: Gesperrte Verbindungen erzeugen keinen Befund.* Abgleich der Prozess-IDs in `findings.db`: Die drei
    Verbindungen, die durchgingen, hat Sysmon aufgezeichnet (alle drei als R2 gemeldet, eine davon 2,8 s nach dem
    Verbindungsaufbau und deshalb erst nach einem Neustart des Dienstes gelesen); für die zwei Versuche zu einer
    nicht erlaubten Adresse, die die Firewall gesperrt hat, gibt es kein Ereignis und keinen Befund. Zwei Versuche
    sind kein Beweis, passen aber dazu, dass Sysmon nur zustande gekommene Verbindungen meldet. Folge: Mit
    eingeschalteter Firewall sieht RCEGuard nicht, dass der Client eine fremde Adresse erreichen wollte, und
    `killOnUnknownRemote` greift dann nie. Sichtbar machen ließe sich das über das Protokoll der Firewall
    (Überwachungsereignis 5157 oder `pfirewall.log`, beides muss erst eingeschaltet werden). Nicht gebaut;
    Entscheidung des Inhabers.
  - *Nicht geprüft:* `uninstall.ps1` mit vorhandenen Regeln (`Remove-GuardFirewallRules`); das Verhalten mit dem
    echten Client; Hostnamen im installierten Dienst (der Test nutzt nur eine Adresse).
  - *Grenzen:* Die Regel gilt für die Programmdatei des Clients, nicht für Programme, die er startet. Regeln werden
    über ihren Namen entfernt; eine fremde Regel mit genau dem Namen `RCEGuard: <Profil>` außerhalb der Gruppe könnte
    dabei statt der eigenen getroffen werden. Eine Sperre, die nicht in die Datei geschrieben werden konnte, endet
    mit dem nächsten Abgleich.
- **Schritt 3 (15.11.2026): Exploit Protection.** Abnahme mit dem Simulator bestanden (zweiter Lauf, 15:56); der
  erste Lauf scheiterte am Zurücknehmen und führte zum Umbau (beides unten).
  - *Nur eine Einstellung:* „Do not allow child processes“ (`DisallowChildProcessCreation`) für den vollen Pfad des
    Clients, über `Set-ProcessMitigation`. Abschnitt 5 nennt den Programmnamen (`-Name Wow.exe`); der würde jede
    `Wow.exe` des Rechners treffen. Microsoft dokumentiert den vollen Pfad für genau diese Einstellung
    („Customize exploit protection“). `ArbitraryCodeGuard` und `BlockDynamicCode` werden nie gesetzt (Warden).
  - *In den Skripten, nicht im Dienst.* Die Einstellung ist eine einmalige Systemänderung, die Windows selbst
    durchsetzt und die auch ohne laufenden Dienst gilt; `install.ps1` setzt sie, `uninstall.ps1` nimmt sie zurück
    (harte Regel „alles ist rückbaubar“). Der Dienst müsste dafür PowerShell starten oder das Binärformat in der
    Registry selbst schreiben. Folge: Sie gilt für den einen Client aus `-ClientPath`, nicht je Profil der
    Konfiguration.
  - *Schalter:* `install.ps1 -BlockChildProcesses` schaltet ein, `-AllowChildProcesses` nimmt zurück, ohne Schalter
    bleibt es, wie der letzte Lauf es hinterlassen hat; wechselt `-ClientPath`, zieht die Einstellung mit. Zwei
    Schalter statt `-BlockChildProcesses:$false`: Unter `powershell.exe -File` (5.1) kommt `:$false` als Text an
    und der Aufruf scheitert (im Trockenlauf gesehen).
  - *Rückbau auf den Stand von vorher.* Die Statusdatei merkt sich den Pfad und den Wert vor dem Einschalten
    (`childProcessBlockPath`, `childProcessBlockBefore`): „nicht gesetzt“ wird wieder „nicht gesetzt“
    (`-Remove -Disable`), ein erzwungenes „aus“ wieder „aus“. War die Einstellung schon an, bevor RCEGuard sie
    anfasste, gehört sie nicht RCEGuard und bleibt, auch beim Entfernen. Nach jedem Setzen und Zurücknehmen wird
    gelesen, ob es gewirkt hat; ein Befehl ohne Fehler und ohne Wirkung gilt als Fehlschlag.
  - *Scheitert das Ändern,* schreibt `install.ps1` erst die Statusdatei (sie sagt, wie weit es kam) und bricht dann
    ab, bevor der Dienst angefasst wird. `uninstall.ps1` warnt in dem Fall mit dem Befehl für die Hand und räumt
    den Rest trotzdem ab: Sonst bliebe wegen einer Einstellung alles installiert.
  - *Standard aus,* wie alles in M3, hier zusätzlich wegen Abschnitt 12: Ob der echte Client damit startet, sich
    anmeldet und patcht, ist nicht geprüft.
  - *Ein abgewiesener Start ist kein Befund.* Es entsteht kein Prozess, also kein Sysmon-Ereignis. Windows
    protokolliert ihn selbst (`Microsoft-Windows-Security-Mitigations/KernelMode`, Ereignis 4, Audit-Modus
    Ereignis 3); das Log ist auf dem Testrechner ohne Admin-Rechte lesbar. Es zu lesen und als Befund zu melden
    ist dieselbe Frage wie bei gesperrten Verbindungen (Schritt 2) und nicht gebaut; Entscheidung des Inhabers.
  - *Geprüft, alles mit Stellvertretern für `Get-`/`Set-ProcessMitigation`, in PowerShell 7 und 5.1:* die
    Entscheidungslogik (`Update-ChildProcessBlock`, 13 Fälle: erstmals, erneut, von Hand entfernt, zurücknehmen,
    anderer Client, schon fremd gesetzt, vorher „aus“, Fehlschläge, Befehl ohne Wirkung); eine Kopie von
    `install.ps1` mit einer Statusdatei im alten Format (6 Läufe); `uninstall.ps1` (nimmt zurück, ein zweiter Lauf
    nicht noch einmal); `prevention-test.ps1` mit dem neuen Teil (26 von 26, Fehlvariante 6 FAIL). Echt gelesen,
    ohne Admin-Rechte: Ein Programm ohne Eintrag liest sich als „nicht gesetzt“, ein vorhandener Eintrag nach
    Programmname (`excel.exe`) wird gelesen, ein erfundener Name ergibt nichts.
  - *Nicht geprüft:* ob `Set-ProcessMitigation` den vollen Pfad auf diesem Windows annimmt und
    `Get-ProcessMitigation` ihn danach liest (auf dem Rechner gibt es keinen Eintrag mit Pfad zum Nachsehen); ob
    der Simulator als Konsolenprogramm mit der Einstellung noch startet (Windows erzeugt für ihn `conhost.exe`;
    nach einer Beschreibung des Mechanismus entsteht der im Kernel und fällt nicht unter die Sperre); wie die
    Abweisung beim Simulator ankommt; ob nach dem Zurücknehmen ein leerer Eintrag in der Registry bleibt
    (`prevention-test.ps1` schreibt den Registry-Stand vorher und nachher in die Ergebnisdatei); der echte Client.
  - *Lauf als Administrator (15.11.2026, 00:35): Firewall-Teil erneut 20 von 20, Exploit Protection 3 FAIL.*
    - *Einschalten geht.* `Set-ProcessMitigation` nimmt den vollen Pfad an, `Get-ProcessMitigation` liest ihn (auch
      ohne Admin-Rechte). Registry: `Image File Execution Options\Wow.exe` mit `UseFilter = 1`, darunter ein
      Schlüssel `{GUID}` mit `FilterFullPath`, `MitigationOptions` (24 Bytes, Byte 12 = `0x10`),
      `MitigationAuditOptions`, `EAFModules`. Den Schlüssel `Wow.exe` gab es vorher nicht.
    - *Windows weist den Programmstart ab.* Ohne Admin-Rechte nachgeprüft, solange die Einstellung noch an war:
      `Wow.exe --spawn` in einer vorhandenen Konsole endet mit „Die Prozesserstellung wurde blockiert“, Exit-Code 1;
      `--connect` läuft. Kein R1-Befund, weil kein Prozess entsteht. Windows protokolliert beides als Ereignis 4
      (`… wurde daran gehindert, den untergeordneten Prozess C:\WINDOWS\SYSTEM32\cmd.exe … zu erstellen`); die
      Einträge standen nicht in den ersten Sekunden im Log, später schon.
    - *Ein Konsolenprogramm bekommt keine eigene Konsole mehr.* Windows weist auch `conhost.exe` ab (Ereignis 4);
      der versteckt gestartete Simulator endete mit Exit-Code `0xC0000142`, ohne etwas auszugeben. Die Annahme aus
      der Recherche, der Konsolen-Host entstehe im Kernel und falle nicht unter die Sperre, war falsch. In einer
      schon offenen Konsole läuft das Programm. Der echte Client ist ein Fensterprogramm; der Simulator nicht, also
      startet `prevention-test.ps1` ihn in diesem Teil in der Konsole des Tests (`Invoke-ClientHere`). Offen: den
      Simulator als Fensterprogramm bauen; das entspräche dem echten Client und nähme die `conhost`-Zeilen aus M2.
    - *Zurücknehmen ist gescheitert.* `Set-ProcessMitigation -Name <Pfad> -Remove -Disable
      DisallowChildProcessCreation`, der von Microsoft dokumentierte Weg zurück zum Systemstandard, lief ohne Fehler
      und änderte nichts (Registry vorher und nachher gleich; Modul ProcessMitigations 1.0.12). Die Prüfung nach dem
      Befehl hat das gemeldet, `install.ps1` hat die Statusdatei geschrieben und abgebrochen: Die Einstellung stand
      weiter in der Statusdatei, der Rechner war also nicht in einem unbekannten Zustand. Der Testclient durfte
      danach weiter keine Programme starten.
    - *Umbau (`Restore-ChildProcessBlock`).* Erst die Wege von `Set-ProcessMitigation` (`-Remove -Disable`, dann
      `-Disable`), nach jedem Schritt wird gelesen. Gab es für den Client vorher keinen Eintrag, gehört der Eintrag
      allein RCEGuard und wird danach direkt aus der Registry genommen: der Unterschlüssel, dessen `FilterFullPath`
      genau der Pfad ist, und der Schlüssel des Programmnamens, wenn sonst nichts darin steht (kein anderer Pfad,
      kein Wert außer `UseFilter`). Gab es vorher einen Eintrag, bleibt er mit allem anderen stehen; lässt sich die
      Einstellung dann nicht abschalten, scheitert der Schritt mit dem, was die Befehle sagten. Die Statusdatei merkt
      sich dafür `childProcessBlockEntryBefore`; fehlt der Wert (Statusdatei des Stands von 00:35, den es nur auf dem
      Testrechner gibt), gilt „kein Eintrag vorher“. Bewusst kein bloßes `-Remove` ohne `-Disable`: Was der Befehl
      bei einem Pfad löscht, ist nach dem Befund oben nicht mehr vorhersagbar.
    - *Geprüft (Stellvertreter, die sich wie die echten Befehle vom 15.11. verhalten und in einer Kopie des
      Registry-Aufbaus unter `HKCU` arbeiten; PowerShell 7 und 5.1):* 16 Fälle der Logik, darunter „kein Befehl
      wirkt“, zwei Clients gleichen Namens, fremde Werte am Schlüssel des Programmnamens, Eintrag mit anderen
      Einstellungen; `install.ps1` in 8 Läufen, der letzte mit dem Zustand des Testrechners; `uninstall.ps1`;
      `prevention-test.ps1` 27 von 27. Echt gelesen: Das Aufräumen fände auf dem Testrechner genau einen Eintrag
      mit passendem Pfad und keinen weiteren Wert am Schlüssel `Wow.exe`.
    - *Nicht geprüft:* das Löschen in der echten Registry (braucht Admin-Rechte); ob `-Disable` für einen Pfad
      wirkt; der echte Client.
  - *Zweiter Lauf als Administrator (15.11.2026, 15:56): ALL PASSED, 27 von 27.* Vorher hat
    `install.ps1 -AllowChildProcesses` den hängengebliebenen Zustand vom ersten Lauf abgeräumt: Einstellung „nicht
    gesetzt“, kein Eintrag, Schlüssel `Image File Execution Options\Wow.exe` weg, Statusdatei ohne Pfad. Im Test
    dann der ganze Weg: einschalten (`ON`), der Simulator läuft und verbindet in der Konsole des Tests, `--spawn`
    wird abgewiesen („Die Prozesserstellung wurde blockiert“), kein R1-Befund; nach `-AllowChildProcesses` „nicht
    gesetzt“, kein Eintrag (Registry: Schlüssel nicht mehr vorhanden), und der Wächter beendet das gestartete
    Programm wieder (R1 nach 1,0 s). Mit eigener Konsole lief der Simulator unter der Einstellung wieder nicht
    (`0xC0000142`). Windows hat beide Abweisungen als Ereignis 4 protokolliert, diesmal schon beim Auslesen drei
    Sekunden später, mit Programm und Befehlszeile (`"cmd.exe" /c ping -n 9 127.0.0.1 > nul`).
  - *Nicht festgestellt:* welcher der Schritte den Eintrag entfernt hat (`-Disable` und danach die Registry, oder
    die Registry allein); die Ausgabe von `install.ps1` aus dem Lauf liegt nicht vor. Am Ergebnis ändert das nichts.
  - *Weiter nicht geprüft:* `uninstall.ps1` mit gesetzter Einstellung (das prüft `install-test.ps1`, Schritte C und
    D, auf einem Rechner ohne RCEGuard); der echte Client mit der Einstellung (Abschnitt 12).
  - *Rückbau durch `uninstall.ps1` (15.11.2026, 15:58): bestanden.* Der Inhaber hat `uninstall.ps1` ausgeführt
    (Sysmon ohne Absturz entfernt) und danach `install-test.ps1`: ALL PASSED, 23 von 23. Schritt C installierte mit
    `-BlockChildProcesses` (Einstellung `ON`), Schritt D: `uninstall.ps1` ohne Fehler, Einstellung „nicht gesetzt“,
    der Rechner wie vor dem Test. Danach gelesen: kein Eintrag, kein Schlüssel `Image File Execution Options\Wow.exe`,
    keine Firewall-Regel, nichts von einer Installation auf dem Rechner.
- **Stand M3 (15.11.2026):** Schritte 1 bis 3 gebaut und mit dem Simulator abgenommen (`prevention-test.ps1` 27 von
  27, `install-test.ps1` 23 von 23). Offen: `uninstall.ps1` mit vorhandenen Firewall-Regeln (im Test sind sie vor dem
  Entfernen schon weg); Hostnamen im installierten Dienst; der echte Client (Firewall mit echter Allowlist, Sperre,
  Exploit Protection).
  Entscheidungen des Inhabers: ob gesperrte Verbindungen und abgewiesene Programmstarts aus den Windows-Logs gelesen
  und gemeldet werden; ob der Simulator ein Fensterprogramm wird; was in M3 Standard wird, sobald die Tray-App da ist.

## 16. Entscheidungen bei der Umsetzung von M4

**Schritte.** (1) Benachrichtigungen über ntfy aus dem Dienst, dazu die Meldungen des Dienstes über sich selbst
(Heartbeat). (2) Tray-App: Status, Alarmliste, Toasts, Sperre anzeigen und freigeben. (3) Profilverwaltung und Autostart
der Tray-App. (4) Abnahme.

- **Schritt 1 (15.11.2026): ntfy und Heartbeat.** Noch nicht mit einem echten ntfy-Server und nicht im installierten
  Dienst gelaufen.
  - *Was gesendet wird:* jeder Befund, der alarmiert oder beendet (`NotificationText.Notifies`), nachdem das
    Entprellen ihn durchgelassen hat; Priorität „urgent“ für KRITISCH, „high“ für HOCH. Nur protokollierte Befunde
    (MITTEL, INFO) nicht. Ein Replay sendet nichts (alte Ereignisse), ein Trockenlauf (`--dry-run`) schon: Er meldet
    ja, nur beendet er nichts.
  - *Versand im Hintergrund (`NtfyNotifier`).* Die Wächter-Schleife übergibt nur; gesendet wird aus einer Warteschlange
    (100 Einträge, bei Überlauf fallen die ältesten weg). Drei Versuche (sofort, nach 2 s, nach 10 s), 10 s Wartezeit
    je Versuch. Ein Ausfall steht einmal im Log, das Ende des Ausfalls mit der Zahl der verlorenen Meldungen. Beim
    Beenden wartet der Dienst höchstens 5 s auf offene Meldungen.
  - *Heartbeat ohne Lebenszeichen.* Abschnitt 7 verlangt einen Alarm, wenn der Client läuft und der Dienst nichts
    mehr sieht oder Sysmon gestoppt ist. Regelmäßige „lebt noch“-Meldungen wären dafür das übliche Mittel, brauchen
    aber einen zweiten Dienst, der ihr Ausbleiben bemerkt, und schlügen bei jedem Ausschalten des Rechners an.
    Gebaut ist stattdessen, was der Dienst selbst wissen kann:
    - *kann nicht arbeiten* (Sysmon-Log weg oder stumm, Konfiguration kaputt): Meldung vor dem Beenden;
    - *unsauber beendet* (von außen beendet, abgestürzt, Strom weg): Der Dienst legt beim Start `guard-running` in
      den Datenordner und löscht die Datei beim regulären Ende. Findet der nächste Start sie vor, meldet er das, mit
      der letzten bekannten Lebenszeit (Änderungszeit von `sysmon-position.json`). Windows startet den Dienst nach
      5 s neu, die Meldung kommt also kurz nach dem Vorfall;
    - *gestoppt, während der Client läuft:* Beim regulären Stopp sieht der Dienst in der Prozessliste nach einem
      Programm mit dem Dateinamen eines überwachten Clients. Wird Sysmon gestoppt, stoppt Windows auch RCEGuard
      (Abhängigkeit); dieser Fall ist damit abgedeckt. Beim Herunterfahren von Windows sind die Programme des
      Benutzers vorher beendet, dann kommt keine Meldung.
    - *Grenze:* Wer den Dienst mit Admin-Rechten deaktiviert oder entfernt, bekommt keine Meldung ausgelöst
      (Abschnitt 2: kein Schutz gegen Angreifer mit Admin-Rechten). Ein Lebenszeichen an einen Überwachungsdienst
      (z. B. eine URL, die regelmäßig abgerufen wird) wäre dafür die Ergänzung; Entscheidung des Inhabers.
  - *Die Konfiguration ist für alle Benutzer lesbar,* also auch Topic und Token (der Datenordner ist seit M2 lesbar,
    damit die Tray-App die Befunde zeigen kann). Wer mit Benutzerrechten läuft, kann damit ins Topic schreiben. Nicht
    gelöst, sondern dokumentiert: ein Token, das nur in dieses eine Topic schreiben darf. Eine eigene, nur für
    Administratoren lesbare Datei für das Token wäre die Alternative; Entscheidung des Inhabers. Im Log steht nur der
    Server, nie Topic oder Token.
  - *Inhalt verlässt den Rechner:* Regel, Zusammenfassung (Programme, Dateien, Adressen; darin kann der
    Windows-Benutzername stehen), Aktion, Zeit, Computername. Im README genannt.
  - *`--notify-test`:* sendet eine Testmeldung und sagt, ob der Server sie angenommen hat; ohne Admin-Rechte.
  - *Geprüft:* 198 Kern- und 81 Dienst-Tests bestanden (je 14 neue): Texte und Prioritäten, Konfiguration; Versand
    gegen einen Stellvertreter für das Netz (Kopfzeilen, Token, Wiederholung, Ausfall einmal im Log und ohne
    Topic/Token, Antwort 403); die Wächter-Schleife (Befund wird gesendet, ohne Topic nichts, unsauberes Ende wird
    beim nächsten Start gemeldet und danach nicht mehr, „kann nicht arbeiten“, Stopp bei laufendem „Client“ mit einem
    echten `cmd.exe` als Stellvertreter). Der veröffentlichte Dienst hat mit `--notify-test` eine echte HTTP-Anfrage
    an einen Empfänger auf dem Testrechner geschickt: POST auf das Topic, `Title`, `Priority`, `Tags`,
    `Authorization: Bearer`, Text als UTF-8.
  - *Nicht geprüft:* ein echter ntfy-Server (nimmt er die Kopfzeilen so, kommt die Meldung auf dem Telefon an); der
    installierte Dienst als `LocalSystem` (Netzzugriff, Namensauflösung); das Verhalten beim Herunterfahren von
    Windows.
- **Schritt 2 (15.11.2026): Tray-App `RCEGuard.Tray`.** Gebaut und ohne Oberfläche getestet; mit einem installierten
  Dienst noch nicht benutzt. `install.ps1` installiert und startet sie noch nicht (Schritt 3).
  - *Liest, statt zu fragen.* Abschnitt 3 zeichnet eine Named Pipe zwischen Dienst und Tray-App. Die Tray-App liest
    stattdessen die Dateien, die der Dienst ohnehin für alle lesbar ablegt (`findings.db` nur lesend, `lockdown.json`,
    Konfiguration), und fragt Windows nach dem Zustand des Dienstes, alle 2 s. Der Dienst (`LocalSystem`) bekommt so
    keine Schnittstelle, über die ein Programm mit Benutzerrechten ihm etwas sagen kann.
  - *Freigeben nur mit Admin-Abfrage.* „Release ...“ startet `RCEGuard.Service.exe --release <Profil>` aus
    `C:\Program Files\RCEGuard` mit dem Verb `runas`; Windows fragt nach einem Administrator. Könnte die Tray-App
    ohne Admin-Rechte freigeben, könnte es auch Schadcode mit Benutzerrechten. Gestartet wird immer genau dieser
    Pfad: Programme dort kann ein normaler Benutzer nicht austauschen. Eine nicht lesbare Sperrdatei (dann gelten
    alle Profile als gesperrt) bietet eine Freigabe für alle an.
  - *Kein Fremdpaket für das Symbol.* Abschnitt 3 nennt `H.NotifyIcon`. Genommen ist `NotifyIcon` aus Windows Forms,
    das zu .NET gehört; das Fenster ist WPF. Die vier Symbole (Schild in Grün, Orange, Rot, Grau mit Haken,
    Ausrufezeichen, Balken, Kreuz) werden beim Start gezeichnet, die App liefert keine Bilddateien mit. Das Zeichen
    im Schild sagt den Zustand auch ohne Farbe.
  - *Hinweise als Sprechblase des Symbols* (`ShowBalloonTip`); Windows 10 und 11 zeigen sie als Benachrichtigung
    und behalten sie im Benachrichtigungscenter. Abschnitt 7 spricht von Toasts; für echte Toasts mit Schaltflächen
    bräuchte die App eine Registrierung im Startmenü oder ein Zusatzpaket. `"notify": { "toast": false }` schaltet
    die Hinweise ab.
  - *Was gemeldet wird:* Befunde, die alarmiert oder beendet haben; mehrere auf einmal als ein Hinweis mit dem
    schwersten. Der Stand je Windows-Benutzer steht in `%LOCALAPPDATA%\RCEGuard\tray-state.txt` (ID des letzten
    gemeldeten Befunds): Was geschah, während die Tray-App nicht lief, wird beim nächsten Start gemeldet, nichts
    doppelt. Der allererste Start meldet nichts Altes. Eine neue Datenbank nach einer Neuinstallation (IDs beginnen
    wieder bei 1) wird erkannt. Ein anderer Datenordner (`--data-dir`) bekommt eine eigene Stand-Datei.
  - *Rangfolge der Anzeige:* Dienst läuft nicht, vor Sperre, vor ungesehenen Befunden, vor „beobachtet“.
    „Ungesehen“ endet, wenn das Fenster in den Vordergrund kommt.
  - *Gemeinsames im Kern:* `LockdownFile` und das Laden der Konfiguration (`GuardConfigFile`) sind in den Kern
    umgezogen, damit Dienst und Tray-App dasselbe Dateiformat aus einer Stelle lesen. Die Tabelle `findings` liest
    die Tray-App mit eigenem Code; ihr Test schreibt die Datenbank mit dem `FindingStore` des Dienstes, eine
    Schemaänderung dort fällt also im Tray-Test auf.
  - *Im Test gefunden:* WPF läuft nicht mit `InvariantGlobalization` („Cannot find non-neutral culture related to
    'en-us'“); die Einstellung gilt lösungsweit und ist für die beiden Tray-Projekte abgeschaltet. Ohne den Test,
    der das Fenster zeichnet, wäre die App beim Start abgestürzt.
  - *Geprüft:* 28 Tests ohne Oberfläche (Lesen der vom Dienst geschriebenen Datenbank, auch während er sie offen
    hat; Zustand und Rangfolge; was gemeldet wird; Freigabe-Argumente; Fenster und Symbole werden in Bilddateien
    gezeichnet). Die Bilder (gesperrtes Profil mit sechs Befunden, „nicht installiert“, die vier Symbole) habe ich
    angesehen. Die App einmal 5 s gegen einen Beispielordner gestartet: läuft, Fenster „RCEGuard“, reagiert, kein
    Absturzbericht; ein zweiter Start zeigt nur den Hinweis, dass sie schon läuft. Arbeitsspeicher dabei 124 MB.
  - *Nicht geprüft:* die App neben einem installierten Dienst (echter Befund, Hinweis von Windows, Symbolwechsel);
    die Freigabe mit Admin-Abfrage; Lesen von `findings.db` als Benutzer ohne Schreibrecht im Datenordner (die
    Tests laufen in einem eigenen Ordner); mehrere Benutzer; hohe Bildschirmskalierung.
- **Schritt 3 (15.11.2026): Tray-App installieren, automatisch starten, entfernen.** Noch nicht als Administrator
  gelaufen. Die Profilverwaltung aus dem Meilenstein ist nicht gebaut (siehe unten).
  - *Veröffentlichung:* `build.ps1 -Publish` legt die Tray-App nach `artifacts\tray`, self-contained wie den
    Dienst (162 MB). Framework-abhängig wäre sie klein, bräuchte aber eine .NET-Desktop-Laufzeit, die jeder Benutzer
    des Rechners nutzen kann; das SDK liegt hier im Profil des Benutzers, der baut, und gespielt werden soll mit
    einem anderen Konto ohne Admin-Rechte (Abschnitt 3).
  - *Eigener Ordner `C:\Program Files\RCEGuard Tray`,* nicht im Ordner des Dienstes: Der wird bei jeder
    Installation des Dienstes gelöscht und neu angelegt, und das scheitert, solange ein Programm daraus läuft. So
    bleibt die Tray-App auch stehen (und zeigt „läuft nicht“), wenn der Dienst nach einem gescheiterten Start
    wieder entfernt wird.
  - *Autostart:* Wert `RCEGuard.Tray` unter `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, also für jeden
    Benutzer bei der Anmeldung. `-SkipTray` lässt die Tray-App weg.
  - *Start ohne Admin-Rechte:* `install.ps1` läuft mit Admin-Rechten; direkt daraus gestartet hätte die Tray-App
    sie auch. Sie wird deshalb über `explorer.exe "<Pfad>"` gestartet. `install-test.ps1` prüft das am laufenden
    Prozess (Token-Abfrage `TokenElevation`, ohne etwas vom Prozess zu lesen).
  - *Entfernen (`Uninstall-GuardTray`):* beendet die Tray-App aller Benutzer, entfernt Ordner, Run-Wert und die
    Dateien `tray-state*.txt` in den Profilen aller Benutzer (Liste aus `ProfileList`; ein dadurch leerer Ordner
    `%LOCALAPPDATA%\RCEGuard` geht mit, anderes darin bleibt). `uninstall.ps1` tut das als Erstes und auch ohne
    Statusdatei, wie beim Dienst.
  - *Im Trockenlauf gefunden:* `Test-Path` wirft für Profile von Systemkonten, in die der Benutzer nicht sehen darf
    (`…\config\systemprofile`); jetzt `Directory.Exists`.
  - *Geprüft, mit Stellvertretern in PowerShell 7 und 5.1* (Programme-Ordner und Benutzerprofile in TEMP, Run-Wert
    und Profilliste unter `HKCU`, ein harmloses Programm als laufende Tray-App): 12 Fälle der Hilfsfunktionen
    (installieren, bei laufender App aktualisieren, entfernen samt Stand zweier Benutzer, Fremdes im Ordner bleibt);
    `install.ps1` und `uninstall.ps1` als Kopie über alle Läufe. Echt und ohne Admin-Rechte: Die veröffentlichte
    Tray-App startet über den Explorer, Elternprozess `explorer`, nicht erhöht, 90 MB.
  - *Nicht geprüft:* die Installation als Administrator; ob der Start über den Explorer aus einer erhöhten Konsole
    wirklich ohne Admin-Rechte ankommt (prüft `install-test.ps1`, Schritt C); der Autostart bei der Anmeldung; das
    Entfernen bei einem zweiten angemeldeten Benutzer.
  - *Lauf als Administrator (15.11.2026, 17:12): `install-test.ps1` ALL PASSED, 25 von 25.* Schritt C: Tray-App
    installiert (Ordner, Run-Wert, Prozess), und der über den Explorer gestartete Prozess hat **keine**
    Admin-Rechte, obwohl die Konsole erhöht lief. Schritt D: `uninstall.ps1` ohne Fehler, der Rechner wie vor dem
    Test (kein Ordner, kein Run-Wert, kein Prozess, kein Stand im Benutzerprofil). Windows führt für 17:12:25 wieder
    einen Absturzbericht für `Sysmon64.exe` 15.22; das Entfernen ging trotzdem durch, es ist nichts übrig. Kein
    Absturzbericht für die Tray-App.
  - *Weiter nicht geprüft:* der Autostart bei der Anmeldung; die Tray-App neben einem laufenden Dienst mit einem
    echten Befund (Hinweis von Windows, Symbolwechsel, Freigabe mit Admin-Abfrage); ein zweiter angemeldeter
    Benutzer.
  - *Abgebrochene Installation hinterließ den Datenordner (15.11.2026, 17:14).* Ich hatte dem Inhaber
    `prevention-test.ps1` ohne `-DownloadSysmon -AcceptSysmonEula` übergeben, obwohl Sysmon nach `install-test.ps1`
    nicht mehr installiert war. `install.ps1` brach richtig ab ("Sysmon is not installed ..."), hatte da aber schon
    den Datenordner angelegt und die Sysmon-Konfiguration hineingeschrieben; ohne Statusdatei räumte `uninstall.ps1`
    das nicht weg. Jetzt prüft `install.ps1` Lizenz und Quelle von Sysmon, bevor es etwas anlegt, und
    `uninstall.ps1` entfernt einen Datenordner ohne Statusdatei, wenn nichts als `sysmon-config.xml` darin liegt
    (ein Ordner mit anderem Inhalt bleibt). Geprüft mit Stellvertretern in PowerShell 7 und 5.1 (6 Fälle).
  - *Tray-App neben dem installierten Dienst (15.11.2026, 17:17): Hinweise kamen.* `prevention-test.ps1` mit
    installierter Tray-App: ALL PASSED. Der Inhaber hat die Windows-Benachrichtigungen gesehen. Damit ist auch
    bestätigt, dass die Tray-App ohne Admin-Rechte `findings.db` in dem für sie nur lesbaren Datenordner lesen kann,
    während der Dienst sie offen hat.
  - *Beobachtung des Inhabers: Die Hinweise haben „z. B. das Snipping Tool verhindert“.* Was genau geschah, weiß
    ich nicht. In den Logs von Windows steht dazu nichts: kein Absturz, kein Fehler, kein Exploit-Protection-Ereignis
    außer denen für `Wow.exe`; `SnippingTool.exe` wurde um 17:17:58 gestartet und lief danach. Die Regeln, die
    Firewall-Regel und die Exploit-Protection-Einstellung gelten nur für den Pfad des Clients. Was in diesen
    Sekunden zusammenkam: sechs meldende Befunde in 15 s (17:17:48 bis 17:18:03), und der Test hat die Tray-App
    dreimal beendet und über den Explorer neu gestartet (jeder Lauf von `install.ps1`). Vermutung, nicht belegt: Die
    Auswahl des Snipping Tools bricht ab, wenn ein anderes Fenster oder eine Benachrichtigung den Fokus bekommt.
  - *Genauer (Inhaber, 15.11.2026):* Das Snipping Tool startete, der Bildschirm dunkelte sich ab, der Hinweis der
    Tray-App lag darüber, und die Auswahl ließ sich nicht benutzen. Ein Nachstellen danach (Auswahl über
    `ms-screenclip:` öffnen, einen einzelnen Hinweis von einem eigenen Symbol zeigen, den Fokus messen) hat der
    Inhaber abgebrochen; eine Messung liegt nicht vor. Seine Rückmeldung dazu: Die Auswahl funktionierte. Ob der
    Hinweis des Nachstellens zu dem Zeitpunkt schon gezeigt war, ist offen. Belegt ist damit nur: Die Auswahl an
    sich geht auf dem Rechner; nicht belegt bleibt, was sie im Testlauf blockiert hat.
  - *Nachgestellt vom Inhaber (15.11.2026, 17:27), mit einem Versuchsskript außerhalb des Repos:* Auswahl öffnen,
    nach 3 s eine Benachrichtigung von einem eigenen Symbol (dieselbe Art wie die der Tray-App), dabei den
    Tastaturfokus mitschreiben. Mit einer Benachrichtigung und mit einer Serie von vier (alle 3 s) ließ sich die
    Auswahl benutzen. Mitschrift der Serie: Die Auswahl (`SnippingTool`) hatte den Fokus ab 0,6 s und behielt ihn
    über die erste Benachrichtigung (3,1 s) hinweg bis 6,1 s; dann ging er an die Konsole zurück (die Auswahl war
    getroffen). Belegt für diesen Aufbau: Eine Benachrichtigung allein nimmt der Auswahl den Fokus nicht.
  - *Damit bleibt als Unterschied zum Testlauf, nicht belegt:* Dort lief gleichzeitig `install.ps1`
    (17:17:58 bis 17:18:03), das die Tray-App beendet und über den Explorer neu startet; die Benachrichtigung eines
    gerade beendeten Programms bleibt stehen, und die neu gestartete App meldet sofort. Das passiert nur bei einer
    Installation, nicht im Betrieb. Nicht weiter verfolgt, solange es im Betrieb nicht wieder auftritt.
  - *Aus der Mitschrift geklärt:* Nach der Auswahl ging der Fokus zweimal an `ShellExperienceHost`, 1,7 s und 1,3 s
    nach der dritten und vierten Benachrichtigung. Das waren Klicks des Inhabers auf die Benachrichtigungen (seine
    Auskunft). Dass eine Benachrichtigung den Fokus von sich aus nimmt, zeigt die Mitschrift also nicht; mit einem
    Spiel im Vollbild ist es nicht geprüft.
  - *Hinweise gebündelt.* Unabhängig von der Ursache war die Serie zu viel: höchstens ein Hinweis in zehn Sekunden
    (`MainViewModel.ToastPause`); was dazwischen kommt, wird danach gemeinsam gemeldet. Symbol und Liste folgen
    sofort. Test mit gestellter Uhr nach dem Muster des Laufs.
  - *Nicht gebaut: Profilverwaltung.* Profile in der Tray-App zu bearbeiten hieße, die Konfiguration mit
    Admin-Rechten zu schreiben und den Dienst neu zu starten. Bis das entschieden ist, bleibt es beim Bearbeiten von
    `appsettings.json` als Administrator und einem Neustart des Dienstes. Entscheidung des Inhabers, ob und wie.
  - *Ein Test ist einmal durchgefallen und ließ sich nicht wiederholen.* In einem Lauf von `build.ps1 -Publish`
    meldete die Dienst-Suite 80 von 81; welcher Test es war, ging in meiner gefilterten Ausgabe verloren. 17 weitere
    Läufe der ganzen Suite danach bestanden alle. Nicht geklärt. *Nachtrag (15.11.2026, 20:00):* Eine mögliche
    Ursache ist gefunden, siehe Abschnitt 17, Schritt 5 („Tests hingen am Rechner“); dass sie es damals war, ist
    nicht belegt.
- **Schritt 4 (15.11.2026): Abnahme der Freigabe aus dem Fenster (`scripts\tray-test.ps1`).** Als Administrator
  bestanden (17:38, 9 von 9), siehe unten.
  - *Warum ein eigenes Skript mit einem Menschen am Bildschirm:* Die Freigabe besteht aus einem Klick im Fenster und
    der Admin-Abfrage von Windows. Beides bedient das Skript nicht (keine Fernsteuerung der Oberfläche, und die
    Admin-Abfrage soll ein Mensch beantworten). Es stellt den Zustand her, wartet und prüft danach.
  - *Ablauf:* installieren (wie `prevention-test.ps1`), prüfen, dass die Tray-App ohne Admin-Rechte läuft;
    Konfiguration mit `lockdown: true` für den Testclient (Profil `TrayTest`), Simulator `--spawn --hold`: Client
    beendet, Profil gesperrt; bis zu 180 s warten, bis `lockdown.json` leer ist; danach: keine Firewall-Regel mehr,
    der laufende Dienst hat die Freigabe bemerkt, der Client startet wieder. Am Ende die Konfiguration von vorher;
    hat niemand freigegeben, gibt das Skript selbst frei, und der Test ist durchgefallen.
  - *Wer hat freigegeben:* Eine leere `lockdown.json` belegt nicht, dass die Tray-App es war. Das Skript sieht
    deshalb während des Wartens alle 100 ms nach einem laufenden `RCEGuard.Service.exe --release` und notiert den
    Namen des Elternprozesses; verlangt ist `RCEGuard.Tray`. Ein Blick dauert auf dem Testrechner rund 70 ms
    (gemessen ohne Admin-Rechte). Annahme, nicht geprüft: Windows trägt bei einem Start mit Admin-Abfrage das
    aufrufende Programm als Elternprozess ein, und der Freigabe-Befehl läuft lang genug, um gesehen zu werden.
    Trifft eines davon nicht zu, fällt genau diese Prüfung durch, obwohl die Freigabe ging; der Wert in der
    Ergebnisdatei sagt dann, was gesehen wurde.
  - `Test-ProcessElevated` liegt jetzt in `TrayTools.ps1` (vorher in `install-test.ps1`), weil beide Tests es
    brauchen.
  - *Geprüft, mit Stellvertretern in PowerShell 7 und 5.1* (Dienst, Tray-App, Simulator und der Mensch am Bildschirm
    ersetzt; Datenordner in TEMP): Freigabe über die Tray-App (ALL PASSED), Freigabe von Hand in einer Konsole
    (nur die Prüfung „von der Tray-App gestartet“ fällt durch), niemand gibt frei (Warten läuft ab, das Skript gibt
    frei und stellt die Konfiguration wieder her, durchgefallen), Tray-App mit Admin-Rechten (durchgefallen). In
    allen Fällen war die Konfiguration danach die von vorher und keine Sicherung übrig. Echt und ohne Admin-Rechte:
    die laufende Tray-App wird gefunden und als nicht erhöht erkannt; `install-test.ps1 -ListOnly` läuft nach dem
    Verschieben der Funktion in beiden Versionen.
  - *Nicht geprüft (vor dem Lauf):* alles, was die Stellvertreter ersetzen, also der Klick, die Admin-Abfrage, der
    Freigabe-Befehl aus der Tray-App und das Erkennen seines Elternprozesses.
  - *Lauf als Administrator (15.11.2026, 17:38): ALL PASSED, 9 von 9.* Der Inhaber hat im Fenster freigegeben und
    die Admin-Abfrage bestätigt. Ablauf nach `guard.log` und Ergebnisdatei: 17:38:16 Client beendet und Profil
    `TrayTest` gesperrt (Regel für jede ausgehende Verbindung geschrieben); Freigabe 25 s nach Beginn des Wartens;
    17:38:48 meldet der laufende Dienst „changed from outside“ und gleicht die Regeln ab; danach startet der Client
    wieder; 17:38:51 läuft der Dienst wieder mit der Konfiguration von vorher. Die Tray-App (der Bau mit den
    gebündelten Hinweisen) lief ohne Admin-Rechte. Beide Annahmen von oben haben sich bestätigt: Der Freigabe-Befehl
    wurde laufend gesehen, und sein Elternprozess war `RCEGuard.Tray`. Zustand danach nachgesehen: Dienst und Sysmon
    laufen, keine Regel von RCEGuard, `lockdown.json` leer, keine `appsettings.json`, eine Tray-App, nicht erhöht.
  - *Weiter nicht geprüft:* der Autostart bei der Anmeldung; ein zweiter angemeldeter Benutzer; die Freigabe mit
    einem Konto ohne Admin-Rechte (dann fragt Windows nach Name und Kennwort eines Administrators statt nach Ja oder
    Nein); der echte Client.

## 17. Entscheidungen bei der Umsetzung von M5

M5 ist „Lernmodus, R7, R8“. Geplante Schritte:

1. **Lernmodus sammelt und schlägt vor** (Kern und Dienst, Befehl `--learned`). Gebaut, siehe unten.
2. **R7 bewerten:** Zugriffsrechte einordnen (nur lesen gegen schreiben/Threads), bekannte Ziele aus dem Gelernten
   zulassen, unbekannte mit Schreibrechten melden. Dazu ein Simulator-Szenario, das ein anderes Programm nur öffnet.
   Gebaut, siehe unten.
3. **R8:** CPU-Last des Clients im Dienst abfragen, Szenario `--cpu` gibt es schon. Gebaut, siehe unten.
4. **Vorschlag in der Tray-App** und Anzeige, dass ein Profil lernt. Hängt an der offenen Entscheidung zur
   Profilverwaltung (Abschnitt 16). Anzeige und Vorschlag gebaut (ohne Übernehmen), siehe Abschnitt 19 am Ende.
5. **Abnahme am installierten Dienst** mit dem Simulator; danach die Sitzung mit dem echten Client (Abschnitt 11).
   Das Skript ist gebaut (vor der Tray-Anzeige, weil aus den Schritten 1 bis 3 zu viel nur mit Tests belegt war),
   siehe unten.

- **Schritt 1 (15.11.2026): Lernmodus sammelt und schlägt vor.** Nicht am installierten Dienst gelaufen.
  - *Schalter:* `"learning": true` je Profil, Standard aus. Kein Zähler für Sitzungen und kein automatisches Ende:
    Der Inhaber schaltet ihn aus. Der Dienst zählt die Starts des Clients nur mit und zeigt sie im Vorschlag.
  - *Was im Lernmodus anders ist (nach Abschnitt 6: „Es wird nichts blockiert, nur gesammelt“):* Für den Client des
    Profils wird nichts beendet und nichts gesperrt (`Handle`: Befund mit `Kill` bekommt als Aktion „not terminated
    (learning mode)“, gemeldet wird er wie sonst, auch über ntfy). Die Firewall-Regel des Profils wird nicht
    geschrieben (`FirewallPlanner.Plan`), weil eine blockierte Verbindung kein Ereignis hinterlässt (Abschnitt 15)
    und so nichts zu lernen wäre. Eine Sperre von vorher bleibt, bis sie freigegeben wird. R2 für eine unbekannte
    Adresse ist ein Logeintrag (Info) statt eines Alarms, `killOnUnknownRemote` gilt nicht. Alle anderen Regeln
    melden wie immer. Der Dienst schreibt bei jedem Start eine Warnung ins Log.
  - *Das heißt auch:* Im Lernmodus schützt RCEGuard diesen Client nicht. Wer in dieser Zeit angegriffen wird, bekommt
    die Meldung, aber nichts wird beendet. Exploit Protection (`install.ps1 -BlockChildProcesses`) ist davon
    unabhängig und bleibt wirksam.
  - *Was gesammelt wird (`Learner`, Datei `learned.json` im Datenordner):* ausgehende Verbindungen (Adresse und
    Port, Anzahl; auch die schon erlaubten), Namensabfragen (Ereignis 22: Name und die Adressen der Antwort),
    Ordner außerhalb des Spielordners, in denen der Client Dateien anlegt (mit Endungen), und andere Programme, die
    er öffnet (Ereignis 10 mit Zugriffsrechten; eigene Kinder nicht, das weiß die Regel-Engine). Je Liste höchstens
    500 Einträge, danach wird nichts Neues aufgenommen und das Profil markiert. Gespeichert wird höchstens alle 5 s
    und beim Beenden.
  - *Vorschlag (`LearnedReport`, Befehl `RCEGuard.Service.exe --learned [Profil]`):* jede Adresse, die die Allowlist
    nicht abdeckt. Hat der Client einen Namen abgefragt, dessen Antwort die Adresse enthielt, wird der Name
    vorgeschlagen statt der Adresse. Ausgegeben werden `allowedHostnames` und `allowedRemote`, wie sie danach
    aussähen. Der Befehl liest nur; übernommen wird von Hand in `appsettings.json`. Automatisch übernehmen würde
    heißen: Was ein Angreifer im Lernmodus tut, steht danach auf der Allowlist.
  - *Dateien und geöffnete Programme werden nur gezeigt.* Eine Allowlist für Dateipfade gibt es nicht: R3 für
    gewöhnliche Dateien außerhalb des Spielordners ist ohnehin nur ein Logeintrag, es gäbe nichts abzuschalten. Für
    geöffnete Programme kam sie mit Schritt 2.
  - *Geprüft:* 26 neue Tests im Kern (Regeln im Lernmodus, Sammeln, Grenzen, Vorschlag, Datei) und 12 im Dienst
    (Wächterschleife mit Stellvertreter-Firewall: nichts beendet, nichts gesperrt, keine Regel, Notizen gespeichert
    und nach Neustart fortgesetzt; Befehl `--learned`). Alle drei Suiten grün (224, 93, 29). Echt und ohne
    Admin-Rechte: die 800 Ereignisse des M2-Abnahmelaufs (`out\m2-events.xml`) durch den gebauten Dienst
    wiedergegeben, einmal ohne und einmal mit Lernmodus. Ohne: dieselben Befunde wie bisher (12 R1 kritisch, 20 R1
    mittel, 4 R2 kritisch, 2 R3, 2 R4, 2 R9). Mit: dieselben, nur R2 als Info und alle `Kill` als „not terminated
    (learning mode)“; `--learned` zeigt 19 Starts, `1.1.1.1:443` achtmal und schlägt `"allowedRemote":
    ["1.1.1.1"]` vor.
  - *Nicht geprüft:* der installierte Dienst im Lernmodus; ein Ereignis 22 des echten Sysmon (in den gespeicherten
    Ereignissen ist keins; der Simulator hat bisher nur Adressen verbunden, das Format der Antwort ist aus der
    Dokumentation von Sysmon); die Meldung über ntfy für einen nicht beendeten Befund; `learned.json` neben einer
    lesenden Tray-App.
  - *Bekannte Lücke:* Die Tray-App zeigt nicht, dass ein Profil lernt; ihr Symbol bleibt grün. Kommt mit Schritt 4.
  - *Offene Entscheidungen des Inhabers:*
    - Soll der Lernmodus wirklich auch das Beenden bei R1, R4, R6 und R9 aussetzen? So steht es in Abschnitt 6, und
      so ist es gebaut. Die strengere Variante (nur R2 und die Firewall-Regel ausgesetzt, alles andere wie immer)
      ist eine Zeile im Dienst. Für die erste Sitzung mit dem echten Client spricht einiges für die gebaute
      Variante: Ein Fehlalarm bei R1 (z. B. ein Fehlerbericht-Programm des Clients) würde sonst das Spiel beenden.
    - Soll der Lernmodus von selbst enden (z. B. nach zwei Sitzungen)? Nicht gebaut.
- **Schritt 2 (15.11.2026): R7 bewerten.** Nicht am installierten Dienst gelaufen.
  - *Einordnung nach den Rechten (`ProcessAccessRules.Classify`):* Rechte, mit denen sich das andere Programm
    verändern lässt (Thread starten `0x0002`, Speicherschutz ändern `0x0008`, Speicher schreiben `0x0020`; „alle
    Rechte“ `0x1fffff`/`0x1F0FFF` enthalten sie) → HOCH, Alarm. Speicher lesen (`0x0010`) → MITTEL, Log. Alles
    darunter (Auskunft, Warten) → Info, Log. Rechte, die sich nicht lesen lassen → HOCH, Alarm (fail closed). R7
    beendet nie: Ein Handle anzufordern ändert noch nichts; wird wirklich ein Thread gestartet, greift R6.
  - *Abweichung vom Konzept:* Abschnitt 4 nennt R7 MITTEL und „nur loggen“, bis der Lernmodus Daten hat, weil Warden
    andere Programme durchsuchen könnte. Durchsuchen braucht Leserechte; die bleiben ein Logeintrag. Ein Alarm ist
    nur das Öffnen mit Schreib- oder Thread-Rechten. Ob der echte Client das je tut (alter Code fordert gern „alle
    Rechte“ an, auch wenn er nur lesen will), zeigt erst die Sitzung mit ihm; dann müsste die Regel oder die
    Allowlist die Rechte je Programm kennen. Bis dahin ist es ein Alarm ohne Beenden.
  - *Allowlist `allowedProcessAccess` je Profil:* volle Pfade (ein bloßer Name träfe auch ein gleichnamiges Programm
    im Download-Ordner). Ein gelistetes Programm darf angesehen werden (Auskunft, Speicher lesen), ohne Eintrag.
    Rechte zum Verändern meldet R7 auch für gelistete Programme: Sonst wäre ein einmal gelerntes Programm ein
    Freibrief, Code hineinzuschreiben.
  - *Der Client öffnet sich selbst:* kein Befund (Quelle und Ziel dieselbe Prozess-GUID). Ein zweiter Prozess
    desselben Programms ist ein anderes Programm.
  - *Vorschlag:* `--learned` schlägt `allowedProcessAccess` mit vor: jedes Programm, das der Client mindestens einmal
    ohne Rechte zum Verändern geöffnet hat. Ein nur mit solchen Rechten geöffnetes Programm steht in der Liste mit
    einem Vermerk, wird aber nicht vorgeschlagen.
  - *Simulator `--open-process [query|read|write]`:* fordert bei Windows ein Handle auf den Explorer der Sitzung an
    (`0x1000`, `0x1010`, `0x102a`) und schließt es sofort. Gelesen oder geschrieben wird nichts; das Handle wird
    nie benutzt. Der Explorer, weil der Simulator kein eigenes Kind öffnen kann (das wäre R1) und der Explorer in
    jeder Sitzung läuft.
  - *Geprüft:* 24 neue Tests im Kern (Einordnung, Allowlist, sich selbst öffnen, Vorschlag, Konfiguration); alle
    Suiten grün (248, 93, 29). Wiedergabe der gespeicherten Ereignisse (`out\m2-events.xml`, `out\events.xml`):
    dieselben Befunde wie vorher, kein R7 (alle Zugriffe darin gelten eigenen Kindern). Echt und ohne Admin-Rechte,
    am installierten Dienst im Stand von vor diesem Schritt: der neue Simulator in `C:\RCEGuardTest` mit allen drei
    Varianten; der Dienst meldete drei R7-Einträge mit genau den angeforderten Rechten (`0x1000`, `0x1010`,
    `0x102a`) und dem Ziel `C:\WINDOWS\Explorer.EXE`, 0,1 bis 1,0 s nach dem Ereignis. Die .NET-Laufzeit des
    Simulators öffnet dabei von sich aus kein weiteres Programm.
  - *Nicht geprüft:* die neue Einordnung am installierten Dienst (dort läuft noch der alte Stand: alle drei als
    MITTEL); ein aufgezeichnetes Ereignis 10 für ein fremdes Programm als Fixture (das Sysmon-Log braucht
    Admin-Rechte; kommt mit der Abnahme); der echte Client.
- **Schritt 3 (15.11.2026): R8, Prozessorlast.** Nicht am installierten Dienst gelaufen.
  - *Entscheidung des Inhabers (15.11.2026): nur die CPU-Last, ohne die Vordergrund-Bedingung aus Abschnitt 4.* Der
    Dienst läuft in Sitzung 0 und sieht nicht, welches Fenster im Vordergrund ist. Die Tray-App könnte es melden,
    läuft aber mit den Rechten des Benutzers; Schadcode mit denselben Rechten könnte die Meldung fälschen.
  - *Regel (`CpuWatch`, Kern):* Durchschnitt der belegten Kerne über ein Fenster (`cpuAlertSeconds`, Standard 300)
    größer als `cpuAlertCores` (Standard 2,0; 0 schaltet die Regel ab) → R8, MITTEL, Alarm, kein Beenden. Gemeldet
    wird einmal je Strecke hoher Last; erst wenn der Durchschnitt wieder auf oder unter dem Wert war, kann der
    nächste Alarm kommen. Vor dem ersten vollen Fenster wird nichts gesagt. Beide Werte gelten für alle Profile:
    Sie hängen am Rechner und am Client-Typ, nicht am Server.
  - *Der Standard von 2,0 Kernen ist eine Annahme:* Der 3.3.5a-Client rechnet im Wesentlichen auf einem Kern.
    Gemessen ist das nicht. Der Lernmodus notiert deshalb die höchste Last (`peakCpuCores` in `learned.json`), und
    `--learned` zeigt sie neben dem Schwellwert.
  - *Messen, ohne den Client zu öffnen (`ProcessTimes`, Dienst):* Prozessorzeit und Startzeit aller Prozesse aus der
    Prozessliste von Windows (`NtQuerySystemInformation`, Klasse 5; die Zahlen des Task-Managers). Der Dienst holt
    sich dafür kein Handle auf den Client. `Process.TotalProcessorTime` von .NET hätte den Client alle 15 s
    geöffnet; bisher öffnet der Dienst einen Prozess nur, um ihn zu beenden, und dabei bleibt es.
  - *Welche Prozesse Clients sind,* weiß der Dienst aus dem Sysmon-Log: Start (Ereignis 1 mit dem Pfad des Clients)
    und Ende (Ereignis 5). Die Prozessliste nennt nur den Dateinamen, nicht den Pfad; nach dem Namen zu gehen hieße,
    auch ein anderes Programm namens `Wow.exe` zu messen. Gegen wiederverwendete PIDs: Die Startzeit aus der
    Prozessliste muss zur Startzeit des Ereignisses passen (2 s Toleranz), sonst wird der Eintrag verworfen.
  - *Lücke:* Ein Client, der schon lief, als der Dienst startete (Neustart des Dienstes mitten in einer Sitzung),
    wird nicht gemessen, bis er neu gestartet wird: Sein Start-Ereignis liegt vor der gespeicherten Position im
    Log. Schließen ließe sich das, indem der Dienst die laufenden Clients mit der Position zusammen speichert.
  - *Takt:* alle 15 s (bei kürzerem Fenster ein Fünftel davon, mindestens 1 s); die Wächterschleife wacht dafür
    entsprechend oft auf, solange ein Client läuft.
  - *Geprüft:* 16 neue Tests im Kern (Fenster, einmal je Strecke, Durchschnitt statt Spitze, Zähler läuft zurück,
    Einstellungen, höchste Last im Lernmodus) und 5 im Dienst: Wächterschleife mit ausgedachten Prozessorzeiten
    (3,0 Kerne bei Schwelle 1,5 über 5 s: ein Alarm, kein zweiter, höchste Last notiert; 1,0 Kerne: kein Alarm;
    fremder Prozess mit derselben PID und beendeter Client: nicht gemessen; `cpuAlertCores: 0`: aus) und die echte
    Prozessliste dieses Rechners (eigener Prozess: Name, Startzeit auf 100 ms, Prozessorzeit wie .NET sie nennt).
    Alle Suiten grün (264, 98, 29), die zeitabhängigen Tests viermal hintereinander.
  - *Nicht geprüft:* R8 am installierten Dienst mit `--cpu` (ob Sysmon-Startzeit und Startzeit der Prozessliste
    wirklich auf 2 s übereinstimmen, zeigt erst dieser Lauf); die Last des echten Clients.
- **Schritt 5 (15.11.2026): Abnahmeskript `scripts\learning-test.ps1`.** Noch nicht als Administrator gelaufen.
  - *Zwei Teile:* (1) Lernen: Profil mit `learning`, dazu `lockdown` und `killOnUnknownRemote` an, damit sichtbar
    wird, dass der Lernmodus beides zurückhält. Der Simulator verbindet sich mit einem Hostnamen und einer Adresse,
    startet ein Programm, öffnet den Explorer (lesen, dann mit Rechten zum Verändern), legt eine Programmdatei an und
    lastet 25 s alle Kerne aus (R8 hier: 1,5 Kerne über 10 s). Geprüft wird am Log des Dienstes, an `lockdown.json`,
    den Firewall-Regeln und an der Ausgabe von `--learned`. (2) Wieder urteilen: Der Vorschlag wird so übernommen,
    wie `--learned` ihn druckt, Lernmodus aus; Gelerntes bleibt still, eine nicht gelernte Adresse ist ein Alarm,
    Ansehen des Explorers ist still, Rechte zum Verändern nicht, ein gestartetes Programm wird beendet.
  - *Der Hostname* (`one.one.one.one`) ist drin, weil der Lernmodus Namensabfragen (Ereignis 22) bisher nur aus dem
    dokumentierten Format liest; der Lauf zeigt, ob das echte Sysmon sie so schreibt. Kommt keine, schlägt das
    Skript die Adresse statt des Namens vor, und genau diese Prüfung fällt durch.
  - *Verbindungen mit `--hold`:* Sysmon zeichnet die Verbindung eines Clients, der nach Sekunden endet, oft nicht auf
    (Abschnitt 14); der Simulator bleibt deshalb nach jeder Verbindung 8 s am Leben.
  - *Am Ende* stehen die Konfiguration und die Notizen von vorher wieder da (`learned.json` wird vor dem Test
    beiseitegelegt: Notizen einer früheren Sitzung würden sonst mitgezählt). Die Sysmon-Ereignisse des Laufs gehen
    nach `out\m5-events.xml`, als Rohmaterial für Fixtures (Ereignis 22, Ereignis 10 für ein fremdes Programm).
  - *Geprüft, mit Stellvertretern in PowerShell 7 und 5.1:* Der Stellvertreter für den Dienst ist die echte
    Regel-Engine: Jeder Aufruf des Simulators wird zu Ereignissen in Sysmon-Form, die der gebaute Dienst mit
    `--replay` auswertet; seine Befundzeilen gehen ins Stellvertreter-Log, und `--learned` ist der echte Befehl auf
    dem Stellvertreter-Datenordner. Damit sind die Textmuster des Skripts gegen die echten Ausgaben geprüft. Von
    Hand im Stellvertreter: die Ereignisse selbst, die R8-Zeile und die höchste Last (eine Wiedergabe misst
    nichts), die Adressen des erlaubten Hostnamens (eine Wiedergabe löst keine Namen auf). Drei Varianten: wie
    gebaut (ALL PASSED, 23 Prüfungen), ein Dienst, der `learning` ignoriert (7 Prüfungen durchgefallen, Abbruch ohne
    Vorschlag), Sysmon ohne Namensabfrage (genau die Namens-Prüfung durchgefallen). In allen Fällen waren
    Konfiguration und Notizen von vorher zurück und nichts übrig. Echt und ohne Admin-Rechte nachgesehen: Name und
    beide Adressen nehmen auf Port 443 Verbindungen an, der Name löst nicht auf eine der beiden Adressen auf, der
    Rechner hat 16 Kerne.
  - *Nicht geprüft:* alles am installierten Dienst (das ist der Lauf des Inhabers).
  - *Tests hingen am Rechner (gefunden beim Veröffentlichen, 20:00).* Zwei Tests der Dienst-Suite
    (`NotifierTests`) fielen durch, weil auf dem Rechner ein Programm namens `WoW.exe` lief (der echte Client des
    Inhabers, seit 19:42): Der Wächter meldet beim Beenden „stopping while the client runs“, wenn ein Prozess mit
    dem Dateinamen des Clients läuft, und Windows vergleicht Namen ohne Groß- und Kleinschreibung; die Tests
    erwarteten genau eine Benachrichtigung. Die Prozessliste für diesen Blick ist jetzt in Tests ersetzbar
    (`GuardWorker.ListProcesses`), die Tests sind unabhängig davon, was auf dem Rechner läuft. Das erklärt
    möglicherweise auch den nicht wiederholbaren Durchfaller aus Abschnitt 16 (damals lief zeitnah der Simulator
    als `Wow.exe`); belegt ist das nicht, das Log von damals gibt es nicht mehr.
  - *Dabei aufgefallen, nicht geändert:* Dieser Blick beim Beenden geht nur nach dem Dateinamen. Läuft ein anderes
    Programm gleichen Namens (hier: der echte Client, während der Dienst den Testclient überwacht), meldet der
    Dienst beim Beenden fälschlich, der Client laufe noch. Es ist nur eine Warnung (und eine ntfy-Meldung, wenn
    eingerichtet); R8 geht aus demselben Grund nicht nach dem Namen.
  - *Erster Lauf als Administrator (15.11.2026, 20:06 bis 20:08): 19 von 23 bestanden, „4 FAILED“.*
    - *Bestanden am installierten Dienst:* Warnung „Learning mode is ON“; gestartetes Programm gemeldet und nicht
      beendet („not terminated (learning mode)“), keine Sperre, keine Regel; R7 für `0x1010` MITTEL und für `0x102a`
      HOCH; R3 HOCH; R8 nach 12 s mit 13,1 Kernen (die Startzeit aus dem Sysmon-Ereignis passt also zur
      Prozessliste); `--learned` mit 7 Starts, dem Explorer als Vorschlag, der Programmdatei und 13,13 Kernen als
      höchster Last. Nach dem Lernen: nicht gelernte Adresse ist R2 KRITISCH, Ansehen des gelisteten Explorers
      still, Rechte zum Verändern weiter HOCH, gestartetes Programm samt Client beendet. Konfiguration zurück.
    - *Durchgefallen, alle vier aus einem Grund:* Sysmon hat keine der beiden Verbindungen des Lernteils
      aufgezeichnet (Client 20:06:48 zu `one.one.one.one`, Client 20:06:56 zu `9.9.9.9`; beide „Connected“, beide
      8 s am Leben). Im Sysmon-Log des Laufs (`out\m5-events.xml`) gibt es für diese beiden Prozesse kein Ereignis 3.
      Ohne Ereignis gab es nichts zu notieren und nichts vorzuschlagen, und im zweiten Teil war deshalb nichts
      erlaubt. Der Dienst hat nichts verschluckt: Alles, was im Sysmon-Log steht, hat er gemeldet.
    - *Was dieselbe Lücke nicht erklärt:* Die drei Verbindungen des zweiten Teils (20:08:00 bis 20:08:16, gleiche
      Art Aufruf) hat Sysmon aufgezeichnet, jeweils 2 s nach der Verbindung. Sysmon hatte seine Konfiguration um
      20:06:44 neu geladen (`install.ps1` am Anfang des Tests); die verpassten Verbindungen lagen 4 s und 12 s
      danach, die aufgezeichneten 76 s und mehr. Vermutung, nicht belegt: Nach dem Laden der Konfiguration zeichnet
      Sysmon eine Weile keine Verbindungen auf. Dagegen spricht eine Verbindung vom Nachmittag, die 3 s nach einem
      Laden aufgezeichnet wurde (17:17:56). Fest steht nur: 8 s am Leben zu bleiben reicht nicht immer (die
      Messung vom 12.11. hatte 4 von 4 ergeben).
    - *Namensabfrage belegt:* Das Ereignis 22 des ersten Clients steht im Log
      (`2606:4700:4700::1001;2606:4700:4700::1111;::ffff:1.1.1.1;::ffff:1.0.0.1;`), also so, wie der Lernmodus es
      liest. Wiedergabe aller Ereignisse des Laufs durch den gebauten Dienst mit einem lernenden Profil: Name mit
      vier Adressen notiert, die IPv6-Verbindung des zweiten Teils dem Namen zugeordnet, Vorschlag
      `allowedHostnames: one.one.one.one`, `allowedRemote: 9.9.9.9, 8.8.8.8`, Explorer.
    - *Daraus geändert:* (1) Das Skript fragt nach jeder Verbindung das Sysmon-Log, ob sie darin steht
      (`Get-SensorConnections`), versucht es bis zu dreimal und führt jeden Versuch im Ergebnis unter „Sensor“ auf,
      mit den Sekunden seit dem letzten Laden der Konfiguration. Eine eigene Prüfung sagt, ob Sysmon die
      Verbindungen aufgezeichnet hat; „kein Befund“ zählt nur für eine aufgezeichnete Verbindung. Ein verpasster
      Versuch ist kein Durchfaller, solange ein späterer aufgezeichnet wurde: Der Test gilt dem Wächter, die Lücke
      des Sensors wird gezählt statt versteckt. (2) IPv6-Adressen in R2: Sysmon schreibt sie ausgeschrieben
      (`2606:4700:4700:0:0:0:0:1001`), mit dem Port dahinter war das Ende der Adresse nicht zu erkennen; jetzt
      Kurzform in eckigen Klammern (`[2606:4700:4700::1001]:443`). (3) Drei Ereignisse des Laufs sind anonymisiert
      als Fixtures eingecheckt (Ereignis 22, Ereignis 10 für den Explorer mit Lese- und mit Schreibrechten), mit
      Tests.
    - *Geprüft nach der Änderung:* Trockenlauf in PowerShell 7 und 5.1 mit fünf Varianten, darunter „Sysmon verpasst
      die ersten zwei Verbindungen“ (ALL PASSED, 5 von 7 aufgezeichnet, die zwei verpassten gelistet) und „Sysmon
      zeichnet keine Verbindung auf“ (6 Prüfungen durchgefallen, 0 von 15). Die Abfragen des Sysmon-Logs selbst sind
      nur in ihrer Form geprüft (dieselben Aufrufe gegen das Anwendungslog in beiden PowerShell-Versionen); das
      Sysmon-Log braucht Admin-Rechte. Alle Suiten grün (268, 98, 29).
    - *Bedeutung für den Betrieb, offen:* Der Lernmodus und R2 hängen daran, dass Sysmon Verbindungen aufzeichnet.
      Der echte Client hält seine Verbindungen lange; ob Sysmon dessen Verbindungen zuverlässig schreibt, ist nicht
      gemessen. Die Firewall-Regel (Abschnitt 15) hängt nicht an Sysmon.
  - *Zweiter Lauf als Administrator (15.11.2026, 20:22 bis 20:24), mit der Sensor-Prüfung: 23 von 24 bestanden.*
    - *Der Lernmodus läuft am installierten Dienst von Anfang bis Ende:* beide Verbindungen notiert (R2 Info), kein
      Alarm; `--learned` schlägt `allowedHostnames: one.one.one.one` und `allowedRemote: 9.9.9.9` vor (die
      Namensabfrage des echten Sysmon wurde also gelesen und der Verbindung zugeordnet), dazu den Explorer; R8 mit
      13,2 Kernen; nach dem Übernehmen des Vorschlags verbindet sich die gelernte Adresse ohne Befund, die nicht
      gelernte ist R2 KRITISCH. Alles Übrige wie im ersten Lauf bestanden.
    - *Durchgefallen ist eine Prüfung, wieder am Sensor:* Für den Hostnamen nach dem Lernen hat Sysmon in drei
      Versuchen keine Verbindung aufgezeichnet. Ob der Wächter sie stillschweigend erlaubt hätte, lässt sich deshalb
      für den Namen nicht sagen (für die Adresse ja).
    - *Sensor: 4 von 9 Verbindungen aufgezeichnet.* Gegengeprüft am gespeicherten Sysmon-Log: Für die fünf anderen
      Prozesse gibt es kein Ereignis 3, auch kein verspätetes; die Namensabfrage (Ereignis 22) steht bei allen drei
      Versuchen mit dem Namen im Log. Die aufgezeichneten wurden 1,4 bis 2,4 s nach dem Start des Clients
      geschrieben. Jeder Client lebte 8,1 s.
    - *Die Vermutung vom ersten Lauf ist widerlegt:* Diesmal wurden gerade die beiden Verbindungen 4 s und 12 s nach
      dem Laden der Konfiguration aufgezeichnet, und verpasst wurden welche 66 s bis 123 s danach. Am Laden der
      Konfiguration liegt es also nicht.
    - *Was beide Läufe zusammen sagen:* Von 14 Verbindungen eines Clients, der 8 s lebt, hat Sysmon 7 aufgezeichnet.
      Die Messung vom 12.11. (4 von 4 bei 8 s) war zu klein. In allen Fällen schließt der Simulator die Verbindung
      sofort nach dem Aufbau; lebendig bleibt nur der Prozess. Nicht gemessen ist, ob eine Verbindung, die offen
      bleibt (wie die des Spiels zum Server), zuverlässig aufgezeichnet wird. Davon hängt ab, wie viel der
      Lernmodus und R2 beim echten Client taugen. Nächster sinnvoller Schritt: genau das messen (Simulator hält die
      Verbindung offen, im Lernmodus, damit keine Alarme kommen), bevor an der Regel etwas geändert wird.
    - *Zustand danach nachgesehen:* Dienst und Sysmon laufen, keine Regel, keine Sperre, Konfiguration und Notizen
      wie vor dem Test.

## 18. Der RCE-Patcher für den Client (zu Abschnitt 12)

Der Inhaber hat am 15.11.2026 nach `Gargash/WoW-RCE-Patcher` gefragt (ein Fork von `stoneharry/RCEPatcher`, den
Abschnitt 12 als Ergänzung außerhalb des Projekts nennt). Nachgelesen am Quelltext, nicht ausgeführt:

- *Was er tut:* Er kopiert `WoW.exe` nach `WoW_patched.exe` und setzt in der Kopie ein einziges Byte, an der festen
  Dateiposition `0x2A7`, auf `0xC0`. Mehr nicht: kein Netzwerk, keine Registry, keine Prüfung von Version oder
  Dateigröße, und er liest das Byte vorher nicht.
- *Was das Byte ist (am Dateikopf des Clients des Inhabers nachgesehen, Build 12340, nur gelesen):* das oberste Byte
  der Rechte des Abschnitts `.zdata`. Dort steht `0xE0` (lesen, schreiben, ausführen); `0xC0` heißt lesen und
  schreiben, nicht ausführen. Der Client ist als DEP-fähig markiert, Windows setzt das also durch. Der Patcher
  nimmt damit einem beschreibbaren Bereich des Clients das Recht, Code auszuführen; laut seiner Beschreibung
  stürzt der Client ab, wenn ein Server den Exploit versucht. Wie der Exploit selbst geht, beschreiben beide
  Projekte nicht, und hier steht es auch nicht.
- *Verhältnis zu RCEGuard:* nicht dasselbe, sondern die andere Hälfte. Der Patcher verhindert einen bekannten Weg
  am Client selbst, indem er die Client-Datei ändert. RCEGuard ändert den Client nie und beobachtet von außen, was
  eingeschleuster Code täte, egal auf welchem Weg er hineinkommt. Beides zusammen ist sinnvoll.
- *Vorbehalte:* Die Position ist fest. Bei einer anderen `WoW.exe` (anderer Build, vom Server angepasste Datei)
  kann `0x2A7` etwas anderes sein; der Simulator dieses Projekts hat dort z. B. `0x00` in einem anderen Feld. Vor
  dem Patchen also nachsehen, dass dort `0xE0` steht und es der Abschnitt `.zdata` ist. Ob ein Server eine
  geänderte Client-Datei beanstandet, sagen die Projekte nicht; geprüft ist es nicht.
- *Der Client des Inhabers ist nicht gepatcht* (dort steht `0xE0`).

## 19. Messung: Welche Verbindungen zeichnet Sysmon auf? (`scripts\sensor-probe.ps1`)

Anlass: In den beiden Abnahmeläufen von M5 hat Sysmon 7 von 14 Verbindungen des Testclients aufgezeichnet
(Abschnitt 17), obwohl jeder Client 8 s lebte. Der Simulator hat die Verbindung dabei immer sofort geschlossen.
Offen ist, ob eine Verbindung, die offen bleibt, zuverlässig aufgezeichnet wird; so verhält sich das Spiel.

- *Simulator:* `--connect ... --keep-open --hold N` lässt die Verbindung bis zum Ende des Prozesses offen und sagt
  am Ende, ob sie noch offen war oder von der Gegenseite geschlossen wurde. Gesendet wird nichts.
- *Skript (15.11.2026):* Profil im Lernmodus (R2 ist dann ein Logeintrag,
  es kommt keine Benachrichtigung), dann abwechselnd zehnmal „sofort geschlossen“ und zehnmal „offen gehalten“,
  reihum zu drei Adressen, jeder Client 8 s am Leben. Nach jeder Verbindung fragt es das Sysmon-Log nach einem
  Ereignis 3 mit der PID des Clients (bis 4 s nach dessen Ende, also 12 s nach der Verbindung). Ergebnis: jede
  Verbindung einzeln, Zählung je Art, und ob der Wächter so viele Verbindungen gemeldet hat, wie Sysmon
  aufgezeichnet hat. Es installiert nichts und lädt die Sysmon-Konfiguration nicht neu. Konfiguration und Notizen
  des Lernmodus stehen danach wieder da.
- *Es ist eine Messung, kein Test:* Es gibt kein „bestanden“. Abbruch (Exit-Code 1) nur, wenn etwas nicht lief oder
  keine einzige Verbindung zustande kam.
- *Geprüft, mit Stellvertretern in PowerShell 7 und 5.1* (Simulator, Sysmon-Log und Dienst ersetzt, alle Antworten
  ausgedacht): vier Varianten (jede zweite „sofort geschlossene“ fehlt; keine Verbindung möglich; Wächter meldet
  eine weniger; Simulator scheitert beim dritten Aufruf). Zählung und Aufräumen stimmen in allen. Echt und ohne
  Admin-Rechte: Der neue Simulator hält eine Verbindung zu `1.1.1.1:443` 3 s offen („still open“), aus einem
  Ordner, den Sysmon nicht überwacht.
- *Nicht geprüft:* die Abfrage des Sysmon-Logs im Skript (dieselbe Form wie in `learning-test.ps1`, dort am
  15.11.2026 um 20:24 als Administrator gelaufen); der Lauf selbst.
- *Was die Messung nicht klärt:* warum Sysmon Verbindungen auslässt. Sie sagt nur, ob es an der Dauer der
  Verbindung hängt.
- *Lauf als Administrator (15.11.2026, 20:35 bis 20:38):* 20 Verbindungen, alle zustande gekommen, alle „offen
  gehaltenen“ waren am Ende noch offen.

  | Art | aufgezeichnet |
  | :--- | :--- |
  | sofort geschlossen | 9 von 10 |
  | 8 s offen gehalten | 8 von 10 |

  - *Ergebnis:* Offenhalten schließt die Lücke nicht. Zwei Verbindungen, die 8 s offen standen, fehlen im
    Sysmon-Log. Der Unterschied zwischen den Arten (eine gegen zwei) sagt bei je zehn nichts.
  - *Der Wächter verliert nichts:* 17 Verbindungen von Sysmon aufgezeichnet, 17 vom Wächter gemeldet.
  - *Aufgezeichnete Ereignisse* standen 1,3 bis 2,2 s nach dem Start des Clients im Log, wie bisher gemessen.
  - *Die Ausfälle kommen gehäuft:* hier 20:36:08 und 20:36:20 hintereinander und 20:37:46; im zweiten
    Abnahmelauf vier hintereinander (20:23:04 bis 20:23:41) und einer; im ersten die beiden ersten. Über alle drei
    Läufe 24 von 34 aufgezeichnet, mit Quoten von 2 von 5, 4 von 9 und 17 von 20. Das sieht nach Zeitabschnitten
    aus, in denen Sysmon keine Verbindungen schreibt, nicht nach einem Zufall je Verbindung. Vermutung, nicht
    belegt. In allen drei Läufen lief das Spiel des Inhabers; ob das eine Rolle spielt, ist nicht gemessen.
  - *Nicht geklärt:* die Ursache; ob Sysmon eine Verbindung, die es beim Aufbau verpasst hat, je nachträgt (das
    Skript wartet bis 12 s nach dem Aufbau, im Abnahmelauf lag das ganze Log vor: dort kam nichts nach).
  - *Folgen:* R2 und der Lernmodus sehen die meisten Verbindungen des Clients, nicht alle. Für den Lernmodus heißt
    das: Der Vorschlag kann eine Adresse auslassen, mit der sich der Client verbunden hat. Wird danach die
    Firewall-Regel des Profils eingeschaltet, ist diese Adresse blockiert, und eine blockierte Verbindung meldet
    der Wächter nicht (Abschnitt 15). Für R2 heißt es: Eine Verbindung zu einer fremden Adresse kann unbemerkt
    bleiben; die Firewall-Regel blockiert sie trotzdem, sie hängt nicht an Sysmon.
  - *Möglicher Ausweg, nicht gebaut:* Der Dienst fragt zusätzlich die Verbindungstabelle von Windows ab
    (`GetExtendedTcpTable` mit der PID des Besitzers; das, was `netstat -o` zeigt), für die Clients, die er für R8
    ohnehin kennt. Dafür wird der Client nicht geöffnet. Eine Verbindung, die länger steht als der Abstand der
    Abfragen (die des Spiels zum Server steht die ganze Sitzung), fände er so auch dann, wenn Sysmon sie verpasst
    hat; sehr kurze Verbindungen fängt weiter nur Sysmon. Beide Quellen zusammen deckten ab, was eine allein
    auslässt.
- **Gebaut (15.11.2026): die Verbindungstabelle von Windows als zweite Quelle.** Entscheidung des Inhabers nach der
  Messung. Am installierten Dienst gemessen (21:53), siehe unten.
  - *Lesen (`TcpConnections`, Dienst):* `GetExtendedTcpTable` für IPv4 und IPv6 mit der PID des Besitzers, also
    die Liste von `netstat -o`. Kein Prozess wird dafür geöffnet. Aus den Zeilen eines Clients zählen nur
    Verbindungen, die er selbst aufgebaut hat: keine lauschenden Sockets, keine auf einem eigenen lauschenden Port
    angenommenen Verbindungen, nichts zu diesem Rechner (`OutboundOf`). Die Tabelle sagt die Richtung nicht; das ist
    die Annäherung daran.
  - *Entscheiden, was neu ist (`ConnectionWatch`, Kern):* Die Tabelle soll Lücken füllen, nicht doppelt melden. Eine
    Verbindung, die Sysmon für diesen Prozess gemeldet hat, ist erledigt. Eine, die nur die Tabelle zeigt, muss
    5 s lang zu sehen sein (Sysmon schreibt bis zu 3 s verspätet), dann gilt sie als von Sysmon verpasst und wird
    einmal herausgegeben. Verschwindet sie vorher, wird sie vergessen: Für so kurze Verbindungen bleibt Sysmon die
    einzige Quelle. Je Prozess höchstens 4096 Gegenstellen.
  - *In der Wächterschleife:* Der Dienst kennt die laufenden Clients schon für R8 (Start und Ende aus dem
    Sysmon-Log, Startzeit gegen wiederverwendete PIDs). Solange einer läuft, liest er alle 2 s Prozessliste und
    Verbindungstabelle. Eine verpasste Verbindung schreibt er ins Log („found in the connection table of Windows;
    Sysmon did not record it“) und gibt sie dann in der Form des Sysmon-Ereignisses an Regel-Engine und Lernmodus:
    dieselbe Beurteilung (R2, Allowlist, Lernmodus), dieselben Notizen. Kein Schalter: Es gibt keinen Grund, die
    zweite Quelle abzuschalten. Die Clients werden jetzt auch verfolgt, wenn R8 aus ist.
  - *Kommt das Sysmon-Ereignis doch noch nach der Tabelle* (später als 5 s), wird es normal ausgewertet; ein Alarm
    zählt dann als Wiederholung (Abschnitt 14), im Lernmodus wird die Verbindung zweimal gezählt. Die Zählung im
    Lernmodus ist ohnehin keine Zahl der Verbindungen mehr, sondern „wie oft gesehen“.
  - *Was bleibt:* Verbindungen, die nach weniger als etwa 5 bis 7 s wieder zu sind, sieht der Dienst nur über
    Sysmon. Ein Client, der beim Start des Dienstes schon lief, wird nicht angesehen (wie bei R8). UDP steht nicht
    in dieser Tabelle; Sysmon zeichnet UDP auf, der 3.3.5a-Client spricht TCP.
  - *Geprüft:* 8 Tests im Kern (Wartezeit, einmal herausgeben, von Sysmon gemeldet, zu kurz, zwei Schreibweisen
    einer Adresse, Prozesse getrennt, Obergrenze) und 9 im Dienst: die echte Tabelle dieses Rechners für IPv4 und
    IPv6 (eigene Verbindung über einen lokalen Port: lauschender Socket, verbindendes und annehmendes Ende mit den
    richtigen Ports und der eigenen PID), die Auswahl der Zeilen, und die Wächterschleife mit ausgedachter Tabelle
    (verpasste Verbindung einmal gemeldet; von Sysmon gemeldete nicht noch einmal; erlaubte Adresse ohne Befund;
    im Lernmodus notiert; zu kurze Verbindung nicht; Tabelle nicht lesbar: eine Warnung, Dienst läuft weiter). Alle
    Suiten grün (276, 107, 29), die zeitabhängigen viermal hintereinander.
  - *Messskript angepasst:* Es zeigt je Verbindung, was Sysmon aufgezeichnet und was der Wächter gesehen hat (über
    Sysmon oder über die Tabelle), und zählt beides je Art. Die Clients leben jetzt 12 s statt 8 s, damit die
    Tabelle Zeit hat (5 s Wartezeit, 2 s Takt). `-Install` bringt den installierten Dienst vorher auf den
    veröffentlichten Stand. Trockenlauf in PowerShell 7 und 5.1 mit fünf Varianten.
  - *Nicht geprüft:* der installierte Dienst (liest er als LocalSystem dieselbe Tabelle, findet er die Verbindung
    eines fremden Prozesses rechtzeitig); die Last durch das Abfragen alle 2 s ist nicht gemessen, nur geschätzt
    (zwei Systemaufrufe über einige hundert Zeilen).
  - *Lauf als Administrator am installierten Dienst (15.11.2026, 21:49 bis 21:53), `sensor-probe.ps1 -Install`:*

    | Art | Sysmon aufgezeichnet | Wächter gesehen | davon nur über die Tabelle |
    | :--- | :--- | :--- | :--- |
    | sofort geschlossen | 9 von 10 | 9 von 10 | 0 |
    | 12 s offen gehalten | 7 von 10 | 10 von 10 | 3 |

    - *Die zweite Quelle tut am installierten Dienst, was sie soll:* Alle drei offen gehaltenen Verbindungen, die
      Sysmon verpasst hat, hat der Dienst (als LocalSystem) in der Tabelle gefunden, 7,0 bis 8,6 s nach dem Start
      des Clients, und im Lernmodus notiert. Nichts wurde doppelt gemeldet: 19 Meldungen des Wächters, 16 aus Sysmon
      und 3 aus der Tabelle.
    - *Wie erwartet offen:* Die eine sofort geschlossene Verbindung, die Sysmon verpasst hat, hat niemand gesehen.
    - *Sysmon über alle vier Läufe des Tages:* 40 von 54 Verbindungen aufgezeichnet. Die Ursache der Ausfälle ist
      weiter ungeklärt.
    - *Nebenbei:* `9.9.9.9` und `8.8.8.8` schließen eine stumme Verbindung von sich aus irgendwann zwischen 8 s und
      12 s, `1.1.1.1` nicht. Für die Messung egal: Gefunden wurden die Verbindungen vorher.
    - *Zustand danach nachgesehen:* Dienst (Stand 21:41) und Sysmon laufen, Konfiguration und Notizen wie vor der
      Messung, keine Regel, keine Sperre. Keine Warnung des Dienstes zur Tabelle im Log.
    - *Weiter nicht geprüft:* der echte Client (seine Verbindungen stehen lange; ob der Dienst sie über Sysmon oder
      über die Tabelle sieht, zeigt die erste Sitzung im Lernmodus); die Last durch das Abfragen.
- **Schritt 4 (15.11.2026): Lernmodus in der Tray-App.** Nicht neben dem installierten Dienst gesehen.
  - *Symbol:* blaues Schild mit Ring (`TrayKind.Learning`). Reihenfolge: Dienst läuft nicht, dann Sperre, dann neue
    Befunde, dann Lernmodus, dann „alles ruhig“. Bei neuen Befunden im Lernmodus bleibt das Symbol orange, die
    zweite Zeile sagt aber dazu, dass für diesen Client nichts beendet oder blockiert wird.
  - *Fenster:* Überschrift „Learning mode: '…' is watched, not protected“, darunter in Blau je lernendem Profil eine
    Zeile (Starts des Clients, Verbindungsziele, geöffnete Programme) mit dem Knopf „What was learned ...“. Der
    öffnet ein Fenster mit dem Text, den auch `--learned` druckt (`LearnedReport.Render`, derselbe Code), zum Lesen
    und Kopieren.
  - *Woher die Tray-App es weiß:* aus der Konfigurationsdatei (wie schon die Namen der Profile) und aus
    `learned.json`. Sie liest also, was in der Datei steht, nicht, was der laufende Dienst geladen hat; nach einer
    Änderung ohne Neustart des Dienstes weicht das ab. Eine eigene Statusdatei des Dienstes würde das schließen,
    ist aber nicht gebaut.
  - *Übernehmen bleibt Handarbeit:* Die Tray-App schreibt keine Konfiguration (Abschnitt 16, offene Entscheidung zur
    Profilverwaltung). Der Text sagt das im Fenster.
  - *Geprüft:* 5 neue Tests (Zustand und Reihenfolge, Status liest lernende Profile und Notizen, Zeilen und Text im
    Fenster, Bilder); alle Suiten grün (276, 107, 34). Fenster mit Lernmodus, das Fenster mit dem Gelernten und die
    fünf Symbole in Bilder gezeichnet und angesehen.
  - *Nicht geprüft:* die Tray-App neben dem installierten Dienst mit einem lernenden Profil (Symbolwechsel, Knopf,
    Kopieren in die Zwischenablage); `learned.json` lesen, während der Dienst sie gerade ersetzt.

## 20. Vorbereitung der Sitzung mit dem echten Client (15.11.2026)

- *Schalter `install.ps1 -Learning`:* schreibt `appsettings.json` mit dem Client als einzigem Profil (`Default`) im
  Lernmodus, bevor der Dienst startet. Nur wenn es noch keine Konfiguration gibt; eine vorhandene Datei fasst das
  Skript nie an (dann bricht es ab, bevor es etwas ändert, und sagt, was von Hand zu tun ist). Mit `-SkipService`
  nicht kombinierbar. Am Ende sagt das Skript in Gelb, dass der Client nicht geschützt ist und wie es weitergeht.
  Ausgeschaltet wird der Lernmodus von Hand in der Datei; einen Schalter dafür gibt es nicht, weil dabei auch die
  Allowlist einzutragen ist.
- *Geprüft, mit Stellvertretern in PowerShell 7 und 5.1* (ProgramData in TEMP, Sysmon „schon installiert“, Dienst
  und Tray-App ersetzt): 10 Prüfungen, darunter: ohne Schalter keine Datei; mit Schalter steht die Datei, bevor der
  Dienst startet, ohne Byte-Order-Mark; **der echte, gebaute Dienst liest sie und sieht das Profil als lernend**
  (`--learned` auf dem Stellvertreter-Ordner); zweiter Aufruf mit Schalter und eine von Hand geschriebene
  Konfiguration werden abgelehnt, ohne etwas zu ändern. Der frühere Trockenlauf für die Exploit-Protection-Schalter
  besteht weiter (0 Fehler in beiden Versionen).
- *Am Rechner des Inhabers nachgesehen, nur lesend:* Die Sysmon-Konfiguration lässt sich für den Pfad des echten
  Clients erzeugen (Pfad mit Leerzeichen; wohlgeformtes XML, kein Platzhalter übrig); die sechs Datenordner, die
  der Sensor ausnimmt (`Cache`, `WTF`, `Logs`, `Interface`, `Screenshots`, `Errors`), gibt es im Spielordner. Im
  Spielordner liegt neben dem Client ein zweites Programm (ein Patch-Menü). Startet der Client es, ist das R1
  (im Lernmodus gemeldet, nicht beendet); startet es den Client, sieht der Wächter davon nichts.
- *Nicht geprüft:* `install.ps1 -Learning` als Administrator; alles am echten Client.
- *Worauf die Sitzung Antworten geben soll:* (1) Akzeptanzkriterium aus Abschnitt 11: keine Befunde HOCH oder
  KRITISCH in einer normalen Sitzung, also welche Regeln beim echten Client fälschlich feuern; (2) welche Adressen
  und Namen, über Sysmon oder über die Verbindungstabelle; (3) welche Programme der Client öffnet und mit welchen
  Rechten (R7: fordert er „alle Rechte“ an?); (4) höchste Prozessorlast gegen die 2,0 Kerne von R8; (5) ob die
  Tray-Anzeige im Betrieb stimmt.
- *Datenschutz:* Log, Notizen und Befunde einer echten Sitzung enthalten die Adressen der Server und Pfade mit dem
  Windows-Benutzernamen. Nichts davon kommt ins Repo (Regel in `CLAUDE.md`: keine echten Server-IPs); in die Doku
  gehen nur Anzahlen und Regelnamen.
- *`install.ps1 -Learning` als Administrator und erster Start des echten Clients (15.11.2026, 22:26 bis 22:29).*
  - *Installation:* ohne Fehler. Nachgesehen: Dienst und Sysmon laufen, Sensor, Dienst und `appsettings.json` nennen
    denselben Client, Profil `Default` im Lernmodus, Warnung „Learning mode is ON“ im Log, Tray-App im neuen Stand
    und ohne Admin-Rechte, keine Regel, keine Sperre, keine Exploit-Protection-Einstellung.
  - *Die Sitzung war kurz:* Der Client lief von 22:27:13 bis etwa 22:29:38 (letztes Ereignis im Sysmon-Log), also
    rund zweieinhalb Minuten: Start, Anmeldung, Realm. Für die Fragen aus der Vorbereitung reicht das nur zum Teil.
  - *Fehlalarme beim Start:* keiner. 43 Befunde, alle nur geloggt: 36 R7 MITTEL, 4 R2 Info, 2 R3 MITTEL, 1 R4 Info.
  - *R7:* Der Client hat in den ersten Sekunden 36 verschiedene laufende Programme geöffnet (Browser,
    Chat-Programme, Systemprozesse, Konsolen), alle mit `0x10` (Speicher lesen), eines zusätzlich mit `0x1410`;
    100 Zugriffe gezählt. Das ist das Muster, das Abschnitt 4 von Warden erwartet hat. Kein Zugriff mit Rechten
    zum Verändern, also kein R7 HOCH: Die Sorge aus Schritt 2 („fordert er alle Rechte an?“) hat sich für den Start
    nicht bestätigt. Ob er tatsächlich gelesen hat, sagt Sysmon nicht.
  - *Verbindungen:* vier Ziele (zweimal Port 80, der Anmeldeport 3724, ein Realm-Port). Sysmon hat zwei davon
    aufgezeichnet; die beiden auf Port 80 hat der Dienst nach rund 6 s in der Verbindungstabelle gefunden. Für drei
    der vier Adressen gab es eine Namensabfrage, der Vorschlag nennt also Namen. Die zweite Quelle war beim echten
    Client schon beim ersten Start nötig.
  - *Dateien:* zwei Einträge im Internet-Cache des Benutzers (R3 MITTEL), passend zu den Abrufen über Port 80.
  - *R4 Info:* ein Schreibzugriff unter `Services\Tcpip\Parameters`, wie beim Simulator.
  - *Nicht gemessen:* die Prozessorlast (R8 braucht ein volles Fenster von 300 s; höchste Last in den Notizen: 0)
    und alles, was erst im Spiel passiert: Kampf, Schlachtfeld, Raid, Realmwechsel, wiederholte Scans, Abmelden.
    Das Akzeptanzkriterium aus Abschnitt 11 (zwei Stunden ohne Befund HOCH oder KRITISCH) ist damit offen.
  - *Der Lernmodus bleibt an.* Eine längere Sitzung braucht keine neue Installation; die Notizen werden fortgesetzt.
