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
- **Offen in M2:** die halb entfernte Sysmon-Installation abräumen (`uninstall.ps1 -RemoveStuckSysmonService`,
  Neustart, `uninstall.ps1`), danach `install-test.ps1` noch einmal vollständig; Verhalten nach dem Aufwachen aus
  dem Ruhezustand. Die Selbstprüfung gegen ein stummes Abo hat im echten Dienst noch nie ausgelöst (das Abo liefert);
  sie ist nur in den Tests mit einem stummen Ersatz-Abo geprüft.
