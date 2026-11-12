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
  gescheitertem Start. Bekannte Lücke: Während der Dienst nicht läuft (hier 5 s), werden Ereignisse nicht nachgeholt;
  das Abo liest nur neue Einträge. Ein Lesezeichen im Sysmon-Log würde das schließen.
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
- **Offen in M2:** Verfolgung von Enkelprozessen, Entprellen wiederholter Alarme.
