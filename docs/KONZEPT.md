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
