# CLAUDE.md — RCEGuard

Wächter gegen Remote Code Execution für WoW-3.3.5a-Clients auf Privatservern. Maßgeblich ist
[`docs/KONZEPT.md`](docs/KONZEPT.md) (Regeln R1–R9, Meilensteine M1–M5); der Stand steht in der
Tabelle „Status“ der [`README.md`](README.md) und wird mit jedem Meilenstein nachgezogen.

## Harte Regeln

- **Kein Eingriff in den Spielprozess.** Keine Injektion, keine Hooks, kein Patchen, kein Lesen des
  Prozessspeichers. Beobachtet wird nur über Betriebssystem-Mechanismen (Sysmon, Firewall, Exploit Protection).
- **Kein echter Exploit und kein Injektor im Repo.** Getestet wird mit dem Simulator
  `src/RCEGuard.FakeWow` (läuft als `Wow.exe`) und mit aufgezeichneten Sysmon-Events als Fixtures.
  Jedes Simulator-Szenario ist harmlos und räumt hinter sich auf.
- **Sysmon wird nicht mitgeliefert**, nur von Microsoft geladen und auf Microsoft-Signatur geprüft. Eine fremde
  Sysmon-Konfiguration wird nie stillschweigend ersetzt.
- **Alles ist rückbaubar.** Was `install.ps1` anlegt, entfernt `uninstall.ps1`; neue Systemänderungen (Dienst,
  Firewall, Exploit Protection) kommen im selben Schritt in beide Skripte.
- **Keine Versprechen.** Keine Aussagen wie „schützt vor RCE“ oder „sicher vor Sperren“; beschrieben wird, was
  erkannt und was blockiert wird.
- **Keine Geheimnisse im Repo** (ntfy-URLs, Tokens, echte Server-IPs aus dem Lernmodus).

## Build

Immer `.\build.ps1`, nie blankes `dotnet build`: Liegt nur eine Runtime im `PATH`, meldet `dotnet build`
„No .NET SDKs were found“ und endet trotzdem mit Exit-Code 0. `TreatWarningsAsErrors` und `Nullable` gelten
lösungsweit. `.\build.ps1 -Publish` legt zusätzlich den Dienst nach `artifacts\service` (self-contained); von dort
installiert ihn `install.ps1`.

## Admin-Rechte

`install.ps1`, `uninstall.ps1`, `show-events.ps1`, `acceptance-test.ps1` und `install-test.ps1` brauchen
Admin-Rechte und ändern Systemzustand. Agenten führen sie nicht selbst aus, sondern liefern die Befehle und werten
die Rückmeldung des Inhabers aus. `render-config.ps1`, `build.ps1`, der Simulator und `install-test.ps1 -ListOnly`
(listet nur, was von einer Installation auf dem Rechner ist) laufen ohne Admin-Rechte.

Der Dienst läuft als `LocalSystem` und startet nur aus `C:\Program Files\RCEGuard`, nie aus einem Ordner, den ein
normaler Benutzer ändern kann (also nie direkt aus dem Repo oder aus `artifacts\`).

In Skripten keine `$PSScriptRoot`-Ausdrücke als Parameter-Standardwerte: Unter `powershell.exe -File`
(Windows PowerShell 5.1) ist die Variable im `param`-Block noch leer.

## Sprache

Englisch: README, Skripte, Code, Kommentare, Meldungen (das Projekt soll veröffentlicht werden können).
Deutsch: `docs/KONZEPT.md` und diese Datei.
