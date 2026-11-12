# Sysmon event fixtures

Real events recorded with Sysmon 15.22 while the simulator (`src/RCEGuard.FakeWow`, running as
`C:\RCEGuardTest\Wow.exe`) ran its scenarios. One event per file, in the XML form of
`EventRecord.ToXml()`.

They are anonymised before they are committed: user name, computer name, user SID, logon id,
current directory and the machine part of the process GUIDs are replaced. New fixtures must be
treated the same way; `scripts/show-events.ps1 -OutFile` writes the raw events, which contain
all of these.

| File | Scenario | Meaning for the rules |
| :--- | :--- | :--- |
| `client-start.xml` | any | the client itself starts; no finding |
| `r1-child-process.xml` | `--spawn` | R1 |
| `r1-console-host.xml` | any, started hidden (acceptance test) | console host Windows attaches to a console program; R1 logged, nothing terminated |
| `r1-miner-child.xml` | `--miner-args` | R1 and R9; Sysmon names only `R1` |
| `r2-network-connect.xml` | `--connect` | R2 |
| `r3-file-create-appdata.xml` | `--drop` | R3 |
| `r4-run-key-set.xml` | `--runkey` | R4; note `HKU\<SID>` instead of `HKCU` |
| `r4-run-key-delete.xml` | `--runkey` | R4, removal |
| `r4-bam-services-noise.xml` | `--spawn` | Windows bookkeeping below `Services\bam`; no finding |
| `r5-client-image-unsigned.xml` | any | the client image itself, unsigned; no finding |
| `r5-system-dll-signed.xml` | any | signed system module; no finding |
| `r7-process-access-own-child.xml` | `--spawn` | handle to the own child; no finding after R1 |
| `client-exit.xml` | any | client session ends |
