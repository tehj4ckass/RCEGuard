<#
.SYNOPSIS
    Measures how reliably Sysmon records the connections of the test client (of a connection that
    is closed right after it is made, and of one that stays open), and what the guard sees in
    the end, with the connection table of Windows as its second source.

.DESCRIPTION
    A measurement, not a test of the guard. In the acceptance runs of 2026-11-15 Sysmon recorded
    only about half of the connections of a client that stayed alive for 8 s; the simulator
    closed each connection at once. The game keeps its connection to the server open. This
    script measures both kinds side by side.

    It runs against the installed service and the simulator (the test client) and

      1. puts the test profile into learning mode (connections are then noted, not alerted, so
         no notification comes up) and restarts the service,
      2. lets the simulator connect -Count times in each way, taking turns, to the addresses
         in -Addresses in turn, and asks the Sysmon log after each connection whether it is in there,
      3. counts per kind what Sysmon recorded and what the guard saw: through Sysmon, or, for a
         connection that stayed open and that Sysmon did not record, in the connection table of
         Windows (the guard looks there every 2 s and takes a connection that has been open for 5 s),
      4. puts the configuration and the notes of the learning mode back.

    Needs an administrator PowerShell, an internet connection, and RCEGuard installed for the
    test client (install.ps1, or one of the tests before). Without -Install it installs nothing
    and does not change the configuration of Sysmon. The result goes to
    <OutDir>\sensor-probe-result.txt.

.PARAMETER TestDir
    Folder with the simulator (Wow.exe).

.PARAMETER OutDir
    Folder for the result; created if missing.

.PARAMETER DataDir
    Data folder of the service.

.PARAMETER Addresses
    IPv4 addresses to connect to, in turn. Each must accept TCP connections on -Port.

.PARAMETER Port
    TCP port.

.PARAMETER Count
    Connections per kind.

.PARAMETER HoldSeconds
    How long each client stays alive after connecting (and, for the second kind, keeps the
    connection open).

.PARAMETER Install
    Run install.ps1 for the test client first, to bring the installed service and tray
    application up to what '.\build.ps1 -Publish' last published. Sysmon must be installed.

.PARAMETER AllowNonAdmin
    Skip the administrator check. Only useful for trying the script itself with stand-ins.

.EXAMPLE
    .\scripts\sensor-probe.ps1

.EXAMPLE
    .\scripts\sensor-probe.ps1 -Install
#>
[CmdletBinding()]
param(
    [string] $TestDir = 'C:\RCEGuardTest',
    [string] $OutDir,
    [string] $DataDir = (Join-Path $env:ProgramData 'RCEGuard'),
    [string[]] $Addresses = @('1.1.1.1', '9.9.9.9', '8.8.8.8'),
    [int] $Port = 443,
    [int] $Count = 10,
    [int] $HoldSeconds = 12,
    [switch] $Install,
    [switch] $AllowNonAdmin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Under 'powershell.exe -File' (Windows PowerShell 5.1) $PSScriptRoot is still empty while the param block is evaluated.
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot '..\out' }

. (Join-Path $PSScriptRoot 'GuardServiceTools.ps1')

$profileName = 'SensorProbe'
$client = Join-Path $TestDir 'Wow.exe'
$configPath = Join-Path $DataDir 'appsettings.json'
$configBackup = Join-Path $DataDir 'appsettings.json.before-sensor-probe'
$learnedPath = Join-Path $DataDir 'learned.json'
$learnedBackup = Join-Path $DataDir 'learned.json.before-sensor-probe'
$guardLog = Join-Path $DataDir $script:GuardLogName

function Install-ForTest {
    & (Join-Path $PSScriptRoot 'install.ps1') -ClientPath $client | Out-Host
}

function Invoke-Client([string[]] $arguments) {
    # Runs the simulator and returns its pid, its exit code and what it printed.
    $out = Join-Path $OutDir 'sensor-probe-client.out'
    $process = Start-Process -FilePath $client -ArgumentList $arguments -RedirectStandardOutput $out -PassThru -WindowStyle Hidden
    $null = $process.Handle
    if (-not $process.WaitForExit(($HoldSeconds + 30) * 1000)) {
        $process.Kill()
        throw "The simulator did not end: $($arguments -join ' ')"
    }
    $text = [string] (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $text; ProcessId = $process.Id }
}

function Get-SensorConnections([datetime] $since) {
    # The connections Sysmon recorded since then (event 3): pid, address, and when the event was written.
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 3; StartTime = $since } -ErrorAction SilentlyContinue |
        ForEach-Object {
            $data = ([xml] $_.ToXml()).Event.EventData.Data
            [pscustomobject]@{
                ProcessId = [int] (($data | Where-Object { $_.Name -eq 'ProcessId' }).'#text')
                Address   = [string] (($data | Where-Object { $_.Name -eq 'DestinationIp' }).'#text')
                Written   = $_.TimeCreated
            }
        })
}

function Restart-Guard {
    Restart-GuardService $DataDir
}

# --- end of functions (the dry run puts its stand-ins here) ---

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $AllowNonAdmin) {
    throw 'Run this script in a PowerShell started as administrator.'
}
if (-not (Test-Path -LiteralPath $client -PathType Leaf)) {
    throw "Simulator not found: '$client'. Publish it with: dotnet publish src\RCEGuard.FakeWow -c Release -o $TestDir"
}
if ($Install) {
    Write-Host "Installing RCEGuard for '$client' ..." -ForegroundColor Cyan
    Install-ForTest
}
if (-not (Test-Path -LiteralPath $guardLog)) {
    throw "The log of the service was not found: '$guardLog'. Install RCEGuard for the test client first: .\scripts\install.ps1 -ClientPath '$client'"
}
if ($Count -lt 1 -or $Addresses.Count -lt 1) { throw '-Count and -Addresses need at least one.' }
foreach ($address in $Addresses) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($address, [ref] $parsed) -or $parsed.AddressFamily -ne 'InterNetwork') {
        throw "'$address' is not an IPv4 address."
    }
}

$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$resultFile = Join-Path $OutDir 'sensor-probe-result.txt'
Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue

function Wait-Until([scriptblock] $condition, [int] $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        if (& $condition) { return $true }
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 250
    }
}

$kinds = @(
    [pscustomobject]@{ Name = 'closed at once'; Arguments = @() }
    [pscustomobject]@{ Name = 'kept open'; Arguments = @('--keep-open') }
)
$rows = @()
$stopped = $null
$configChanged = $false
$guardLines = 0
$probeStart = Get-Date
try {
    Write-Host "Learning mode on for the test client, so that the connections raise no alert ..." -ForegroundColor Cyan
    if (Test-Path -LiteralPath $configPath) { Move-Item -LiteralPath $configPath -Destination $configBackup -Force }
    if (Test-Path -LiteralPath $learnedPath) { Move-Item -LiteralPath $learnedPath -Destination $learnedBackup -Force }
    $configChanged = $true
    $config = [ordered]@{
        cpuAlertCores = 0
        profiles      = @([ordered]@{ name = $profileName; clientPath = $client; learning = $true })
    }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Restart-Guard
    $logStart = Get-FileLength $guardLog
    $probeStart = Get-Date

    $total = $Count * $kinds.Count
    Write-Host "$total connections, each client alive for $HoldSeconds s: about $([int] ($total * ($HoldSeconds + 3) / 60 + 1)) min ..." -ForegroundColor Cyan
    for ($i = 0; $i -lt $Count; $i++) {
        foreach ($kind in $kinds) {
            $address = $Addresses[($rows.Count) % $Addresses.Count]
            $started = Get-Date
            $result = Invoke-Client (@('--connect', "${address}:$Port") + $kind.Arguments + @('--hold', "$HoldSeconds"))
            $connected = $result.Output -match 'Connected;'
            $clientPid = $result.ProcessId
            $record = $null
            if ($connected) {
                # Sysmon writes a connection one to three seconds after it was made; the client lived longer than that.
                $null = Wait-Until { @(Get-SensorConnections $started.AddSeconds(-2) | Where-Object { $_.ProcessId -eq $clientPid }).Count -gt 0 } 4
                $record = @(Get-SensorConnections $started.AddSeconds(-2) | Where-Object { $_.ProcessId -eq $clientPid }) | Select-Object -First 1
            }
            $open = if ($result.Output -match 'still open after') { 'still open at the end' } elseif ($result.Output -match 'closed by the other side') { 'closed by the other side' } else { '' }
            $row = [pscustomobject]@{
                Time     = $started.ToString('HH:mm:ss')
                Kind     = $kind.Name
                Address  = "${address}:$Port"
                Pid      = $clientPid
                Client   = $(if ($connected) { "connected$(if ($open) { ", $open" })" } else { 'NOT connected' })
                Sysmon   = $(if (-not $connected) { '-' } elseif ($null -ne $record) { "recorded after $(($record.Written - $started).TotalSeconds.ToString('0.0', [Globalization.CultureInfo]::InvariantCulture)) s" } else { 'NOT recorded' })
                Guard    = ''
                Recorded = ($null -ne $record)
                InTable  = $false
                Counted  = $connected
            }
            $rows += $row
            Write-Host ("  {0}  {1,-14} {2,-16} {3}" -f $row.Time, $row.Kind, $row.Address, $row.Sysmon)
        }
    }

    # What the guard made of them: one "learning mode" line per connection it was given, and one line
    # with the pid for every connection it found in the connection table because Sysmon had not recorded it.
    Start-Sleep -Seconds 3
    $logLines = @((Read-TextFrom $guardLog $logStart) -split "`r?`n")
    $guardLines = @($logLines | Where-Object { $_ -match "R2 INFO \[$profileName\] Learning mode: the game client connected to " }).Count
    foreach ($row in $rows) {
        $row.InTable = @($logLines | Where-Object { $_ -match "\(pid $($row.Pid)\) to .* found in the connection table of Windows" }).Count -gt 0
        $row.Guard = if (-not $row.Counted) { '-' }
            elseif ($row.Recorded -and $row.InTable) { 'seen (Sysmon and connection table)' }
            elseif ($row.Recorded) { 'seen (Sysmon)' }
            elseif ($row.InTable) { 'seen (connection table)' }
            else { 'NOT seen' }
    }
}
catch {
    $stopped = [string] $_.Exception.Message
    Write-Host "The measurement stopped: $stopped" -ForegroundColor DarkYellow
}
finally {
    if ($configChanged) {
        Write-Host 'Putting the configuration back ...' -ForegroundColor Cyan
        try {
            Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $configBackup) { Move-Item -LiteralPath $configBackup -Destination $configPath -Force }
            Remove-Item -LiteralPath $learnedPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $learnedBackup) { Move-Item -LiteralPath $learnedBackup -Destination $learnedPath -Force }
            Restart-Guard
        }
        catch {
            $problem = "The configuration could not be put back: $($_.Exception.Message)"
            Write-Host $problem -ForegroundColor Red
            if (-not $stopped) { $stopped = $problem }
        }
    }
}

$report = @(
    "RCEGuard sensor probe, $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Client: $client    Port: $Port    Each client alive for $HoldSeconds s"
    ''
)
if ($rows.Count -gt 0) {
    $report += ($rows | Format-Table Time, Kind, Address, Pid, Client, Sysmon, Guard -AutoSize | Out-String -Width 220).Trim()
    $report += ''
    foreach ($kind in $kinds) {
        $of = @($rows | Where-Object { $_.Kind -eq $kind.Name -and $_.Counted })
        $recorded = @($of | Where-Object { $_.Recorded })
        $seen = @($of | Where-Object { $_.Recorded -or $_.InTable })
        $onlyTable = @($of | Where-Object { $_.InTable -and -not $_.Recorded })
        $report += ('{0,-15} Sysmon recorded {1} of {2}; the guard saw {3} of {2} ({4} only through the connection table)' -f ($kind.Name + ':'), $recorded.Count, $of.Count, $seen.Count, $onlyTable.Count)
    }
    # One line per connection from Sysmon, one per connection taken from the table.
    $expected = @($rows | Where-Object { $_.Recorded }).Count + @($rows | Where-Object { $_.InTable }).Count
    if (-not $stopped) {
        $report += ''
        $report += "The guard reported $guardLines connection(s); from what Sysmon recorded and what the guard took from the table, $expected were to be expected.$(if ($guardLines -ne $expected) { ' THESE DIFFER.' })"
    }
    $notConnected = @($rows | Where-Object { -not $_.Counted }).Count
    if ($notConnected -gt 0) { $report += "$notConnected time(s) the client did not get a connection; those are not counted." }
    if (-not $stopped -and $notConnected -eq $rows.Count) {
        $stopped = "The client did not get a single connection, so nothing was measured. The measurement needs an internet connection; other addresses can be given with -Addresses."
    }
}
if ($stopped) {
    $report += ''
    $report += "STOPPED: $stopped"
}
[IO.File]::WriteAllLines($resultFile, [string[]] $report, [Text.UTF8Encoding]::new($false))
Write-Host ''
$report | ForEach-Object { Write-Host $_ }
Write-Host "Result saved to '$resultFile'."
if ($stopped) { exit 1 }
