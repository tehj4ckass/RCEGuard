<#
.SYNOPSIS
    Runs the simulator scenarios against the running guard and reports what was detected and terminated.

.DESCRIPTION
    Acceptance check for milestone M2 (concept, section 11): every simulator scenario is detected
    within 2 s and the critical ones are terminated.

    The script
      1. makes sure the sensor is installed for the test client (calls install.ps1 if needed),
      2. starts RCEGuard.Service in the background, logging to <OutDir>\m2-service.log,
      3. runs each scenario with --hold, so the client is still alive when the guard reacts,
      4. stops the service and writes <OutDir>\m2-result.txt.

    Needs an administrator PowerShell (Sysmon log, install). Build first with .\build.ps1 and
    publish the simulator to the test folder (see README).

.PARAMETER TestDir
    Folder with the simulator (Wow.exe).

.PARAMETER OutDir
    Folder for the service log and the result; created if missing.

.PARAMETER ServiceExe
    Service binary to test; default is the Release build in this repository.

.PARAMETER HoldSeconds
    How long each scenario keeps the client alive for the guard.

.PARAMETER DownloadSysmon
    Passed to install.ps1 if the sensor has to be installed.

.PARAMETER AcceptSysmonEula
    Passed to install.ps1 if the sensor has to be installed.

.PARAMETER SkipSensor
    Do not check or install the sensor (it is known to be active for the test client).

.PARAMETER AllowNonAdmin
    Skip the administrator check. Only useful for trying the script itself with a stand-in service.

.EXAMPLE
    .\scripts\acceptance-test.ps1 -DownloadSysmon -AcceptSysmonEula
#>
[CmdletBinding()]
param(
    [string] $TestDir = 'C:\RCEGuardTest',
    [string] $OutDir = (Join-Path $PSScriptRoot '..\out'),
    [string] $ServiceExe = (Join-Path $PSScriptRoot '..\src\RCEGuard.Service\bin\Release\net8.0-windows\RCEGuard.Service.exe'),
    [int] $HoldSeconds = 8,
    [switch] $DownloadSysmon,
    [switch] $AcceptSysmonEula,
    [switch] $SkipSensor,
    [switch] $AllowNonAdmin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $AllowNonAdmin) {
    throw 'Run this script in a PowerShell started as administrator.'
}

$client = Join-Path $TestDir 'Wow.exe'
if (-not (Test-Path -LiteralPath $client -PathType Leaf)) {
    throw "Simulator not found: '$client'. Publish it with: dotnet publish src\RCEGuard.FakeWow -c Release -o $TestDir"
}
if (-not (Test-Path -LiteralPath $ServiceExe -PathType Leaf)) {
    throw "Service not found: '$ServiceExe'. Build it with .\build.ps1"
}
$ServiceExe = (Resolve-Path -LiteralPath $ServiceExe).Path

$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$serviceLog = Join-Path $OutDir 'm2-service.log'
$resultFile = Join-Path $OutDir 'm2-result.txt'
$scenarioOut = Join-Path $OutDir 'm2-scenario.out'

# Scenario, expected rules, and whether the guard must terminate the client.
$scenarios = @(
    [pscustomobject]@{ Name = 'spawn';      Arguments = @('--spawn');                  Rules = @('R1');       MustDie = $true }
    [pscustomobject]@{ Name = 'miner-args'; Arguments = @('--miner-args');             Rules = @('R1', 'R9'); MustDie = $true }
    [pscustomobject]@{ Name = 'runkey';     Arguments = @('--runkey');                 Rules = @('R4');       MustDie = $true }
    [pscustomobject]@{ Name = 'connect';    Arguments = @('--connect', '1.1.1.1:443'); Rules = @('R2');       MustDie = $false }
    [pscustomobject]@{ Name = 'drop';       Arguments = @('--drop');                   Rules = @('R3');       MustDie = $false }
)

function Read-SharedLines([string] $path) {
    # The service still has the file open for writing.
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $reader = New-Object IO.StreamReader $stream
        $text = $reader.ReadToEnd()
    }
    finally { $stream.Dispose() }
    return @($text -split "`r?`n" | Where-Object { $_ })
}

function Get-FoundRules([string[]] $lines) {
    # Finding lines look like: "... R1 CRITICAL [Profile] summary | action: Kill -> ... | 123 ms after the event"
    foreach ($line in $lines) {
        if ($line -match '\b(R\d+) (CRITICAL|HIGH|MEDIUM|INFO) \[.*\| (\d+) ms after the event') {
            [pscustomobject]@{ Rule = $Matches[1]; DelayMs = [int] $Matches[3]; Line = $line }
        }
    }
}

# --- 1. Sensor ---------------------------------------------------------------------------------
if (-not $SkipSensor) {
    $statePath = Join-Path $env:ProgramData 'RCEGuard\install-state.json'
    $sensorReady = $false
    if (Test-Path -LiteralPath $statePath) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $serviceThere = $null -ne (Get-Service -Name $state.sysmonServiceName -ErrorAction SilentlyContinue)
        $sensorReady = $serviceThere -and [string]::Equals($state.clientPath, $client, [StringComparison]::OrdinalIgnoreCase)
    }
    if (-not $sensorReady) {
        Write-Host "Installing the sensor for '$client' ..."
        & (Join-Path $PSScriptRoot 'install.ps1') -ClientPath $client -DownloadSysmon:$DownloadSysmon -AcceptSysmonEula:$AcceptSysmonEula
    }
}

# --- 2. Service --------------------------------------------------------------------------------
Remove-Item -LiteralPath $serviceLog, $resultFile -Force -ErrorAction SilentlyContinue
$service = Start-Process -FilePath $ServiceExe -RedirectStandardOutput $serviceLog -PassThru -WindowStyle Hidden
$null = $service.Handle
$results = @()
try {
    $deadline = (Get-Date).AddSeconds(20)
    while ($true) {
        if ($service.HasExited) {
            throw "The service stopped right away (exit code $($service.ExitCode)):`n$((Read-SharedLines $serviceLog) -join "`n")"
        }
        if (@(Read-SharedLines $serviceLog) -match 'Subscribed to') { break }
        if ((Get-Date) -gt $deadline) { throw "The service did not subscribe to the Sysmon log within 20 s. See '$serviceLog'." }
        Start-Sleep -Milliseconds 200
    }
    Write-Host 'Service is watching. Running the scenarios ...'

    # --- 3. Scenarios --------------------------------------------------------------------------
    foreach ($scenario in $scenarios) {
        # @(...) everywhere: under strict mode a single line or an empty result has no Count and no members.
        $linesBefore = @(Read-SharedLines $serviceLog).Count
        $arguments = @($scenario.Arguments) + @('--hold', "$HoldSeconds")
        $process = Start-Process -FilePath $client -ArgumentList $arguments -RedirectStandardOutput $scenarioOut -PassThru -WindowStyle Hidden
        $null = $process.Handle
        if (-not $process.WaitForExit(($HoldSeconds + 30) * 1000)) {
            $process.Kill()
            throw "Scenario '$($scenario.Name)' did not end."
        }
        $output = (Get-Content -LiteralPath $scenarioOut -Raw -ErrorAction SilentlyContinue)
        $outcome =
            if ($output -match 'NOT TERMINATED') { 'survived' }
            elseif ($output -match 'was stopped:') { 'scenario failed' }
            elseif ($process.ExitCode -ne 0) { 'terminated' }
            else { 'ended by itself' }

        # The service logs asynchronously: give the findings a moment to arrive.
        $found = @()
        $foundRules = @()
        $missing = @($scenario.Rules)
        $settle = (Get-Date).AddSeconds(4)
        do {
            Start-Sleep -Milliseconds 250
            $newLines = @(Read-SharedLines $serviceLog | Select-Object -Skip $linesBefore)
            $found = @(Get-FoundRules $newLines)
            $foundRules = @($found | ForEach-Object { $_.Rule } | Select-Object -Unique)
            $missing = @($scenario.Rules | Where-Object { $_ -notin $foundRules })
        } while ($missing.Count -gt 0 -and (Get-Date) -lt $settle)

        $relevant = @($found | Where-Object { $_.Rule -in $scenario.Rules })
        $maxDelay = if ($relevant.Count -gt 0) { [int] ($relevant | Measure-Object DelayMs -Maximum).Maximum } else { $null }
        $detected = $missing.Count -eq 0
        $inTime = $detected -and $maxDelay -lt 2000
        $killOk = if ($scenario.MustDie) { $outcome -eq 'terminated' } else { $outcome -eq 'survived' }
        $results += [pscustomobject]@{
            Scenario = $scenario.Name
            Expected = ($scenario.Rules -join '+') + $(if ($scenario.MustDie) { ', terminated' } else { ', alert only' })
            Found    = ($foundRules -join '+')
            DelayMs  = $maxDelay
            Client   = $outcome
            Result   = if ($detected -and $inTime -and $killOk) { 'PASS' } else { 'FAIL' }
        }
    }
}
finally {
    # --- 4. Clean up ---------------------------------------------------------------------------
    if (-not $service.HasExited) {
        & taskkill.exe /PID $service.Id /T /F 2>&1 | Out-Null
        $null = $service.WaitForExit(5000)
    }
    Remove-Item -LiteralPath $scenarioOut -Force -ErrorAction SilentlyContinue

    # If the guard terminated the client in the middle of --runkey or --drop, the test artefacts are still there.
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if ($null -ne (Get-ItemProperty -Path $runKey -Name 'RCEGuardTest' -ErrorAction SilentlyContinue)) {
        Remove-ItemProperty -Path $runKey -Name 'RCEGuardTest' -Force
        Write-Host 'Removed the test autostart value the terminated simulator left behind.'
    }
    Remove-Item -LiteralPath (Join-Path $env:APPDATA 'rceguard-test.exe') -Force -ErrorAction SilentlyContinue
}

$failed = @($results | Where-Object Result -eq 'FAIL').Count
$verdict = if ($results.Count -eq $scenarios.Count -and $failed -eq 0) { 'ALL PASSED' } else { "$failed of $($scenarios.Count) FAILED" }
$report = @(
    "RCEGuard acceptance test (M2), $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Client: $client    Service: $ServiceExe"
    ($results | Format-Table -AutoSize | Out-String).TrimEnd()
    ''
    "Verdict: $verdict"
    "Service log: $serviceLog"
)
[IO.File]::WriteAllLines($resultFile, $report, [Text.UTF8Encoding]::new($false))
$report | ForEach-Object { Write-Host $_ }
Write-Host "Result saved to '$resultFile'."
if ($verdict -ne 'ALL PASSED') { exit 1 }
