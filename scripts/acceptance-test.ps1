<#
.SYNOPSIS
    Runs the simulator scenarios against the running guard and reports what was detected and terminated.

.DESCRIPTION
    Acceptance check for milestone M2 (concept, section 11): every simulator scenario is detected
    within 2 s and the critical ones are terminated.

    Two modes:

    Default (console): the script starts RCEGuard.Service from the build output in the background
    and stops it at the end. Nothing stays installed except the sensor.

    -InstalledService: the script installs RCEGuard completely with install.ps1 (sensor and Windows
    service; publish the service first with '.\build.ps1 -Publish'), runs the scenarios against
    the installed service and also checks how the service is registered and that Windows restarts
    it after its process was ended. The service stays installed and running for the test client.

    In both modes the script
      1. makes sure the sensor is installed for the test client (calls install.ps1 if needed),
      2. runs each scenario with --hold, so the client is still alive when the guard reacts,
      3. saves the recorded events to <OutDir>\m2-events.xml,
      4. writes <OutDir>\m2-result.txt.

    Needs an administrator PowerShell (Sysmon log, install). Build first with .\build.ps1 and
    publish the simulator to the test folder (see README).

    The simulator is a console program and is started hidden, so Windows attaches a console host
    (conhost.exe) to it as a child process. The guard logs that as R1 without terminating anything;
    the test leaves that line out of its "Found" column.

.PARAMETER TestDir
    Folder with the simulator (Wow.exe).

.PARAMETER OutDir
    Folder for the service log and the result; created if missing.

.PARAMETER ServiceExe
    Console mode: service binary to test; default is the Release build in this repository.

.PARAMETER InstalledService
    Test the installed Windows service instead of a console instance (see description).

.PARAMETER GuardLog
    -InstalledService: log file of the service; default C:\ProgramData\RCEGuard\guard.log.

.PARAMETER HoldSeconds
    How long each scenario keeps the client alive for the guard.

.PARAMETER DownloadSysmon
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER AcceptSysmonEula
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER SkipSensor
    Do not install anything: the sensor (and with -InstalledService the service) is known to be
    active for the test client.

.PARAMETER AllowNonAdmin
    Skip the administrator check. Only useful for trying the script itself with a stand-in guard.

.EXAMPLE
    .\scripts\acceptance-test.ps1 -DownloadSysmon -AcceptSysmonEula

.EXAMPLE
    .\scripts\acceptance-test.ps1 -InstalledService
#>
[CmdletBinding()]
param(
    [string] $TestDir = 'C:\RCEGuardTest',
    [string] $OutDir,
    [string] $ServiceExe,
    [switch] $InstalledService,
    [string] $GuardLog = (Join-Path $env:ProgramData 'RCEGuard\guard.log'),
    [int] $HoldSeconds = 8,
    [switch] $DownloadSysmon,
    [switch] $AcceptSysmonEula,
    [switch] $SkipSensor,
    [switch] $AllowNonAdmin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Defaults that need the script folder are set here: under 'powershell.exe -File' (Windows
# PowerShell 5.1) $PSScriptRoot is still empty while the param block is evaluated.
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot '..\out' }
if (-not $ServiceExe) { $ServiceExe = Join-Path $PSScriptRoot '..\src\RCEGuard.Service\bin\Release\net8.0-windows\RCEGuard.Service.exe' }

. (Join-Path $PSScriptRoot 'GuardServiceTools.ps1')

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $AllowNonAdmin) {
    throw 'Run this script in a PowerShell started as administrator.'
}

$client = Join-Path $TestDir 'Wow.exe'
if (-not (Test-Path -LiteralPath $client -PathType Leaf)) {
    throw "Simulator not found: '$client'. Publish it with: dotnet publish src\RCEGuard.FakeWow -c Release -o $TestDir"
}
if (-not $InstalledService) {
    if (-not (Test-Path -LiteralPath $ServiceExe -PathType Leaf)) {
        throw "Service not found: '$ServiceExe'. Build it with .\build.ps1"
    }
    $ServiceExe = (Resolve-Path -LiteralPath $ServiceExe).Path
}

$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$resultFile = Join-Path $OutDir 'm2-result.txt'
$scenarioOut = Join-Path $OutDir 'm2-scenario.out'
$eventsFile = Join-Path $OutDir 'm2-events.xml'
# The log the findings are read from: the installed service's own log, or the console output of the instance started here.
$serviceLog = if ($InstalledService) { $GuardLog } else { Join-Path $OutDir 'm2-service.log' }

# Scenario, expected rules, whether the guard must terminate the client, and whether the scenario
# raises the same alert several times in one client, which the guard must report only once.
$scenarios = @(
    [pscustomobject]@{ Name = 'spawn';      Arguments = @('--spawn');                                 Rules = @('R1');       MustDie = $true;  Once = $false }
    [pscustomobject]@{ Name = 'miner-args'; Arguments = @('--miner-args');                            Rules = @('R1', 'R9'); MustDie = $true;  Once = $false }
    [pscustomobject]@{ Name = 'detach';     Arguments = @('--detach');                                Rules = @('R1');       MustDie = $true;  Once = $false }
    [pscustomobject]@{ Name = 'runkey';     Arguments = @('--runkey');                                Rules = @('R4');       MustDie = $true;  Once = $false }
    [pscustomobject]@{ Name = 'connect';    Arguments = @('--connect', '1.1.1.1:443');                Rules = @('R2');       MustDie = $false; Once = $false }
    [pscustomobject]@{ Name = 'drop';       Arguments = @('--drop');                                  Rules = @('R3');       MustDie = $false; Once = $false }
    [pscustomobject]@{ Name = 'repeat';     Arguments = @('--connect', '1.1.1.1:443', '--repeat', '3'); Rules = @('R2');     MustDie = $false; Once = $true }
)

# The program the --detach scenario leaves behind carries this text on its command line.
$detachMarker = 'rceguard-detached-test'
function Get-LeftBehind {
    @(Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%$detachMarker%'" |
        Where-Object { $_.ProcessId -ne $PID })
}

function Read-LogLines([long] $offset = 0) {
    # The guard still has the file open for writing.
    return @((Read-TextFrom $serviceLog $offset) -split "`r?`n" | Where-Object { $_ })
}

function Get-FoundRules([string[]] $lines) {
    # Finding lines look like: "... R1 CRITICAL [Profile] summary | action: Kill -> ... | 123 ms after the event"
    foreach ($line in $lines) {
        # Not a finding about the scenario: Windows attaches a console host to the hidden simulator.
        if ($line -match 'Windows attached a console to the game client') { continue }
        if ($line -match '\b(R\d+) (CRITICAL|HIGH|MEDIUM|INFO) \[.*\| (\d+) ms after the event') {
            [pscustomobject]@{ Rule = $Matches[1]; DelayMs = [int] $Matches[3]; Line = $line }
        }
    }
}

# --- 1. Sensor and guard -----------------------------------------------------------------------
$installScript = Join-Path $PSScriptRoot 'install.ps1'
$service = $null
if ($InstalledService) {
    if (-not $SkipSensor) {
        Write-Host "Installing RCEGuard (sensor and service) for '$client' ..."
        & $installScript -ClientPath $client -DownloadSysmon:$DownloadSysmon -AcceptSysmonEula:$AcceptSysmonEula
    }
    if (-not (Test-Path -LiteralPath $serviceLog)) {
        throw "The log of the service was not found: '$serviceLog'."
    }
}
else {
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
            & $installScript -ClientPath $client -SkipService -DownloadSysmon:$DownloadSysmon -AcceptSysmonEula:$AcceptSysmonEula
        }
    }

    # Two guards would both act on every event.
    $installedGuard = Get-Service -Name $script:GuardServiceName -ErrorAction SilentlyContinue
    if ($null -ne $installedGuard -and $installedGuard.Status -ne 'Stopped') {
        throw "The Windows service '$script:GuardServiceName' is running. Test it with -InstalledService, or stop it first."
    }

    Remove-Item -LiteralPath $serviceLog -Force -ErrorAction SilentlyContinue
    $service = Start-Process -FilePath $ServiceExe -RedirectStandardOutput $serviceLog -PassThru -WindowStyle Hidden
    $null = $service.Handle
}

Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue
$results = @()
$checks = @()
try {
    if ($null -ne $service) {
        $deadline = (Get-Date).AddSeconds(20)
        while ($true) {
            if ($service.HasExited) {
                throw "The service stopped right away (exit code $($service.ExitCode)):`n$((Read-LogLines) -join "`n")"
            }
            if (@(Read-LogLines) -match 'Subscribed to') { break }
            if ((Get-Date) -gt $deadline) { throw "The service did not subscribe to the Sysmon log within 20 s. See '$serviceLog'." }
            Start-Sleep -Milliseconds 200
        }
    }
    Write-Host 'The guard is watching. Running the scenarios ...'

    # --- 2. Scenarios --------------------------------------------------------------------------
    foreach ($scenario in $scenarios) {
        # @(...) everywhere: under strict mode a single line or an empty result has no Count and no members.
        $offset = Get-FileLength $serviceLog
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

        # The guard logs asynchronously: give the findings a moment to arrive.
        $found = @()
        $foundRules = @()
        $missing = @($scenario.Rules)
        $settle = (Get-Date).AddSeconds(4)
        do {
            Start-Sleep -Milliseconds 250
            $found = @(Get-FoundRules (Read-LogLines $offset))
            $foundRules = @($found | ForEach-Object { $_.Rule } | Select-Object -Unique)
            $missing = @($scenario.Rules | Where-Object { $_ -notin $foundRules })
        } while ($missing.Count -gt 0 -and (Get-Date) -lt $settle)

        # --detach: the child has exited by the time the guard reacts; what it started must be gone as well.
        $leftBehind = @(Get-LeftBehind)
        if ($leftBehind.Count -gt 0) {
            $outcome += ', left a program running'
            foreach ($survivor in $leftBehind) { & taskkill.exe /PID $survivor.ProcessId /T /F 2>&1 | Out-Null }
        }

        $relevant = @($found | Where-Object { $_.Rule -in $scenario.Rules })
        $maxDelay = if ($relevant.Count -gt 0) { [int] ($relevant | Measure-Object DelayMs -Maximum).Maximum } else { $null }
        $detected = $missing.Count -eq 0
        $inTime = $detected -and $maxDelay -lt 2000
        $killOk = if ($scenario.MustDie) { $outcome -eq 'terminated' } else { $outcome -eq 'survived' }
        # The client has ended, so every repetition is long past the guard: more than one report means it did not count them.
        $onceOk = -not $scenario.Once -or $relevant.Count -eq 1
        $results += [pscustomobject]@{
            Scenario = $scenario.Name
            Expected = ($scenario.Rules -join '+') + $(if ($scenario.MustDie) { ', terminated' } else { ', alert only' }) + $(if ($scenario.Once) { ', reported once' } else { '' })
            Found    = ($foundRules -join '+') + $(if ($scenario.Once -and $relevant.Count -ne 1) { " ($($relevant.Count) reports)" } else { '' })
            DelayMs  = $maxDelay
            Client   = $outcome
            Result   = if ($detected -and $inTime -and $killOk -and $onceOk) { 'PASS' } else { 'FAIL' }
        }
    }

    # --- 3. The installed service itself --------------------------------------------------------
    if ($InstalledService) {
        $registered = Get-GuardService
        if (-not $isAdmin) {
            # Trying the script with a stand-in guard: the checks below would be about the real service.
            $checks += [pscustomobject]@{ Check = 'service checks'; Value = 'not run without administrator rights'; Result = 'SKIP' }
        }
        elseif ($null -eq $registered) {
            $checks += [pscustomobject]@{ Check = 'service is registered'; Value = 'no such service'; Result = 'FAIL' }
        }
        else {
            $binary = Get-GuardServiceBinary $registered
            $checks += [pscustomobject]@{ Check = 'runs from Program Files'; Value = $binary; Result = $(if (Test-GuardServiceIsOurs $registered) { 'PASS' } else { 'FAIL' }) }
            $checks += [pscustomobject]@{ Check = 'binary path is quoted'; Value = $registered.PathName; Result = $(if ($registered.PathName.StartsWith('"')) { 'PASS' } else { 'FAIL' }) }
            $checks += [pscustomobject]@{ Check = 'account'; Value = $registered.StartName; Result = $(if ($registered.StartName -eq 'LocalSystem') { 'PASS' } else { 'FAIL' }) }
            $checks += [pscustomobject]@{ Check = 'starts with Windows'; Value = $registered.StartMode; Result = $(if ($registered.StartMode -eq 'Auto') { 'PASS' } else { 'FAIL' }) }
            $dependsOn = @(Get-Service -Name $script:GuardServiceName | ForEach-Object { $_.ServicesDependedOn } | ForEach-Object { $_.Name }) -join ','
            $checks += [pscustomobject]@{ Check = 'depends on Sysmon'; Value = $dependsOn; Result = $(if ($dependsOn -match '^Sysmon') { 'PASS' } else { 'FAIL' }) }

            # Windows must restart the service when its process dies (recovery actions). It does so after
            # 5 s the first two times within a day and after 60 s from the third time on, and this test
            # counts: on a day with several runs the restart takes a minute.
            $oldPid = [int] $registered.ProcessId
            $offset = Get-FileLength $serviceLog
            Write-Host "Ending the service process ($oldPid) to see whether Windows restarts it ..."
            Stop-Process -Id $oldPid -Force

            # While the service is down the client starts a program. The restarted service must find
            # that in the Sysmon log and act on it, although it was not running when it happened.
            $missedOut = Join-Path $OutDir 'm2-missed.out'
            $missed = Start-Process -FilePath $client -ArgumentList @('--spawn', '--hold', '100') -RedirectStandardOutput $missedOut -PassThru -WindowStyle Hidden
            $null = $missed.Handle

            $ended = Get-Date
            $deadline = $ended.AddSeconds(90)
            $restarted = $false
            do {
                Start-Sleep -Milliseconds 500
                $now = Get-GuardService
                $restarted = $null -ne $now -and $now.State -eq 'Running' -and [int] $now.ProcessId -notin @(0, $oldPid) -and ((Read-TextFrom $serviceLog $offset) -match 'Subscribed to')
            } while (-not $restarted -and (Get-Date) -lt $deadline)
            $newPid = if ($null -ne $now) { [int] $now.ProcessId } else { 0 }
            $downSeconds = [int] ((Get-Date) - $ended).TotalSeconds
            $checks += [pscustomobject]@{ Check = 'restarted after its process was ended'; Value = "pid $oldPid -> $newPid after $downSeconds s"; Result = $(if ($restarted) { 'PASS' } else { 'FAIL' }) }

            $missedEnded = $missed.WaitForExit(45000)
            if (-not $missedEnded) { & taskkill.exe /PID $missed.Id /T /F 2>&1 | Out-Null }
            $missedOutput = Get-Content -LiteralPath $missedOut -Raw -ErrorAction SilentlyContinue
            $missedOutcome =
                if (-not $missedEnded) { 'did not end' }
                elseif ($missedOutput -match 'NOT TERMINATED') { 'survived' }
                elseif ($missed.ExitCode -ne 0) { 'terminated' }
                else { 'ended by itself' }
            $lateFindings = @()
            $settle = (Get-Date).AddSeconds(4)
            do {
                Start-Sleep -Milliseconds 250
                $lateFindings = @(Read-LogLines $offset | Where-Object { $_ -match '\bR1 CRITICAL \[' -and $_ -match 'written while RCEGuard was not running' })
            } while ($lateFindings.Count -eq 0 -and (Get-Date) -lt $settle)
            $lateFound = if ($lateFindings.Count -gt 0) { 'R1 found afterwards' } else { 'R1 not found' }
            $checks += [pscustomobject]@{
                Check  = 'acted on a program started while it was down'
                Value  = "$lateFound, client $missedOutcome"
                Result = $(if ($lateFindings.Count -gt 0 -and $missedOutcome -eq 'terminated') { 'PASS' } else { 'FAIL' })
            }
            Remove-Item -LiteralPath $missedOut -Force -ErrorAction SilentlyContinue
        }
    }

    # Keep the raw events of this run: material for test fixtures and for looking into a failure.
    # They contain user and machine names, so they stay in the ignored out folder.
    if ($isAdmin) {
        try { & (Join-Path $PSScriptRoot 'show-events.ps1') -Last 800 -OutFile $eventsFile }
        catch { Write-Warning "Could not save the events of this run: $($_.Exception.Message)" }
    }
}
finally {
    # --- 4. Clean up ---------------------------------------------------------------------------
    if ($null -ne $service -and -not $service.HasExited) {
        & taskkill.exe /PID $service.Id /T /F 2>&1 | Out-Null
        $null = $service.WaitForExit(5000)
    }
    foreach ($survivor in @(Get-LeftBehind)) { & taskkill.exe /PID $survivor.ProcessId /T /F 2>&1 | Out-Null }
    Remove-Item -LiteralPath $scenarioOut -Force -ErrorAction SilentlyContinue

    # If the guard terminated the client in the middle of --runkey or --drop, the test artefacts are still there.
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if ($null -ne (Get-ItemProperty -Path $runKey -Name 'RCEGuardTest' -ErrorAction SilentlyContinue)) {
        Remove-ItemProperty -Path $runKey -Name 'RCEGuardTest' -Force
        Write-Host 'Removed the test autostart value the terminated simulator left behind.'
    }
    Remove-Item -LiteralPath (Join-Path $env:APPDATA 'rceguard-test.exe') -Force -ErrorAction SilentlyContinue
}

$failed = @($results | Where-Object Result -eq 'FAIL').Count + @($checks | Where-Object Result -eq 'FAIL').Count
$complete = $results.Count -eq $scenarios.Count -and (-not $InstalledService -or $checks.Count -gt 0)
$verdict = if ($complete -and $failed -eq 0) { 'ALL PASSED' } else { "$failed FAILED" }
$mode = if ($InstalledService) { 'installed Windows service' } else { "console instance $ServiceExe" }
$report = @(
    "RCEGuard acceptance test (M2), $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Client: $client    Guard: $mode"
    ($results | Format-Table -AutoSize | Out-String).TrimEnd()
)
if ($checks.Count -gt 0) {
    $report += ($checks | Format-Table -AutoSize -Wrap | Out-String).TrimEnd()
}
$report += @(
    ''
    "Verdict: $verdict"
    "Guard log: $serviceLog"
)
[IO.File]::WriteAllLines($resultFile, $report, [Text.UTF8Encoding]::new($false))
$report | ForEach-Object { Write-Host $_ }
Write-Host "Result saved to '$resultFile'."
if ($verdict -ne 'ALL PASSED') { exit 1 }
