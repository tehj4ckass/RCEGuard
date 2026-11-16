<#
.SYNOPSIS
    Checks milestone M5 on the installed service: learning mode with its suggestion, R7 (another
    program opened) and R8 (processor load).

.DESCRIPTION
    Runs against the installed Windows service and the simulator (the test client). The script

      1. installs RCEGuard for the test client with install.ps1 (unless -SkipInstall),
      2. gives the service a configuration with the test profile in learning mode and lets the
         simulator connect to a host name and to an address, start a program, open another
         program, create a file and keep the processor busy. Nothing may be terminated or locked
         down; unknown addresses may only be noted; the other rules must report as always,
      3. asks the service what it learned ('RCEGuard.Service.exe --learned') and checks the
         suggestion,
      4. takes the suggestion over as printed, turns learning mode off and checks that the guard
         judges again: what was learned is quiet, an unknown address alerts, opening a program
         with rights to change it alerts, and a started program is terminated,
      5. puts the configuration back as it was and saves the recorded Sysmon events.

    Sysmon does not record every connection (see docs\DETECTION.md, "Connections"). The script asks
    the Sysmon log after each connection whether it is in there and tries up to three times; what
    was not recorded is listed in the result, apart from the checks of the guard.

    Needs an administrator PowerShell and an internet connection. Publish first with
    '.\build.ps1 -Publish' and the simulator to the test folder (see README). Windows shows
    notifications of the tray application while the test runs. The result goes to
    <OutDir>\m5-result.txt, the events to <OutDir>\m5-events.xml.

.PARAMETER TestDir
    Folder with the simulator (Wow.exe).

.PARAMETER OutDir
    Folder for the result; created if missing.

.PARAMETER DataDir
    Data folder of the service.

.PARAMETER HostName
    A host name the test client connects to while learning. Must accept TCP connections on -Port.

.PARAMETER OtherAddress
    An IPv4 address the test client connects to while learning. Must accept TCP connections on
    -Port and must not be an address of -HostName.

.PARAMETER UnknownAddress
    An IPv4 address the test client only connects to after learning. Must accept TCP connections
    on -Port and must not be an address of -HostName.

.PARAMETER Port
    TCP port for all three.

.PARAMETER HoldSeconds
    How long the simulator stays alive after a connection or after starting a program. Sysmon
    often does not record the connection of a client that ends within a few seconds.

.PARAMETER CpuSeconds
    How long the simulator keeps the processor busy. R8 looks at 10 s in this test.

.PARAMETER DownloadSysmon
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER AcceptSysmonEula
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER SkipInstall
    Do not call install.ps1: the service is installed and running for the test client.

.PARAMETER AllowNonAdmin
    Skip the administrator check. Only useful for trying the script itself with stand-ins.

.EXAMPLE
    .\scripts\learning-test.ps1 -DownloadSysmon -AcceptSysmonEula
#>
[CmdletBinding()]
param(
    [string] $TestDir = 'C:\RCEGuardTest',
    [string] $OutDir,
    [string] $DataDir = (Join-Path $env:ProgramData 'RCEGuard'),
    [string] $HostName = 'one.one.one.one',
    [string] $OtherAddress = '9.9.9.9',
    [string] $UnknownAddress = '8.8.8.8',
    [int] $Port = 443,
    [int] $HoldSeconds = 8,
    [int] $CpuSeconds = 25,
    [switch] $DownloadSysmon,
    [switch] $AcceptSysmonEula,
    [switch] $SkipInstall,
    [switch] $AllowNonAdmin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Under 'powershell.exe -File' (Windows PowerShell 5.1) $PSScriptRoot is still empty while the param block is evaluated.
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot '..\out' }

. (Join-Path $PSScriptRoot 'GuardServiceTools.ps1')

$profileName = 'LearnTest'
$cpuCores = 1.5
$cpuWindow = 10
$client = Join-Path $TestDir 'Wow.exe'
$configPath = Join-Path $DataDir 'appsettings.json'
$configBackup = Join-Path $DataDir 'appsettings.json.before-learning-test'
$lockdownPath = Join-Path $DataDir 'lockdown.json'
$learnedPath = Join-Path $DataDir 'learned.json'
$learnedBackup = Join-Path $DataDir 'learned.json.before-learning-test'
$guardLog = Join-Path $DataDir $script:GuardLogName

function Install-ForTest {
    & (Join-Path $PSScriptRoot 'install.ps1') -ClientPath $client -DownloadSysmon:$DownloadSysmon -AcceptSysmonEula:$AcceptSysmonEula | Out-Host
}

function Invoke-Client([string[]] $arguments, [int] $timeoutSeconds = 0) {
    # Runs the simulator and returns its exit code and what it printed.
    if ($timeoutSeconds -le 0) { $timeoutSeconds = $HoldSeconds + 30 }
    $out = Join-Path $OutDir 'm5-client.out'
    $process = Start-Process -FilePath $client -ArgumentList $arguments -RedirectStandardOutput $out -PassThru -WindowStyle Hidden
    $null = $process.Handle
    if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
        $process.Kill()
        throw "The simulator did not end: $($arguments -join ' ')"
    }
    $text = [string] (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $text; ProcessId = $process.Id }
}

function Get-SensorConnections([datetime] $since) {
    # The pids of the processes whose connections Sysmon recorded since then (event 3).
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 3; StartTime = $since } -ErrorAction SilentlyContinue |
        ForEach-Object { [int] ((([xml] $_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }).'#text') })
}

function Get-SensorReloadTime {
    # When Sysmon last loaded its configuration (event 16); install.ps1 makes it do that.
    $record = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 16 } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -ne $record) { $record.TimeCreated } else { $null }
}

function Restart-Guard {
    Restart-GuardService $DataDir
}

function Invoke-Learned {
    # Asks the installed service what it learned for the test profile; returns exit code and output.
    $exe = Join-Path $script:GuardInstallDir $script:GuardExeName
    $ErrorActionPreference = 'Continue'   # 5.1 turns a line on stderr into an error under 'Stop'
    $lines = @(& $exe --learned $profileName --data-dir $DataDir 2>&1 | ForEach-Object { "$_" })
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($lines -join "`n") }
}

function Get-TestRuleCount {
    @(Get-GuardFirewallRules).Count
}

function Save-Events([string] $file) {
    # The Sysmon events of the run, as raw material for test fixtures.
    & (Join-Path $PSScriptRoot 'show-events.ps1') -Last 1500 -OutFile $file | Out-Null
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
foreach ($address in @($OtherAddress, $UnknownAddress)) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($address, [ref] $parsed) -or $parsed.AddressFamily -ne 'InterNetwork') {
        throw "'$address' is not an IPv4 address."
    }
}

$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$resultFile = Join-Path $OutDir 'm5-result.txt'
$eventsFile = Join-Path $OutDir 'm5-events.xml'
Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue

$checks = @()
function Add-Check([string] $step, [string] $check, [bool] $ok, [string] $value = '') {
    if ($value.Length -gt 110) { $value = $value.Substring(0, 107) + '...' }
    $script:checks += [pscustomobject]@{ Step = $step; Check = $check; Value = $value; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }) }
}

function Wait-Until([scriptblock] $condition, [int] $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        if (& $condition) { return $true }
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 250
    }
}

function Get-NewLines([long] $offset, [string] $pattern) {
    # The lines the service wrote to its log after $offset that match.
    @((Read-TextFrom $guardLog $offset) -split "`r?`n" | Where-Object { $_ -match $pattern })
}

function Wait-NewLines([long] $offset, [string] $pattern, [int] $seconds) {
    $null = Wait-Until { @(Get-NewLines $offset $pattern).Count -gt 0 } $seconds
    @(Get-NewLines $offset $pattern)
}

function Get-LockedProfiles {
    if (-not (Test-Path -LiteralPath $lockdownPath)) { return @() }
    $state = Get-Content -LiteralPath $lockdownPath -Raw | ConvertFrom-Json
    @($state.locked | ForEach-Object { [string] $_.profile })
}

$script:sensorNotes = @()
$script:sensorMissed = 0
$script:sensorTries = 0

function Connect-Client([string] $target) {
    <#
        Connects and stays alive, so that Sysmon has time to record the connection, and asks the
        Sysmon log whether it did. Up to three tries: what Sysmon does not record, the guard
        cannot judge, and that is noted apart from the checks of the guard.
    #>
    $said = ''
    $connected = $false
    $recorded = $false
    $tries = 0
    while ($tries -lt 3 -and -not $recorded) {
        $tries++
        $started = Get-Date
        $result = Invoke-Client @('--connect', "${target}:$Port", '--hold', "$HoldSeconds")
        $line = @($result.Output -split "`r?`n" | Where-Object { $_ -match 'Connected;|was stopped:' })
        $said = if ($line.Count -gt 0) { $line[0].Trim() } else { "exit code $($result.ExitCode), no message" }
        $connected = $result.Output -match 'Connected;'
        if (-not $connected) { break }   # no connection, nothing to record

        $clientPid = $result.ProcessId
        $recorded = Wait-Until { @(Get-SensorConnections $started.AddSeconds(-2)) -contains $clientPid } 4
        $script:sensorTries++
        if (-not $recorded) { $script:sensorMissed++ }
        $reload = Get-SensorReloadTime
        $after = if ($null -ne $reload) { "$([int] ($started - $reload).TotalSeconds) s after Sysmon loaded its configuration" } else { 'time of the last configuration load unknown' }
        $script:sensorNotes += "    $($started.ToString('HH:mm:ss')) ${target}:$Port (pid $clientPid, $after): $(if ($recorded) { 'recorded' } else { 'NOT recorded by Sysmon' })"
    }
    [pscustomobject]@{ Connected = $connected; Said = $said; Recorded = $recorded; Tries = $tries }
}

function Get-SuggestedList([string] $text, [string] $name) {
    # One of the lists of the suggestion, read the way a person would copy it; $null if it is not there.
    $match = [regex]::Match($text, '"' + [regex]::Escape($name) + '":\s*(\[[^\r\n]*\])')
    if (-not $match.Success) { return $null }
    # Into a variable first: Windows PowerShell 5.1 hands a JSON list down the pipeline as one object.
    $items = ConvertFrom-Json -InputObject $match.Groups[1].Value
    # The comma keeps an empty list a list.
    return , @($items | ForEach-Object { [string] $_ })
}

$tag = "\[$([regex]::Escape($profileName))\]"

# --- 1. Installed service ----------------------------------------------------------------------
if (-not $SkipInstall) {
    Write-Host "Installing RCEGuard (sensor, service and tray application) for '$client' ..."
    Install-ForTest
}
if (-not (Test-Path -LiteralPath $guardLog)) {
    throw "The log of the service was not found: '$guardLog'. Is RCEGuard installed?"
}

$stopped = $null
$configChanged = $false
$notes = @()
try {
    if (@(Get-LockedProfiles).Count -gt 0) {
        throw "A profile is in lockdown ($(@(Get-LockedProfiles) -join ', ')). Release it first: this test needs to start without one."
    }

    # --- 2. Learning ------------------------------------------------------------------------------
    Write-Host ''
    Write-Host '1. Learning mode on for the test client ...' -ForegroundColor Cyan
    if (Test-Path -LiteralPath $configPath) { Move-Item -LiteralPath $configPath -Destination $configBackup -Force }
    # Notes from an earlier session would be counted into this one.
    if (Test-Path -LiteralPath $learnedPath) { Move-Item -LiteralPath $learnedPath -Destination $learnedBackup -Force }
    $configChanged = $true
    $config = [ordered]@{
        lockdown        = $true
        cpuAlertCores   = $cpuCores
        cpuAlertSeconds = $cpuWindow
        # Lockdown and killOnUnknownRemote are on to show that learning holds both back.
        profiles        = @([ordered]@{ name = $profileName; clientPath = $client; learning = $true; killOnUnknownRemote = $true })
    }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    $learningStart = Get-FileLength $guardLog
    Restart-Guard
    $said = @(Wait-NewLines $learningStart "Learning mode is ON for '$profileName'" 5)
    Add-Check '1' 'the service says in its log that the profile is learning' ($said.Count -gt 0)

    Write-Host "   The client connects to ${HostName}:$Port and ${OtherAddress}:$Port ..."
    $viaName = Connect-Client $HostName
    $viaAddress = Connect-Client $OtherAddress
    Add-Check '1' 'the client reaches the host name and the address' ($viaName.Connected -and $viaAddress.Connected) "$($viaName.Said) / $($viaAddress.Said)"
    Add-Check '1' 'Sysmon recorded both connections (at most three tries each)' ($viaName.Recorded -and $viaAddress.Recorded) "name: $(if ($viaName.Recorded) { "try $($viaName.Tries)" } else { "not in $($viaName.Tries) tries" }); address: $(if ($viaAddress.Recorded) { "try $($viaAddress.Tries)" } else { "not in $($viaAddress.Tries) tries" })"
    $noted = @(Wait-NewLines $learningStart "R2 INFO $tag Learning mode: the game client connected to $([regex]::Escape($OtherAddress)):$Port" 10)
    $all = @(Get-NewLines $learningStart "R2 INFO $tag Learning mode: the game client connected to ")
    Add-Check '1' 'both connections are noted, not alerted (R2 info)' ($noted.Count -gt 0 -and $all.Count -ge 2) "$($all.Count) line(s)"
    $alerts = @(Get-NewLines $learningStart "R2 (CRITICAL|HIGH) $tag")
    Add-Check '1' 'no connection is an alert, and none terminates the client' ($alerts.Count -eq 0) "$($alerts.Count) R2 alert line(s)"

    Write-Host '   The client starts a program ...'
    $spawn = Invoke-Client @('--spawn', '--hold', "$HoldSeconds")
    $survived = $spawn.Output -match 'NOT TERMINATED'
    $r1 = @(Wait-NewLines $learningStart "R1 CRITICAL $tag .*not terminated \(learning mode\)" 8)
    Add-Check '1' 'the started program is reported, and nothing is terminated' ($survived -and $r1.Count -gt 0) "client $(if ($survived) { 'survived' } else { "did not survive (exit code $($spawn.ExitCode))" }); $($r1.Count) R1 line(s) with 'not terminated (learning mode)'"
    Add-Check '1' 'the profile is not locked down and no firewall rule is written' (@(Get-LockedProfiles).Count -eq 0 -and (Get-TestRuleCount) -eq 0) "in lockdown: $(@(Get-LockedProfiles).Count); rules: $(Get-TestRuleCount)"

    Write-Host '   The client opens another program (to read it, then with rights to change it) ...'
    $null = Invoke-Client @('--open-process', 'read')
    $null = Invoke-Client @('--open-process', 'write')
    # The guard holds an access for reading back for a few seconds: a burst of them (a scan) becomes one finding.
    $read = @(Wait-NewLines $learningStart "R7 MEDIUM $tag .*to read its memory \(0x1010[;)]" 20)
    $write = @(Wait-NewLines $learningStart "R7 HIGH $tag .*with rights to change it \(0x102a" 8)
    Add-Check '1' 'R7: reading is a log entry, rights to change it are an alert' ($read.Count -gt 0 -and $write.Count -gt 0) "$($read.Count) medium, $($write.Count) high"

    Write-Host '   The client creates a program file outside its folder ...'
    $null = Invoke-Client @('--drop')
    $r3 = @(Wait-NewLines $learningStart "R3 HIGH $tag" 8)
    Add-Check '1' 'the other rules alert as always (R3 for the file)' ($r3.Count -gt 0) "$($r3.Count) R3 line(s)"

    Write-Host "   The client keeps the processor busy for $CpuSeconds s (R8 looks at $cpuWindow s) ..."
    $null = Invoke-Client @('--cpu', "$CpuSeconds") ($CpuSeconds + 30)
    $r8 = @(Wait-NewLines $learningStart "R8 MEDIUM $tag The game client kept [\d.]+ processor cores busy" 5)
    $r8Value = if ($r8.Count -gt 0) { [regex]::Match($r8[0], 'kept [\d.]+ processor cores busy[^|]*').Value.Trim() } else { "no R8 line; this machine has $([Environment]::ProcessorCount) processor(s)" }
    Add-Check '1' 'R8: the processor load is reported' ($r8.Count -eq 1) $r8Value

    # --- 3. What was learned ------------------------------------------------------------------------
    Write-Host ''
    Write-Host "2. What the service learned ('--learned') ..." -ForegroundColor Cyan
    # The notes are saved a few seconds after the last one.
    $null = Wait-Until { (Invoke-Learned).Output -match 'Highest processor load: \d' } 15
    $learned = Invoke-Learned
    Write-Host $learned.Output
    Add-Check '2' 'the command succeeds and shows the profile as learning' ($learned.ExitCode -eq 0 -and $learned.Output -match "Profile '$profileName'" -and $learned.Output -match 'Learning mode is ON') "exit code $($learned.ExitCode)"
    $starts = [regex]::Match($learned.Output, 'Noted: (\d+) start\(s\)')
    Add-Check '2' 'it counted the starts of the client' ($starts.Success -and [int] $starts.Groups[1].Value -ge 7) $(if ($starts.Success) { "$($starts.Groups[1].Value) start(s)" } else { 'no count' })
    $hostnames = Get-SuggestedList $learned.Output 'allowedHostnames'
    $remotes = Get-SuggestedList $learned.Output 'allowedRemote'
    $programs = Get-SuggestedList $learned.Output 'allowedProcessAccess'
    $hasSuggestion = $null -ne $hostnames -and $null -ne $remotes -and $null -ne $programs
    Add-Check '2' 'it prints a suggestion with the three lists' $hasSuggestion
    if (-not $hasSuggestion) {
        throw 'There is no suggestion to take over, so the rest of the test cannot run.'
    }
    Add-Check '2' 'the host name is suggested as a name (a name query of Sysmon was read)' ($hostnames -contains $HostName) "allowedHostnames: $($hostnames -join ', ')"
    Add-Check '2' 'the address without a name is suggested as an address' ($remotes -contains $OtherAddress) "allowedRemote: $($remotes -join ', ')"
    $explorer = @($programs | Where-Object { $_ -match '\\explorer\.exe$' })
    Add-Check '2' 'the program the client looked at is suggested' ($explorer.Count -eq 1) "allowedProcessAccess: $($programs -join ', ')"
    $load = [regex]::Match($learned.Output, 'Highest processor load: ([\d.]+) cores')
    Add-Check '2' 'the highest processor load is noted' ($load.Success -and [double]::Parse($load.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture) -gt $cpuCores) $(if ($load.Success) { "$($load.Groups[1].Value) cores" } else { 'not measured' })
    Add-Check '2' 'the created program file is shown' ($learned.Output -match '<- program files') ''

    # --- 4. The suggestion taken over, learning off ------------------------------------------------
    Write-Host ''
    Write-Host '3. The suggestion taken over, learning mode off: the guard judges again ...' -ForegroundColor Cyan
    $config = [ordered]@{
        cpuAlertCores   = $cpuCores
        cpuAlertSeconds = $cpuWindow
        profiles        = @([ordered]@{
                name                 = $profileName
                clientPath           = $client
                allowedHostnames     = @($hostnames)
                allowedRemote        = @($remotes)
                allowedProcessAccess = @($programs)
            })
    }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    $judgingStart = Get-FileLength $guardLog
    Restart-Guard
    $stillLearning = @(Get-NewLines $judgingStart 'Learning mode is ON')
    Add-Check '3' 'the service does not say "learning" any more' ($stillLearning.Count -eq 0)

    Write-Host "   The client connects to ${HostName}:$Port and ${OtherAddress}:$Port again ..."
    $viaName = Connect-Client $HostName
    $viaAddress = Connect-Client $OtherAddress
    $r2 = @(Get-NewLines $judgingStart "R2 \w+ $tag")
    # "No finding" only counts for a connection Sysmon recorded: one it missed is quiet for another reason.
    Add-Check '3' 'what was learned connects, is recorded by Sysmon and leaves no finding' ($viaName.Recorded -and $viaAddress.Recorded -and $r2.Count -eq 0) "name: $(if ($viaName.Recorded) { 'recorded' } elseif ($viaName.Connected) { 'not recorded' } else { $viaName.Said }); address: $(if ($viaAddress.Recorded) { 'recorded' } elseif ($viaAddress.Connected) { 'not recorded' } else { $viaAddress.Said }); $($r2.Count) R2 line(s)"

    Write-Host "   The client connects to ${UnknownAddress}:$Port, which it never did while learning ..."
    $unknown = Connect-Client $UnknownAddress
    $r2 = @(Wait-NewLines $judgingStart "R2 CRITICAL $tag .*not on the allowlist: $([regex]::Escape($UnknownAddress)):$Port" 10)
    Add-Check '3' 'an address that was not learned is an alert again' ($unknown.Recorded -and $r2.Count -gt 0) "$(if ($unknown.Recorded) { "recorded at try $($unknown.Tries)" } elseif ($unknown.Connected) { "not recorded by Sysmon in $($unknown.Tries) tries" } else { $unknown.Said }); $($r2.Count) R2 critical line(s)"

    Write-Host '   The client opens the other program again ...'
    $null = Invoke-Client @('--open-process', 'read')
    $null = Invoke-Client @('--open-process', 'write')
    $write = @(Wait-NewLines $judgingStart "R7 HIGH $tag .*with rights to change it \(0x102a" 8)
    $r7 = @(Get-NewLines $judgingStart "R7 \w+ $tag")
    Add-Check '3' 'looking at the listed program is quiet, rights to change it still alert' ($write.Count -eq 1 -and $r7.Count -eq 1) "$($r7.Count) R7 line(s), $($write.Count) of them high"

    Write-Host '   The client starts a program ...'
    $spawn = Invoke-Client @('--spawn', '--hold', "$HoldSeconds")
    $terminated = $spawn.ExitCode -ne 0 -and $spawn.Output -notmatch 'NOT TERMINATED|was stopped:'
    $r1 = @(Wait-NewLines $judgingStart "R1 CRITICAL $tag" 8)
    $spared = @(Get-NewLines $judgingStart 'not terminated \(learning mode\)')
    Add-Check '3' 'the started program and the client are terminated again' ($terminated -and $r1.Count -gt 0 -and $spared.Count -eq 0) "client $(if ($terminated) { 'terminated' } else { 'not terminated' }); $($r1.Count) R1 critical line(s)"
}
catch {
    $stopped = [string] $_.Exception.Message
    Write-Host "The test stopped: $stopped" -ForegroundColor DarkYellow
}
finally {
    # --- 5. Back to the configuration from before the test -----------------------------------------
    if ($configChanged) {
        Write-Host ''
        Write-Host '4. Putting the configuration back ...' -ForegroundColor Cyan
        $cleanupProblem = $null
        try {
            Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $configBackup) { Move-Item -LiteralPath $configBackup -Destination $configPath -Force }
            # The notes of the test are of no use to anybody; those from before come back.
            Remove-Item -LiteralPath $learnedPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $learnedBackup) { Move-Item -LiteralPath $learnedBackup -Destination $learnedPath -Force }
            Restart-Guard
        }
        catch { $cleanupProblem = [string] $_.Exception.Message }
        $left = Get-TestRuleCount
        $leftovers = @($configBackup, $learnedBackup | Where-Object { Test-Path -LiteralPath $_ })
        Add-Check '4' 'the configuration is back; no lockdown, rule or backup file is left' (-not $cleanupProblem -and $left -eq 0 -and @(Get-LockedProfiles).Count -eq 0 -and $leftovers.Count -eq 0) $(
            if ($cleanupProblem) { $cleanupProblem } elseif ($left) { "$left rule(s)" } elseif ($leftovers.Count) { "left: $($leftovers -join ', ')" } else { '' })
    }
    try {
        Save-Events $eventsFile
        $notes += "Sysmon events of the run: $eventsFile"
    }
    catch { $notes += "The Sysmon events could not be saved: $($_.Exception.Message)" }
}

$failed = @($checks | Where-Object { $_.Result -eq 'FAIL' }).Count
$verdict =
    if ($stopped) { "STOPPED: $stopped" }
    elseif ($failed -eq 0) { 'ALL PASSED' }
    else { "$failed FAILED" }
$report = @(
    "RCEGuard learning test (M5), $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Client: $client    Name: ${HostName}:$Port    Address: ${OtherAddress}:$Port    Not learned: ${UnknownAddress}:$Port"
    ''
    ($checks | Format-Table Step, Check, Value, Result -AutoSize -Wrap | Out-String -Width 220).Trim()
    ''
    "Verdict: $verdict"
    "Guard log: $guardLog"
)
if ($script:sensorTries -gt 0) {
    $report += ''
    $report += "Sensor: Sysmon recorded $($script:sensorTries - $script:sensorMissed) of $($script:sensorTries) connections of the test client (each client stayed alive for $HoldSeconds s):"
    $report += $script:sensorNotes
}
if ($notes.Count -gt 0) {
    $report += ''
    $report += $notes
}
[IO.File]::WriteAllLines($resultFile, [string[]] $report, [Text.UTF8Encoding]::new($false))
Write-Host ''
$report | ForEach-Object { Write-Host $_ }
Write-Host "Result saved to '$resultFile'."
if ($verdict -ne 'ALL PASSED') { exit 1 }
