<#
.SYNOPSIS
    Checks the tray application next to the installed service: it runs without administrator
    rights, and a lockdown can be released from its window.

.DESCRIPTION
    Part of this test is done by you, at the screen. The script

      1. installs RCEGuard for the test client with install.ps1 (unless -SkipInstall), which also
         installs and starts the tray application,
      2. checks that the tray application runs, and without administrator rights,
      3. gives the service a configuration with lockdown on and lets the simulator start a
         program: the service terminates it and locks the profile down,
      4. waits for you: double-click the shield next to the clock (it is red now), click
         "Release ..." in the window, confirm, and confirm the administrator question of Windows,
      5. checks that the lockdown is gone, that no firewall rule is left and that the release
         command was started by the tray application,
      6. puts the configuration back as it was.

    Needs an administrator PowerShell. Publish first with '.\build.ps1 -Publish' and the
    simulator to the test folder (see README). The result goes to <OutDir>\m4-result.txt.

.PARAMETER TestDir
    Folder with the simulator (Wow.exe).

.PARAMETER OutDir
    Folder for the result; created if missing.

.PARAMETER DataDir
    Data folder of the service.

.PARAMETER WaitSeconds
    How long the script waits for you to release the lockdown in the window.

.PARAMETER HoldSeconds
    How long the simulator stays alive after starting a program, so the service can terminate it.

.PARAMETER DownloadSysmon
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER AcceptSysmonEula
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER SkipInstall
    Do not call install.ps1: service and tray application are installed and running.

.PARAMETER AllowNonAdmin
    Skip the administrator check. Only useful for trying the script itself with stand-ins.

.EXAMPLE
    .\scripts\tray-test.ps1 -DownloadSysmon -AcceptSysmonEula
#>
[CmdletBinding()]
param(
    [string] $TestDir = 'C:\RCEGuardTest',
    [string] $OutDir,
    [string] $DataDir = (Join-Path $env:ProgramData 'RCEGuard'),
    [int] $WaitSeconds = 180,
    [int] $HoldSeconds = 8,
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
. (Join-Path $PSScriptRoot 'TrayTools.ps1')

$profileName = 'TrayTest'
$client = Join-Path $TestDir 'Wow.exe'
$configPath = Join-Path $DataDir 'appsettings.json'
$configBackup = Join-Path $DataDir 'appsettings.json.before-tray-test'
$lockdownPath = Join-Path $DataDir 'lockdown.json'
$guardLog = Join-Path $DataDir $script:GuardLogName

function Install-ForTest {
    & (Join-Path $PSScriptRoot 'install.ps1') -ClientPath $client -DownloadSysmon:$DownloadSysmon -AcceptSysmonEula:$AcceptSysmonEula | Out-Host
}

function Invoke-Client([string[]] $arguments) {
    # Runs the simulator and returns its exit code and what it printed.
    $out = Join-Path $OutDir 'm4-client.out'
    $process = Start-Process -FilePath $client -ArgumentList $arguments -RedirectStandardOutput $out -PassThru -WindowStyle Hidden
    $null = $process.Handle
    if (-not $process.WaitForExit(($HoldSeconds + 30) * 1000)) {
        $process.Kill()
        throw "The simulator did not end: $($arguments -join ' ')"
    }
    $text = [string] (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $text }
}

function Get-TrayRights {
    # One entry per running tray application: $false = no administrator rights, $true = administrator rights, $null = unknown.
    @(Get-TrayProcesses | ForEach-Object { Test-ProcessElevated ([int] $_.ProcessId) })
}

function Get-TestRuleCount {
    @(Get-GuardFirewallRules).Count
}

function Restart-Guard {
    Restart-GuardService $DataDir
}

function Get-LockedProfiles {
    if (-not (Test-Path -LiteralPath $lockdownPath)) { return @() }
    $state = Get-Content -LiteralPath $lockdownPath -Raw | ConvertFrom-Json
    @($state.locked | ForEach-Object { [string] $_.profile })
}

function Get-ReleaseStarters {
    # Who started a release command that is running right now: the name of its parent process.
    @(Get-CimInstance Win32_Process -Filter "Name='$script:GuardExeName'" |
        Where-Object { $null -ne $_ -and [string] $_.CommandLine -match '--release' } |
        ForEach-Object {
            $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
            if ($null -ne $parent) { $parent.ProcessName } else { 'a process that has ended' }
        })
}

function Invoke-ReleaseForCleanup {
    # Only for putting things back if the lockdown was not released in the window.
    $exe = Join-Path $script:GuardInstallDir $script:GuardExeName
    $ErrorActionPreference = 'Continue'   # 5.1 turns a line on stderr into an error under 'Stop'
    $null = @(& $exe --release 2>&1)
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

$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$resultFile = Join-Path $OutDir 'm4-result.txt'
Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue

$checks = @()
function Add-Check([string] $step, [string] $check, [bool] $ok, [string] $value = '') {
    $script:checks += [pscustomobject]@{ Step = $step; Check = $check; Value = $value; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }) }
}

function Wait-Until([scriptblock] $condition, [double] $seconds, [int] $everyMilliseconds = 250) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        if (& $condition) { return $true }
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds $everyMilliseconds
    }
}

# --- 1. Installed service and tray application -------------------------------------------------
if (-not $SkipInstall) {
    Write-Host "Installing RCEGuard (sensor, service and tray application) for '$client' ..."
    Install-ForTest
}
if (-not (Test-Path -LiteralPath $guardLog)) {
    throw "The log of the service was not found: '$guardLog'. Is RCEGuard installed?"
}

$stopped = $null
$configChanged = $false
try {
    Write-Host ''
    Write-Host '1. The tray application ...' -ForegroundColor Cyan
    # Started through Explorer: give it a moment to come up.
    $null = Wait-Until { @(Get-TrayRights).Count -gt 0 } 15
    $rights = @(Get-TrayRights)
    $rightsText = @($rights | ForEach-Object { if ($null -eq $_) { 'unknown' } elseif ($_) { 'administrator rights' } else { 'no administrator rights' } }) -join ', '
    Add-Check '1' 'the tray application is running' ($rights.Count -ge 1) "$($rights.Count) process(es)"
    Add-Check '1' 'it runs without administrator rights' ($rights.Count -ge 1 -and @($rights | Where-Object { $_ -ne $false }).Count -eq 0) $(if ($rights.Count) { $rightsText } else { 'not running' })
    if ($rights.Count -eq 0) {
        throw 'The tray application is not running, so the lockdown cannot be released from its window.'
    }

    # --- 2. A lockdown ---------------------------------------------------------------------------
    Write-Host ''
    Write-Host '2. Lockdown on for the test client; the simulator starts a program ...' -ForegroundColor Cyan
    if (@(Get-LockedProfiles).Count -gt 0) {
        throw "A profile is already in lockdown ($(@(Get-LockedProfiles) -join ', ')). Release it first: this test needs to start without one."
    }
    if (Test-Path -LiteralPath $configPath) { Move-Item -LiteralPath $configPath -Destination $configBackup -Force }
    $configChanged = $true
    $config = [ordered]@{
        lockdown = $true
        profiles = @([ordered]@{ name = $profileName; clientPath = $client })
    }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Restart-Guard

    $spawn = Invoke-Client @('--spawn', '--hold', "$HoldSeconds")
    $terminated = $spawn.ExitCode -ne 0 -and $spawn.Output -notmatch 'NOT TERMINATED|was stopped:'
    $locked = Wait-Until { $profileName -in @(Get-LockedProfiles) } 8
    Add-Check '2' 'the client was terminated and the profile is in lockdown' ($terminated -and $locked) "client $(if ($terminated) { 'terminated' } else { 'not terminated' }); in lockdown: $(@(Get-LockedProfiles) -join ', ')"
    if (-not $locked) {
        throw 'There is no lockdown to release, so the rest of the test cannot run.'
    }

    # --- 3. Your part ------------------------------------------------------------------------------
    Write-Host ''
    Write-Host '3. Your part:' -ForegroundColor Yellow
    Write-Host '     - The shield next to the clock is red now. Double-click it.' -ForegroundColor Yellow
    Write-Host "     - In the window, click `"Release ...`" next to '$profileName' and confirm." -ForegroundColor Yellow
    Write-Host '     - Confirm the administrator question of Windows.' -ForegroundColor Yellow
    Write-Host "   Waiting up to $WaitSeconds s ..." -ForegroundColor Yellow
    $offset = Get-FileLength $guardLog
    $script:starters = @()
    $waitStarted = Get-Date
    $released = Wait-Until {
        # The release command runs for about a second: look for it on every round, and look often.
        $now = @(Get-ReleaseStarters)
        if ($now.Count -gt 0) { $script:starters = @($script:starters) + $now }
        @(Get-LockedProfiles).Count -eq 0
    } $WaitSeconds 100
    $starters = @($script:starters)
    $took = [int] ((Get-Date) - $waitStarted).TotalSeconds
    Add-Check '3' 'the lockdown was released while the script waited' $released $(if ($released) { "after $took s" } else { "still in lockdown after $WaitSeconds s: $(@(Get-LockedProfiles) -join ', ')" })
    if ($released) {
        $byTray = @($starters | Where-Object { $_ -eq 'RCEGuard.Tray' }).Count -gt 0
        Add-Check '3' 'the release command was started by the tray application' $byTray $(if ($starters.Count) { "started by: $(@($starters | Select-Object -Unique) -join ', ')" } else { 'the release command was not seen running' })
        $noRule = Wait-Until { (Get-TestRuleCount) -eq 0 } 5
        Add-Check '3' 'no firewall rule of RCEGuard is left' $noRule "$(Get-TestRuleCount) rule(s)"
        # The running service looks at the lockdown state at least every 15 s.
        $noticed = Wait-Until { (Read-TextFrom $guardLog $offset) -match 'changed from outside' } 25
        Add-Check '3' 'the running service noticed the release' $noticed
        $again = Invoke-Client @('--connect', '127.0.0.1:9')
        Add-Check '3' 'the client starts again' ($again.Output -match 'R2: connecting') "exit code $($again.ExitCode)"
    }
}
catch {
    $stopped = [string] $_.Exception.Message
    Write-Host "The test stopped: $stopped" -ForegroundColor DarkYellow
}
finally {
    # --- 4. Back to the configuration from before the test ---------------------------------------
    if ($configChanged) {
        Write-Host ''
        Write-Host '4. Putting the configuration back ...' -ForegroundColor Cyan
        $cleanupProblem = $null
        try {
            if (@(Get-LockedProfiles).Count -gt 0) { Invoke-ReleaseForCleanup }
            Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $configBackup) { Move-Item -LiteralPath $configBackup -Destination $configPath -Force }
            Restart-Guard
        }
        catch { $cleanupProblem = [string] $_.Exception.Message }
        $left = Get-TestRuleCount
        Add-Check '4' 'the configuration is back, no lockdown and no rule of RCEGuard is left' (-not $cleanupProblem -and $left -eq 0 -and @(Get-LockedProfiles).Count -eq 0) $(
            if ($cleanupProblem) { $cleanupProblem } elseif ($left) { "$left rule(s)" } else { '' })
    }
}

$failed = @($checks | Where-Object { $_.Result -eq 'FAIL' }).Count
$verdict =
    if ($stopped) { "STOPPED: $stopped" }
    elseif ($failed -eq 0) { 'ALL PASSED' }
    else { "$failed FAILED" }
$report = @(
    "RCEGuard tray test (M4), $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Client: $client"
    ''
    ($checks | Format-Table Step, Check, Value, Result -AutoSize -Wrap | Out-String -Width 200).Trim()
    ''
    "Verdict: $verdict"
    "Guard log: $guardLog"
)
[IO.File]::WriteAllLines($resultFile, [string[]] $report, [Text.UTF8Encoding]::new($false))
Write-Host ''
$report | ForEach-Object { Write-Host $_ }
Write-Host "Result saved to '$resultFile'."
if ($verdict -ne 'ALL PASSED') { exit 1 }
