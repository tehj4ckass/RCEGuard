<#
.SYNOPSIS
    Checks the prevention of milestone M3 on the installed service: the firewall rule of a profile,
    the lockdown after a finding that terminates the client, and the release.

.DESCRIPTION
    Runs against the installed Windows service and the simulator (the test client). The script

      1. installs RCEGuard for the test client with install.ps1 (unless -SkipInstall),
      2. checks that the test client reaches two addresses on the internet while nothing is blocked,
      3. gives the service a configuration with the firewall on for the test client and only the
         first address allowed, and with lockdown on,
      4. checks the rule in Windows Firewall, that the allowed address still connects and that the
         other one does not,
      5. lets the simulator start a program: the service must terminate it and lock the profile
         down, after which not even the allowed address connects, also after a restart of the service,
      6. releases the lockdown with 'RCEGuard.Service.exe --release' and checks that the allowed
         address connects again,
      7. puts the configuration back as it was and checks that the rule is gone,
      8. turns on "Do not allow child processes" for the test client with
         'install.ps1 -BlockChildProcesses' and checks that the client still starts and connects,
         that Windows refuses when it starts a program, and that the setting is gone again after
         'install.ps1 -AllowChildProcesses'.

    Needs an administrator PowerShell and an internet connection. Publish the service first with
    '.\build.ps1 -Publish' and the simulator to the test folder (see README).
    While the test runs, only the test client is blocked; no other program is affected.
    The result goes to <OutDir>\m3-result.txt.

.PARAMETER TestDir
    Folder with the simulator (Wow.exe).

.PARAMETER OutDir
    Folder for the result; created if missing.

.PARAMETER DataDir
    Data folder of the service.

.PARAMETER AllowedAddress
    IPv4 address the test profile allows. Must accept TCP connections on -Port.

.PARAMETER OtherAddress
    IPv4 address the test profile does not allow. Must accept TCP connections on -Port.

.PARAMETER Port
    TCP port for both addresses.

.PARAMETER HoldSeconds
    How long the simulator stays alive after starting a program, so the service can terminate it.

.PARAMETER DownloadSysmon
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER AcceptSysmonEula
    Passed to install.ps1 if Sysmon has to be installed.

.PARAMETER SkipInstall
    Do not call install.ps1: the service is installed and running for the test client.

.PARAMETER AllowNonAdmin
    Skip the administrator check. Only useful for trying the script itself with stand-ins.

.EXAMPLE
    .\scripts\prevention-test.ps1 -DownloadSysmon -AcceptSysmonEula
#>
[CmdletBinding()]
param(
    [string] $TestDir = 'C:\RCEGuardTest',
    [string] $OutDir,
    [string] $DataDir = (Join-Path $env:ProgramData 'RCEGuard'),
    [string] $AllowedAddress = '1.1.1.1',
    [string] $OtherAddress = '1.0.0.1',
    [int] $Port = 443,
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
. (Join-Path $PSScriptRoot 'ExploitProtectionTools.ps1')

$profileName = 'PreventionTest'
$ruleName = "RCEGuard: $profileName"
$client = Join-Path $TestDir 'Wow.exe'
$configPath = Join-Path $DataDir 'appsettings.json'
$configBackup = Join-Path $DataDir 'appsettings.json.before-prevention-test'
$lockdownPath = Join-Path $DataDir 'lockdown.json'
$guardLog = Join-Path $DataDir $script:GuardLogName

function Invoke-Client([string[]] $arguments) {
    # Runs the simulator and returns its exit code and what it printed.
    $out = Join-Path $OutDir 'm3-client.out'
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

function Get-TestRules {
    # The firewall rules of RCEGuard, reduced to what the checks look at.
    @(Get-GuardFirewallRules | ForEach-Object {
        [pscustomobject]@{
            Name           = [string] $_.Name
            Program        = [string] $_.ApplicationName
            Addresses      = [string] $_.RemoteAddresses
            Enabled        = [bool] $_.Enabled
            BlocksOutbound = ($_.Direction -eq 2 -and $_.Action -eq 0)   # outbound, block
        }
    })
}

function Restart-Guard {
    Restart-GuardService $DataDir
}

function Invoke-Release {
    # Runs the release command of the installed service and returns its exit code and output.
    $exe = Join-Path $script:GuardInstallDir $script:GuardExeName
    $ErrorActionPreference = 'Continue'   # 5.1 turns a line on stderr into an error under 'Stop'
    $lines = @(& $exe --release 2>&1 | ForEach-Object { "$_" })
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($lines -join "`n") }
}

function Set-TestBlock([bool] $on) {
    # Turns "Do not allow child processes" on or off for the test client the way a user does: with install.ps1.
    $install = Join-Path $PSScriptRoot 'install.ps1'
    if ($on) { & $install -ClientPath $client -BlockChildProcesses | Out-Host }
    else { & $install -ClientPath $client -AllowChildProcesses | Out-Host }
}

function Get-TestBlock {
    Get-ChildProcessBlock $client
}

function Get-RefusedStartEvents([datetime] $since) {
    # What Windows itself logged about program starts it refused (Exploit Protection, event 4), as text lines.
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Security-Mitigations/KernelMode'; Id = 4; StartTime = $since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'Wow\.exe' } |
        ForEach-Object { (($_.Message -split "`r?`n")[0]).Trim() })
}

function Get-BlockRegistry {
    # The entry Windows keeps for programs of the client's name (Image File Execution Options), as text lines.
    $key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + (Split-Path -Path $client -Leaf)
    $ErrorActionPreference = 'Continue'   # 5.1 turns a line on stderr into an error under 'Stop'
    $lines = @(& reg.exe query $key /s 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0) { return @('(no such key)') }
    return $lines
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
foreach ($address in @($AllowedAddress, $OtherAddress)) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($address, [ref] $parsed) -or $parsed.AddressFamily -ne 'InterNetwork') {
        throw "'$address' is not an IPv4 address."
    }
}

$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$resultFile = Join-Path $OutDir 'm3-result.txt'
Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue

$checks = @()
function Add-Check([string] $step, [string] $check, [bool] $ok, [string] $value = '') {
    $script:checks += [pscustomobject]@{ Step = $step; Check = $check; Value = $value; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }) }
}

function Test-Connect([string] $address) {
    # 'connected' or 'blocked', with what the simulator said.
    $result = Invoke-Client @('--connect', "${address}:$Port")
    $line = @($result.Output -split "`r?`n" | Where-Object { $_ -match 'Connected;|was stopped:' })
    $said = if ($line.Count -gt 0) { $line[0].Trim() } else { "exit code $($result.ExitCode), no message" }
    if ($said.Length -gt 100) { $said = $said.Substring(0, 100) + '...' }
    [pscustomobject]@{ Connected = ($result.Output -match 'Connected;'); Said = $said }
}

function Get-TestRule {
    @(Get-TestRules | Where-Object { $_.Name -eq $ruleName }) | Select-Object -First 1
}

function Wait-Until([scriptblock] $condition, [int] $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        if (& $condition) { return $true }
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 250
    }
}

function Get-LockedProfiles {
    if (-not (Test-Path -LiteralPath $lockdownPath)) { return @() }
    $state = Get-Content -LiteralPath $lockdownPath -Raw | ConvertFrom-Json
    @($state.locked | ForEach-Object { [string] $_.profile })
}

# --- 1. Installed service ----------------------------------------------------------------------
if (-not $SkipInstall) {
    Write-Host "Installing RCEGuard (sensor and service) for '$client' ..."
    & (Join-Path $PSScriptRoot 'install.ps1') -ClientPath $client -DownloadSysmon:$DownloadSysmon -AcceptSysmonEula:$AcceptSysmonEula
}
if (-not (Test-Path -LiteralPath $guardLog)) {
    throw "The log of the service was not found: '$guardLog'. Is RCEGuard installed?"
}

$stopped = $null
$configChanged = $false
try {
    # --- 2. Without the firewall both addresses must be reachable -------------------------------
    Write-Host ''
    Write-Host "1. Without a rule: does the test client reach ${AllowedAddress}:${Port} and ${OtherAddress}:${Port}? ..." -ForegroundColor Cyan
    $before = @(Get-TestRules)
    if ($before.Count -gt 0) {
        throw "Windows Firewall already has rules of RCEGuard ($(@($before | ForEach-Object { $_.Name }) -join ', ')). The test needs a service whose configuration turns neither 'firewall' nor 'lockdown' on."
    }
    foreach ($address in @($AllowedAddress, $OtherAddress)) {
        $try = Test-Connect $address
        if (-not $try.Connected) {
            throw "The test client does not reach ${address}:$Port even without a firewall rule ($($try.Said)). The test needs an internet connection; other addresses can be given with -AllowedAddress and -OtherAddress."
        }
    }
    Add-Check '1' 'both addresses are reachable without a rule' $true "${AllowedAddress}:$Port, ${OtherAddress}:$Port"

    # --- 3. Configuration with firewall and lockdown --------------------------------------------
    Write-Host ''
    Write-Host "2. Firewall on for the test client, only $AllowedAddress allowed ..." -ForegroundColor Cyan
    if (Test-Path -LiteralPath $configPath) { Move-Item -LiteralPath $configPath -Destination $configBackup -Force }
    $configChanged = $true
    $config = [ordered]@{
        lockdown = $true
        profiles = @([ordered]@{ name = $profileName; clientPath = $client; allowedRemote = @($AllowedAddress); firewall = $true })
    }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Restart-Guard

    $rule = Get-TestRule
    $all = @(Get-TestRules)
    Add-Check '2' 'one rule of RCEGuard is in Windows Firewall' ($null -ne $rule -and $all.Count -eq 1) (@($all | ForEach-Object { $_.Name }) -join ', ')
    if ($null -ne $rule) {
        Add-Check '2' 'it is an enabled outbound block rule for the client' ($rule.Enabled -and $rule.BlocksOutbound -and [string]::Equals($rule.Program, $client, [StringComparison]::OrdinalIgnoreCase)) $rule.Program
        # The rule names everything except the allowed address: its neighbours are the ends of two ranges.
        $parts = $AllowedAddress.Split('.')
        $last = [int] $parts[3]
        $prefix = ($parts[0..2] -join '.')
        $around = ($last -gt 0 -and $last -lt 255) -and $rule.Addresses.Contains("-$prefix.$($last - 1),") -and $rule.Addresses.Contains(",$prefix.$($last + 1)-")
        $count = @($rule.Addresses.Split(',')).Count
        Add-Check '2' 'it blocks every address but the allowed one' ($around -and $rule.Addresses -ne '*') "$count ranges, gap at $AllowedAddress"
    }
    $allowed = Test-Connect $AllowedAddress
    Add-Check '2' 'the allowed address still connects' $allowed.Connected $allowed.Said
    $other = Test-Connect $OtherAddress
    Add-Check '2' 'the other address is blocked' (-not $other.Connected) $other.Said

    # --- 4. Lockdown ----------------------------------------------------------------------------
    Write-Host ''
    Write-Host '3. The test client starts a program: the service must terminate it and lock the profile down ...' -ForegroundColor Cyan
    $offset = Get-FileLength $guardLog
    $spawn = Invoke-Client @('--spawn', '--hold', "$HoldSeconds")
    $terminated = $spawn.ExitCode -ne 0 -and $spawn.Output -notmatch 'NOT TERMINATED'
    $lockedLine = ''
    $null = Wait-Until { @((Read-TextFrom $guardLog $offset) -split "`r?`n" | Where-Object { $_ -match '\bR1 CRITICAL \[' -and $_ -match 'locked down' }).Count -gt 0 } 6
    $lockedLines = @((Read-TextFrom $guardLog $offset) -split "`r?`n" | Where-Object { $_ -match '\bR1 CRITICAL \[' -and $_ -match 'locked down' })
    if ($lockedLines.Count -gt 0) { $lockedLine = 'R1, locked down' }
    Add-Check '3' 'the client was terminated and the finding says "locked down"' ($terminated -and $lockedLines.Count -gt 0) "client $(if ($terminated) { 'terminated' } else { 'not terminated' }); $(if ($lockedLine) { $lockedLine } else { 'no such line in the log' })"
    $rule = Get-TestRule
    Add-Check '3' 'the rule blocks every address' ($null -ne $rule -and $rule.Addresses -eq '*' -and $rule.Enabled -and $rule.BlocksOutbound) $(if ($null -ne $rule) { $rule.Addresses.Substring(0, [Math]::Min(40, $rule.Addresses.Length)) } else { 'no rule' })
    $locked = @(Get-LockedProfiles)
    Add-Check '3' 'the lockdown is noted in lockdown.json' ($profileName -in $locked) ($locked -join ', ')
    $allowed = Test-Connect $AllowedAddress
    Add-Check '3' 'the allowed address is blocked too' (-not $allowed.Connected) $allowed.Said

    Write-Host ''
    Write-Host '4. Restarting the service: the lockdown must still be there ...' -ForegroundColor Cyan
    Restart-Guard
    $rule = Get-TestRule
    Add-Check '4' 'the rule still blocks every address' ($null -ne $rule -and $rule.Addresses -eq '*') $(if ($null -ne $rule) { $rule.Addresses.Substring(0, [Math]::Min(40, $rule.Addresses.Length)) } else { 'no rule' })
    $allowed = Test-Connect $AllowedAddress
    Add-Check '4' 'the allowed address is still blocked' (-not $allowed.Connected) $allowed.Said

    # --- 5. Release -----------------------------------------------------------------------------
    Write-Host ''
    Write-Host '5. Releasing the lockdown ...' -ForegroundColor Cyan
    $offset = Get-FileLength $guardLog
    $release = Invoke-Release
    Write-Host $release.Output
    Add-Check '5' 'the release command succeeds and names the profile' ($release.ExitCode -eq 0 -and $release.Output -match "Released '$profileName'") "exit code $($release.ExitCode)"
    $null = Wait-Until { $r = Get-TestRule; $null -ne $r -and $r.Addresses -ne '*' } 5
    $rule = Get-TestRule
    Add-Check '5' 'the rule is back to the allowlist' ($null -ne $rule -and $rule.Addresses -ne '*') $(if ($null -ne $rule) { "$(@($rule.Addresses.Split(',')).Count) ranges" } else { 'no rule' })
    Add-Check '5' 'lockdown.json is empty' (@(Get-LockedProfiles).Count -eq 0) (@(Get-LockedProfiles) -join ', ')
    $allowed = Test-Connect $AllowedAddress
    Add-Check '5' 'the allowed address connects again' $allowed.Connected $allowed.Said
    $other = Test-Connect $OtherAddress
    Add-Check '5' 'the other address is still blocked' (-not $other.Connected) $other.Said
    # The running service looks at the lockdown state at least every 15 s.
    $noticed = Wait-Until { (Read-TextFrom $guardLog $offset) -match 'changed from outside' } 25
    Add-Check '5' 'the running service noticed the release' $noticed
}
catch {
    $stopped = [string] $_.Exception.Message
    Write-Host "The test stopped: $stopped" -ForegroundColor DarkYellow
}
finally {
    # --- 6. Back to the configuration from before the test -------------------------------------
    if ($configChanged) {
        Write-Host ''
        Write-Host '6. Putting the configuration back ...' -ForegroundColor Cyan
        $cleanupProblem = $null
        try {
            if (@(Get-LockedProfiles).Count -gt 0) { $null = Invoke-Release }
            Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $configBackup) { Move-Item -LiteralPath $configBackup -Destination $configPath -Force }
            Restart-Guard
        }
        catch { $cleanupProblem = [string] $_.Exception.Message }
        $left = @(Get-TestRules)
        Add-Check '6' 'the configuration is back and no rule of RCEGuard is left' (-not $cleanupProblem -and $left.Count -eq 0 -and @(Get-LockedProfiles).Count -eq 0) $(
            if ($cleanupProblem) { $cleanupProblem } elseif ($left.Count) { @($left | ForEach-Object { $_.Name }) -join ', ' } else { '' })
        if (-not $cleanupProblem) {
            $allowed = Test-Connect $OtherAddress
            Add-Check '6' 'the test client reaches the other address again' $allowed.Connected $allowed.Said
        }
    }
}

# --- 7. Exploit Protection: the client may not start other programs --------------------------
# After the firewall part, with the configuration from before the test (no lockdown).
$notes = @()
$blockChanged = $false
if (-not $stopped) {
    try {
        Write-Host ''
        Write-Host '7. Exploit Protection: the test client may not start other programs ...' -ForegroundColor Cyan
        $blockBefore = Get-TestBlock
        if ($blockBefore -ne 'NOTSET') {
            throw "Exploit Protection already has a setting for child processes of '$client' ($blockBefore). The test needs a client without one."
        }
        $blockChanged = $true
        Set-TestBlock $true
        $blockNow = Get-TestBlock
        Add-Check '7' 'install.ps1 -BlockChildProcesses turns the setting on' ($blockNow -eq 'ON') "DisallowChildProcessCreation: $blockNow"
        $notes += 'Registry while the setting is on:'
        $notes += @(Get-BlockRegistry | ForEach-Object { "    $_" })

        # The simulator is a console program: Windows starts a console host for it. That must still work.
        $try = Test-Connect $OtherAddress
        Add-Check '7' 'the client still starts and connects' $try.Connected $try.Said

        $offset = Get-FileLength $guardLog
        $since = (Get-Date).AddSeconds(-2)
        $spawn = Invoke-Client @('--spawn', '--hold', "$HoldSeconds")
        $refusal = @($spawn.Output -split "`r?`n" | Where-Object { $_ -match 'was stopped:' })
        $said = if ($refusal.Count -gt 0) { $refusal[0].Trim() } else { "exit code $($spawn.ExitCode): the program was started" }
        if ($said.Length -gt 100) { $said = $said.Substring(0, 100) + '...' }
        Add-Check '7' 'Windows refuses when the client starts a program' ($refusal.Count -gt 0) $said
        Start-Sleep -Seconds 3
        $r1 = @((Read-TextFrom $guardLog $offset) -split "`r?`n" | Where-Object { $_ -match '\bR1 CRITICAL \[' })
        Add-Check '7' 'nothing was started, so the guard has no R1 finding' ($r1.Count -eq 0) "$($r1.Count) R1 CRITICAL line(s)"
        $events = @(Get-RefusedStartEvents $since)
        $notes += "Windows events about the refused start (Security-Mitigations/KernelMode, id 4): $($events.Count)"
        $notes += @($events | Select-Object -First 2 | ForEach-Object { "    $_" })
    }
    catch {
        $stopped = [string] $_.Exception.Message
        Write-Host "The test stopped: $stopped" -ForegroundColor DarkYellow
    }
    finally {
        if ($blockChanged) {
            $backProblem = $null
            try { Set-TestBlock $false } catch { $backProblem = [string] $_.Exception.Message }
            $blockNow = Get-TestBlock
            Add-Check '7' 'install.ps1 -AllowChildProcesses puts the setting back' (-not $backProblem -and $blockNow -eq 'NOTSET') $(if ($backProblem) { $backProblem } else { "DisallowChildProcessCreation: $blockNow" })
            $notes += 'Registry after the setting was taken back:'
            $notes += @(Get-BlockRegistry | ForEach-Object { "    $_" })
            if (-not $backProblem) {
                $offset = Get-FileLength $guardLog
                $spawn = Invoke-Client @('--spawn', '--hold', "$HoldSeconds")
                $terminated = $spawn.ExitCode -ne 0 -and $spawn.Output -notmatch 'NOT TERMINATED|was stopped:'
                $null = Wait-Until { @((Read-TextFrom $guardLog $offset) -split "`r?`n" | Where-Object { $_ -match '\bR1 CRITICAL \[' }).Count -gt 0 } 6
                $r1 = @((Read-TextFrom $guardLog $offset) -split "`r?`n" | Where-Object { $_ -match '\bR1 CRITICAL \[' })
                Add-Check '7' 'without the setting the program starts and the guard terminates it' ($terminated -and $r1.Count -gt 0) "client $(if ($terminated) { 'terminated' } else { 'not terminated' }); $($r1.Count) R1 CRITICAL line(s)"
            }
        }
    }
}

$failed = @($checks | Where-Object { $_.Result -eq 'FAIL' }).Count
$verdict =
    if ($stopped) { "STOPPED: $stopped" }
    elseif ($failed -eq 0) { 'ALL PASSED' }
    else { "$failed FAILED" }
$report = @(
    "RCEGuard prevention test (M3), $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Client: $client    Allowed: ${AllowedAddress}:$Port    Not allowed: ${OtherAddress}:$Port"
    ''
    ($checks | Format-Table Step, Check, Value, Result -AutoSize -Wrap | Out-String -Width 200).Trim()
    ''
    "Verdict: $verdict"
    "Guard log: $guardLog"
)
if ($notes.Count -gt 0) {
    $report += ''
    $report += 'Seen on the way (not checks):'
    $report += $notes
}
[IO.File]::WriteAllLines($resultFile, [string[]] $report, [Text.UTF8Encoding]::new($false))
Write-Host ''
$report | ForEach-Object { Write-Host $_ }
Write-Host "Result saved to '$resultFile'."
if ($verdict -ne 'ALL PASSED') { exit 1 }
