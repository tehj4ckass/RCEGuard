<#
.SYNOPSIS
    Tests installing and removing RCEGuard, including a service that cannot start.

.DESCRIPTION
    Checks two promises of the install scripts on a machine without RCEGuard:

      - A service that cannot start is removed again. Otherwise Windows would start a service that
        runs as LocalSystem over and over.
      - After uninstall.ps1 nothing that the installation brought is left on the machine.

    Steps:
      A. install.ps1 with a published service that lacks a file: its process dies at once.
      B. install.ps1 with a configuration file that is not valid JSON: the service starts, reports
         that it cannot run, and ends.
      C. install.ps1 without a fault: the service must run.
      D. uninstall.ps1: the machine must look as it did before step A.

    After A and B the service, its folder in Program Files and its event sources must be gone, the
    sensor must still be installed, and Windows must not start the service again.

    Needs an administrator PowerShell and a published service ('.\build.ps1 -Publish'). Sysmon is
    downloaded from Microsoft if it is not installed; that means accepting the Sysinternals licence
    terms (https://learn.microsoft.com/sysinternals/license-terms). The script refuses to start if
    RCEGuard or Sysmon is installed: it would remove them at the end.

    With -ListOnly the script only lists what of an RCEGuard installation is on this machine. That
    needs no administrator rights and changes nothing.

.PARAMETER TestDir
    Folder with the simulator (Wow.exe); it is only named as the client to watch, not started.

.PARAMETER OutDir
    Folder for the result (install-test-result.txt); created if missing.

.PARAMETER ServicePath
    Folder with the published service; default is artifacts\service in this repository.

.PARAMETER ListOnly
    Only list what is installed (see description).

.PARAMETER AllowNonAdmin
    Skip the administrator check. Only useful for trying the script itself with stand-ins for
    install.ps1 and uninstall.ps1 (-InstallScript, -UninstallScript, -DataDir).

.EXAMPLE
    .\scripts\install-test.ps1

.EXAMPLE
    .\scripts\install-test.ps1 -ListOnly
#>
[CmdletBinding()]
param(
    [string] $TestDir = 'C:\RCEGuardTest',
    [string] $OutDir,
    [string] $ServicePath,
    [switch] $ListOnly,
    [switch] $AllowNonAdmin,
    [string] $InstallScript,
    [string] $UninstallScript,
    [string] $DataDir = (Join-Path $env:ProgramData 'RCEGuard')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Defaults that need the script folder are set here: under 'powershell.exe -File' (Windows
# PowerShell 5.1) $PSScriptRoot is still empty while the param block is evaluated.
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot '..\out' }
if (-not $ServicePath) { $ServicePath = Join-Path $PSScriptRoot '..\artifacts\service' }
if (-not $InstallScript) { $InstallScript = Join-Path $PSScriptRoot 'install.ps1' }
if (-not $UninstallScript) { $UninstallScript = Join-Path $PSScriptRoot 'uninstall.ps1' }

. (Join-Path $PSScriptRoot 'SysmonTools.ps1')
. (Join-Path $PSScriptRoot 'GuardServiceTools.ps1')

$servicesKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$sysmonServiceNames = @('Sysmon64', 'Sysmon', 'Sysmon64a')

# Reported, but not counted as a trace: this key was still there after the uninstall of 2026-11-13/14,
# and it is not known yet whether every 'sysmon -u' leaves it or only the one during which Sysmon
# crashed. A complete run of this test answers that.
$sysmonAutologgerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Microsoft-Windows-Sysmon-Operational'
function Get-AutologgerNote([string] $when) {
    "${when}: $(if (Test-Path -LiteralPath $sysmonAutologgerKey) { 'there' } else { 'not there' })"
}

function Get-InstallationTraces {
    <#
        Everything an RCEGuard installation puts on the machine, each with whether it is there now.
        Reads only (registry and file system), so it also works without administrator rights.
        Group 'guard': the service. Group 'sensor': Sysmon. Group 'data': the data folder.
    #>
    $windir = $env:windir
    $found = @(
        @('guard', "service '$script:GuardServiceName'", (Test-Path -LiteralPath (Join-Path $servicesKey $script:GuardServiceName))),
        @('guard', 'process of the service', (@(Get-GuardProcesses).Count -gt 0)),
        @('guard', "folder '$script:GuardInstallDir'", (Test-Path -LiteralPath $script:GuardInstallDir))
    )
    foreach ($source in $script:GuardEventSources) {
        $found += , @('guard', "event source '$source'", (Test-Path -LiteralPath (Join-Path $script:GuardEventLogRoot $source)))
    }
    $found += , @('data', "folder '$DataDir'", (Test-Path -LiteralPath $DataDir))
    $found += , @('sensor', 'Sysmon service', (@($sysmonServiceNames | Where-Object { Test-Path -LiteralPath (Join-Path $servicesKey $_) }).Count -gt 0))
    $found += , @('sensor', 'Sysmon driver', (Test-Path -LiteralPath (Join-Path $servicesKey 'SysmonDrv')))
    $sysmonFiles = @('Sysmon64.exe', 'Sysmon.exe', 'Sysmon64a.exe', 'SysmonDrv.sys' | Where-Object { Test-Path -LiteralPath (Join-Path $windir $_) })
    $found += , @('sensor', "Sysmon files in '$windir'", ($sysmonFiles.Count -gt 0))
    $found += , @('sensor', 'Sysmon event publisher', (Test-Path -LiteralPath $script:SysmonPublisherKey))
    $found += , @('sensor', 'Sysmon event channel', (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'))
    $found += , @('sensor', 'Sysmon event log file', (Test-Path -LiteralPath $script:SysmonLogFile))
    $found += , @('sensor', 'Sysinternals licence note (this user)', (Test-Path -LiteralPath $script:SysmonEulaKey))
    $downloads = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'rceguard-sysmon-*' -ErrorAction SilentlyContinue)
    $found += , @('sensor', 'Sysmon download folder in TEMP', ($downloads.Count -gt 0))

    foreach ($item in $found) {
        [pscustomobject]@{ Group = $item[0]; Name = $item[1]; Present = [bool] $item[2] }
    }
}

function Get-PresentNames([object[]] $traces, [string[]] $groups) {
    @($traces | Where-Object { $_.Present -and $_.Group -in $groups } | ForEach-Object { $_.Name })
}

if ($ListOnly) {
    $traces = @(Get-InstallationTraces)
    $traces | Select-Object Group, Name, @{ Name = 'Present'; Expression = { if ($_.Present) { 'yes' } else { '-' } } } |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $present = @(Get-PresentNames $traces @('guard', 'data', 'sensor'))
    if ($present.Count -eq 0) { Write-Host 'Nothing of an RCEGuard installation is on this machine.' }
    else { Write-Host "$($present.Count) of $($traces.Count) are present." }
    Write-Host "Not counted: Sysmon's autologger entry in the registry ($(Get-AutologgerNote 'now'))."
    return
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $AllowNonAdmin) {
    throw 'Run this script in a PowerShell started as administrator (or with -ListOnly to only look).'
}

$client = Join-Path $TestDir 'Wow.exe'
if (-not (Test-Path -LiteralPath $client -PathType Leaf)) {
    throw "Simulator not found: '$client'. Publish it with: dotnet publish src\RCEGuard.FakeWow -c Release -o $TestDir"
}
$ServicePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ServicePath)
if (-not (Test-Path -LiteralPath (Join-Path $ServicePath $script:GuardExeName) -PathType Leaf)) {
    throw "No published service in '$ServicePath'. Publish it first with '.\build.ps1 -Publish'."
}
# The file whose absence makes the service process die at once.
$neededFile = 'RCEGuard.Core.dll'
if (-not (Test-Path -LiteralPath (Join-Path $ServicePath $neededFile) -PathType Leaf)) {
    throw "'$neededFile' is not in '$ServicePath'; step A of this test removes it from a copy to break the service."
}

$before = @(Get-InstallationTraces)
$autologger = @(Get-AutologgerNote 'before the test')
# The file of Sysmon's log and the licence note may be there from an earlier Sysmon of the owner:
# they are not ours, must survive the test, and so are allowed to be there.
$blocking = @(Get-PresentNames $before @('guard', 'data', 'sensor') | Where-Object { $_ -notin @('Sysmon event log file', 'Sysinternals licence note (this user)') })
if ($blocking.Count -gt 0 -and -not $AllowNonAdmin) {
    throw "This test needs a machine without RCEGuard and without Sysmon, because it removes both at the end. Found: $($blocking -join '; '). Run uninstall.ps1 first."
}

$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$resultFile = Join-Path $OutDir 'install-test-result.txt'
$statePath = Join-Path $DataDir 'install-state.json'
$brokenConfig = Join-Path $DataDir 'appsettings.json'
$brokenService = Join-Path ([IO.Path]::GetTempPath()) ("rceguard-broken-service-" + [guid]::NewGuid().ToString('N'))

$checks = @()
# What install.ps1 and uninstall.ps1 said when they stopped, in full: the table only has room for the first line.
$messages = @()
function Add-Message([string] $step, [string] $text) {
    if ($text) { $script:messages += "--- $step ---`n$text" }
}
function Add-Check([string] $step, [string] $check, [bool] $ok, [string] $value = '') {
    $script:checks += [pscustomobject]@{ Step = $step; Check = $check; Value = $value; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }) }
}

function Invoke-Install([string] $servicePath) {
    # Returns the error message of install.ps1, or $null if it succeeded.
    try {
        & $InstallScript -ClientPath $client -ServicePath $servicePath -DownloadSysmon -AcceptSysmonEula | Out-Host
        return $null
    }
    catch {
        Write-Host "install.ps1 stopped: $($_.Exception.Message)" -ForegroundColor DarkYellow
        return [string] $_.Exception.Message
    }
}

function First-Line([string] $text) {
    if (-not $text) { return '' }
    $line = @($text -split "`r?`n" | Where-Object { $_.Trim() })[0]
    if ($line.Length -gt 110) { $line.Substring(0, 110) + '...' } else { $line }
}

function Test-FailedStart([string] $step, [string] $message, [string] $expectedReason) {
    # What must be true after an installation whose service could not start.
    Add-Check $step 'install.ps1 reports the failure' ([bool] $message) (First-Line $message)
    Add-Check $step 'the message names the reason' ($message -match $expectedReason) $expectedReason
    Add-Check $step 'the message says the service was removed' ($message -match 'The service was removed again')

    $traces = @(Get-InstallationTraces)
    $guardLeft = @(Get-PresentNames $traces @('guard'))
    Add-Check $step 'nothing of the service is left' ($guardLeft.Count -eq 0) $(if ($guardLeft.Count) { $guardLeft -join '; ' } else { 'service, process, folder and event sources are gone' })
    $sensor = @(Get-PresentNames $traces @('sensor'))
    Add-Check $step 'the sensor stays installed' ('Sysmon service' -in $sensor -and 'Sysmon driver' -in $sensor)

    $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { $null }
    $noted = $null -ne $state -and -not [bool] (Get-StateValue $state 'serviceInstalled' $true)
    Add-Check $step 'install-state.json says: no service' $noted $(if ($null -eq $state) { 'no state file' } else { "serviceInstalled = $(Get-StateValue $state 'serviceInstalled' '?')" })

    # Windows restarts a failed service after 5 s. Nothing may come back.
    Write-Host 'Waiting 8 s to see whether Windows starts the service again ...'
    Start-Sleep -Seconds 8
    $back = @(Get-PresentNames @(Get-InstallationTraces) @('guard'))
    Add-Check $step 'nothing came back after 8 s' ($back.Count -eq 0) $(if ($back.Count) { $back -join '; ' } else { '' })
}

$unexpected = $null
try {
    # --- A. A published service that lacks a file -------------------------------------------------
    Write-Host ''
    Write-Host "A. Installing with a service that cannot start (a copy without $neededFile) ..." -ForegroundColor Cyan
    Copy-Item -LiteralPath $ServicePath -Destination $brokenService -Recurse
    Remove-Item -LiteralPath (Join-Path $brokenService $neededFile) -Force
    $message = Invoke-Install $brokenService
    Add-Message 'A: install.ps1' $message
    Test-FailedStart 'A' $message 'could not be started|ended right after it was started|did not start watching'
    if (-not $AllowNonAdmin -and 'Sysmon service' -notin @(Get-PresentNames @(Get-InstallationTraces) @('sensor'))) {
        throw "Sysmon is not installed after step A, so the other steps cannot run. install.ps1 said: $message"
    }

    # --- B. A configuration the service cannot read -----------------------------------------------
    Write-Host ''
    Write-Host 'B. Installing with a configuration file that is not valid JSON ...' -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
    Set-Content -LiteralPath $brokenConfig -Value '{ "profiles": [ { "name": "Default", ' -Encoding UTF8
    try {
        $message = Invoke-Install $ServicePath
        Add-Message 'B: install.ps1' $message
        Test-FailedStart 'B' $message 'cannot run'
        Add-Check 'B' 'the message quotes the log of the service' ($message -match 'not valid JSON')
    }
    finally {
        Remove-Item -LiteralPath $brokenConfig -Force -ErrorAction SilentlyContinue
    }

    # --- C. Without a fault -----------------------------------------------------------------------
    Write-Host ''
    Write-Host 'C. Installing without a fault ...' -ForegroundColor Cyan
    $message = Invoke-Install $ServicePath
    Add-Message 'C: install.ps1' $message
    Add-Check 'C' 'install.ps1 succeeds after the failed attempts' (-not $message) (First-Line $message)
    $service = Get-GuardService
    $running = $null -ne $service -and $service.State -eq 'Running'
    Add-Check 'C' 'the service runs' $running $(if ($null -eq $service) { 'no such service' } else { "$($service.State), start mode $($service.StartMode), pid $($service.ProcessId)" })
    Add-Check 'C' 'the service starts with Windows' ($null -ne $service -and $service.StartMode -eq 'Auto') $(if ($null -ne $service) { $service.StartMode } else { '' })
    $autologger += Get-AutologgerNote 'while installed'

    # --- D. Remove everything ---------------------------------------------------------------------
    Write-Host ''
    Write-Host 'D. Removing RCEGuard ...' -ForegroundColor Cyan
    $removeError = $null
    try { & $UninstallScript | Out-Host } catch { $removeError = [string] $_.Exception.Message; Write-Host "uninstall.ps1 stopped: $removeError" -ForegroundColor DarkYellow }
    Add-Message 'D: uninstall.ps1' $removeError
    Add-Check 'D' 'uninstall.ps1 succeeds' (-not $removeError) (First-Line $removeError)
    $after = @(Get-InstallationTraces)
    $autologger += Get-AutologgerNote 'after uninstall.ps1'
    $beforeNames = @(Get-PresentNames $before @('guard', 'data', 'sensor'))
    $afterNames = @(Get-PresentNames $after @('guard', 'data', 'sensor'))
    $added = @($afterNames | Where-Object { $_ -notin $beforeNames })
    $missing = @($beforeNames | Where-Object { $_ -notin $afterNames })
    Add-Check 'D' 'nothing of the installation is left' ($added.Count -eq 0) $(if ($added.Count) { $added -join '; ' } else { 'the machine looks as before the test' })
    Add-Check 'D' 'what was there before is still there' ($missing.Count -eq 0) $(if ($missing.Count) { "gone: $($missing -join '; ')" } elseif ($beforeNames.Count) { $beforeNames -join '; ' } else { 'nothing was there before' })
}
catch {
    $unexpected = [string] $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $brokenConfig -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $brokenService) { Remove-Item -LiteralPath $brokenService -Recurse -Force -ErrorAction SilentlyContinue }
}

$failed = @($checks | Where-Object { $_.Result -eq 'FAIL' }).Count
$verdict =
    if ($unexpected) { "STOPPED: $unexpected" }
    elseif ($failed -eq 0) { 'ALL PASSED' }
    else { "$failed FAILED" }
$leftNow = @(Get-PresentNames @(Get-InstallationTraces) @('guard', 'data', 'sensor'))
$report = @(
    "RCEGuard install test, $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Client: $client    Service from: $ServicePath"
    ''
    ($checks | Format-Table Step, Check, Value, Result -AutoSize -Wrap | Out-String -Width 220).Trim()
    ''
    "Verdict: $verdict"
    "On the machine now: $(if ($leftNow.Count) { $leftNow -join '; ' } else { 'nothing of an RCEGuard installation' })"
    "Sysmon's autologger entry in the registry (not counted): $($autologger -join '; ')"
)
if ($messages.Count -gt 0) {
    $report += ''
    $report += 'What the scripts said when they stopped:'
    $report += $messages
}
$report | Set-Content -LiteralPath $resultFile -Encoding UTF8
Write-Host ''
$report | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host "Result written to $resultFile"
if ($unexpected -or $failed -gt 0) {
    if ($leftNow.Count -gt 0) { Write-Host 'RCEGuard may still be installed. Remove it with: .\scripts\uninstall.ps1' -ForegroundColor Yellow }
    exit 1
}
