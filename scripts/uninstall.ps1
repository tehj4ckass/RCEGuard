#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes RCEGuard again: the guard service and the sensor.

.DESCRIPTION
    First stops and removes the Windows service 'RCEGuard', C:\Program Files\RCEGuard and the
    registrations of the service as a source of the Windows Application log.
    Then uses C:\ProgramData\RCEGuard\install-state.json written by install.ps1:
      - If install.ps1 -BlockChildProcesses turned on the Exploit Protection setting "Do not
        allow child processes" for the client, the setting is put back to what it was before.
      - Sysmon is uninstalled only if RCEGuard installed it. What Sysmon leaves behind then goes
        too, if the installation brought it: the file of its event log (everything it recorded)
        and the note in the registry that the Sysinternals licence was accepted.
      - If RCEGuard replaced the rules of a Sysmon that was already there, Sysmon stays
        installed and is reset to its default rules; the earlier rules were dumped to
        C:\ProgramData\RCEGuard\sysmon-rules-before-rceguard-*.txt and must be reloaded by hand.
    The data folder is removed unless -KeepData is given or such a dump exists.
    What the service wrote to the Windows Application log stays there; Windows keeps that log.

    If removing Sysmon fails, the reason is also written to C:\ProgramData\RCEGuard\uninstall.log.

.PARAMETER KeepData
    Keeps C:\ProgramData\RCEGuard (configuration, findings database, log, dumps) and the file of
    Sysmon's event log.

.PARAMETER RemoveStuckSysmonService
    Only for one case, and uninstall.ps1 says so when it meets it: Sysmon ended in the middle of
    its own uninstall and left its service registered. That service is protected by Windows, and
    nothing can remove it the regular way any more. With this switch the script deletes the
    registration of the service from the registry (HKLM\SYSTEM\CurrentControlSet\Services) and
    stops. Windows drops the service when it is restarted; run uninstall.ps1 again after that.
#>
[CmdletBinding()]
param(
    [switch] $KeepData,
    [switch] $RemoveStuckSysmonService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:ProgramData 'RCEGuard'
$statePath = Join-Path $dataDir 'install-state.json'
$logPath = Join-Path $dataDir 'uninstall.log'

function Add-UninstallLog([string[]] $lines) {
    # Best effort: what is on the screen is gone when the window closes, this stays with the data.
    try {
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Add-Content -LiteralPath $logPath -Value (@("=== $stamp") + $lines) -Encoding UTF8 -ErrorAction Stop
    }
    catch { Write-Verbose "Could not write '$logPath': $($_.Exception.Message)" }
}

. (Join-Path $PSScriptRoot 'SysmonTools.ps1')
. (Join-Path $PSScriptRoot 'GuardServiceTools.ps1')
. (Join-Path $PSScriptRoot 'ExploitProtectionTools.ps1')

# The guard service goes first: it depends on Sysmon and keeps files in the data folder open.
# It is removed even without a state file, so a broken installation can always be cleaned up.
$serviceRemoved = Uninstall-GuardService
if ($serviceRemoved) {
    Write-Host "RCEGuard service removed (Windows service '$script:GuardServiceName', '$script:GuardInstallDir')."
}

if (-not (Test-Path -LiteralPath $statePath)) {
    if ($serviceRemoved) {
        Write-Host "No sensor installation found ('$statePath' is missing); nothing else to do."
    }
    else {
        Write-Host "No RCEGuard installation found ('$statePath' is missing). Nothing to do."
    }
    return
}

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json

# Exploit Protection: back to what it was before install.ps1 -BlockChildProcesses.
$blockPath = [string] (Get-StateValue $state 'childProcessBlockPath' '')
if ($blockPath) {
    $blockBefore = [string] (Get-StateValue $state 'childProcessBlockBefore' 'NOTSET')
    $blockEntryBefore = [bool] (Get-StateValue $state 'childProcessBlockEntryBefore' $false)
    try {
        # Not again if an earlier run of this script, one that stopped later on, has done it already.
        if ((Get-ChildProcessBlock $blockPath) -eq 'ON' -or (-not $blockEntryBefore -and (Test-ExploitProtectionEntry $blockPath))) {
            Restore-ChildProcessBlock $blockPath $blockBefore $blockEntryBefore
            Write-Host "Exploit Protection: '$blockPath' may start other programs again (setting back to '$blockBefore')."
        }
    }
    catch {
        # Not a reason to leave the rest installed: the setting is one command away, and this warning names it.
        Write-Warning "The Exploit Protection setting of '$blockPath' could not be put back: $($_.Exception.Message)"
        Write-Warning "The client still may not start other programs. To change that by hand, run as administrator: Set-ProcessMitigation -Name '$blockPath' -Remove -Disable $script:ChildProcessMitigation"
    }
}

$sysmonExe = $state.sysmonExe
$sysmonPresent = $sysmonExe -and (Test-Path -LiteralPath $sysmonExe -PathType Leaf)

if (-not $sysmonPresent) {
    Write-Warning "Sysmon binary '$sysmonExe' not found; it seems to have been removed already."
}
elseif ($state.sysmonInstalledByRceGuard) {
    try { $sysmonResult = Uninstall-Sysmon $sysmonExe $RemoveStuckSysmonService.IsPresent }
    catch {
        Add-UninstallLog (@($script:SysmonUninstallNotes) + @("FAILED: $($_.Exception.Message)"))
        throw
    }
    if ($sysmonResult -eq 'restart') {
        Add-UninstallLog (@($script:SysmonUninstallNotes) + @('Waiting for a restart of Windows.'))
        Write-Warning 'The registration of the Sysmon service was deleted from the registry. Windows still lists the service until it is restarted.'
        Write-Host "Restart Windows now ('Restart', not 'Shut down'), then run uninstall.ps1 again to remove the rest."
        return
    }
    # 'sysmon -u' removes service and driver but leaves its own binary in the Windows folder.
    $windowsDir = [IO.Path]::GetFullPath($env:windir).TrimEnd('\')
    $leftInWindows = [string]::Equals([IO.Path]::GetDirectoryName($sysmonExe), $windowsDir, [StringComparison]::OrdinalIgnoreCase)
    if ($leftInWindows -and (Test-Path -LiteralPath $sysmonExe -PathType Leaf)) {
        Remove-Item -LiteralPath $sysmonExe -Force
    }
    Write-Host 'Sysmon uninstalled.'

    # 'sysmon -u' also leaves the file of its event log and the licence note. They go if this
    # installation brought them; what was there before belongs to someone else.
    $logIsOurs = [bool] (Get-StateValue $state 'sysmonLogFileCreated')
    $eulaIsOurs = [bool] (Get-StateValue $state 'sysmonEulaKeyCreated')
    $sameUser = [string] (Get-StateValue $state 'installedBySid' '') -eq (Get-CurrentUserSid)
    foreach ($problem in @(Remove-SysmonTraces ($logIsOurs -and -not $KeepData) ($eulaIsOurs -and $sameUser))) { Write-Warning $problem }
    if ($logIsOurs -and $KeepData -and (Test-Path -LiteralPath $script:SysmonLogFile)) {
        Write-Host "Kept the event log file of Sysmon: '$script:SysmonLogFile'."
    }
    elseif ($logIsOurs -and -not (Test-Path -LiteralPath $script:SysmonLogFile)) {
        Write-Host 'Removed the event log file of Sysmon.'
    }
    if ($eulaIsOurs -and -not $sameUser) {
        Write-Warning "The note that the Sysinternals licence was accepted is in the registry of the user who installed RCEGuard ('$script:SysmonEulaKey' of that user). It stays; that user can delete the key."
    }
}
else {
    Invoke-Sysmon $sysmonExe @('-c', '--') 'Resetting the Sysmon configuration' | Out-Null
    Write-Host 'Sysmon was not installed by RCEGuard: it stays installed and is back on its default rules.'
}

$dumps = @(Get-ChildItem -LiteralPath $dataDir -Filter 'sysmon-rules-before-rceguard-*.txt' -ErrorAction SilentlyContinue)
if ($dumps.Count -gt 0) {
    Write-Warning "Your earlier Sysmon rules are in: $($dumps.FullName -join ', '). Reload your own configuration with 'sysmon -c <file>'."
    Remove-Item -LiteralPath $statePath -Force
    Write-Host "Kept '$dataDir' because it contains those dumps."
}
elseif ($KeepData) {
    Remove-Item -LiteralPath $statePath -Force
    Write-Host "Kept '$dataDir'."
}
else {
    Remove-Item -LiteralPath $dataDir -Recurse -Force
    Write-Host "Removed '$dataDir'."
}
