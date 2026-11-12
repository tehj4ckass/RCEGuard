#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the RCEGuard sensor again.

.DESCRIPTION
    Uses C:\ProgramData\RCEGuard\install-state.json written by install.ps1:
      - Sysmon is uninstalled only if RCEGuard installed it.
      - If RCEGuard replaced the rules of a Sysmon that was already there, Sysmon stays
        installed and is reset to its default rules; the earlier rules were dumped to
        C:\ProgramData\RCEGuard\sysmon-rules-before-rceguard-*.txt and must be reloaded by hand.
    The data folder is removed unless -KeepData is given or such a dump exists.

.PARAMETER KeepData
    Keeps C:\ProgramData\RCEGuard (configuration, state, dumps).
#>
[CmdletBinding()]
param(
    [switch] $KeepData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:ProgramData 'RCEGuard'
$statePath = Join-Path $dataDir 'install-state.json'

if (-not (Test-Path -LiteralPath $statePath)) {
    Write-Host "No RCEGuard installation found ('$statePath' is missing). Nothing to do."
    return
}

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$sysmonExe = $state.sysmonExe
$sysmonPresent = $sysmonExe -and (Test-Path -LiteralPath $sysmonExe -PathType Leaf)

. (Join-Path $PSScriptRoot 'SysmonTools.ps1')

if (-not $sysmonPresent) {
    Write-Warning "Sysmon binary '$sysmonExe' not found; it seems to have been removed already."
}
elseif ($state.sysmonInstalledByRceGuard) {
    Invoke-Sysmon $sysmonExe @('-u') 'Sysmon uninstall' | Out-Null
    # 'sysmon -u' removes service and driver but leaves its own binary in the Windows folder.
    $windowsDir = [IO.Path]::GetFullPath($env:windir).TrimEnd('\')
    $leftInWindows = [string]::Equals([IO.Path]::GetDirectoryName($sysmonExe), $windowsDir, [StringComparison]::OrdinalIgnoreCase)
    if ($leftInWindows -and (Test-Path -LiteralPath $sysmonExe -PathType Leaf)) {
        Remove-Item -LiteralPath $sysmonExe -Force
    }
    Write-Host 'Sysmon uninstalled.'
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
