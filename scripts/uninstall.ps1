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

function Invoke-Sysmon([string] $exe, [string[]] $arguments, [string] $what) {
    # Windows PowerShell 5.1 turns redirected stderr lines into terminating errors under 'Stop'.
    $ErrorActionPreference = 'Continue'
    $output = & $exe @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$what failed (exit code $LASTEXITCODE):`n$($output -join "`n")"
    }
}

if (-not $sysmonPresent) {
    Write-Warning "Sysmon binary '$sysmonExe' not found; it seems to have been removed already."
}
elseif ($state.sysmonInstalledByRceGuard) {
    Invoke-Sysmon $sysmonExe @('-u') 'Sysmon uninstall'
    Write-Host 'Sysmon uninstalled.'
}
else {
    Invoke-Sysmon $sysmonExe @('-c', '--') 'Resetting the Sysmon configuration'
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
