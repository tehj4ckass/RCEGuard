#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the RCEGuard sensor: Sysmon with a configuration that only watches one game client.

.DESCRIPTION
    Milestone M1 (sensor only). The script
      1. renders the Sysmon configuration for the given client,
      2. installs Sysmon with it, or loads it into a Sysmon that RCEGuard installed earlier,
      3. creates C:\ProgramData\RCEGuard, writable by administrators only.

    Sysmon has one configuration per machine. If a Sysmon that RCEGuard did not install is
    already present, the script stops, because loading this configuration would replace the
    existing one. -ReplaceExistingConfig overrides that; the old rules are dumped to a text
    file first, but they cannot be restored automatically.

    Sysmon 15 sometimes fails to register its event manifest on recent Windows builds
    ("wevtutil.exe returned failure", exit code 13). The script then removes what the attempt
    left behind and tries once more; if that fails too, it leaves nothing behind and asks for a
    restart.

    Sysmon is not shipped with RCEGuard. Pass a Sysmon64.exe you downloaded from Microsoft
    with -SysmonPath, or let the script fetch it from download.sysinternals.com with
    -DownloadSysmon. Installing Sysmon requires accepting the Sysinternals licence terms
    (https://learn.microsoft.com/sysinternals/license-terms); confirm that with
    -AcceptSysmonEula.

.EXAMPLE
    .\install.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -DownloadSysmon -AcceptSysmonEula

.EXAMPLE
    .\install.ps1 -ClientPath 'C:\RCEGuardTest\Wow.exe'
    Points an already installed RCEGuard sensor at another client (e.g. the simulator).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ClientPath,
    [string] $SysmonPath,
    [switch] $DownloadSysmon,
    [switch] $AcceptSysmonEula,
    [switch] $ReplaceExistingConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:ProgramData 'RCEGuard'
$configPath = Join-Path $dataDir 'sysmon-config.xml'
$statePath = Join-Path $dataDir 'install-state.json'
$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'

. (Join-Path $PSScriptRoot 'SysmonTools.ps1')

function Assert-MicrosoftSigned([string] $path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "'$path' is not a validly signed Microsoft binary (status: $($signature.Status)). Aborting."
    }
}

# --- 1. Data folder, writable by administrators and SYSTEM only -------------------------------
if (-not (Test-Path -LiteralPath $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
}
# Well-known SIDs instead of names, so this works on every Windows language.
& icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set the access rights on '$dataDir'." }

$state = if (Test-Path -LiteralPath $statePath) {
    Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
} else {
    $null
}

# --- 2. Render the configuration ---------------------------------------------------------------
& (Join-Path $PSScriptRoot 'render-config.ps1') -ClientPath $ClientPath -OutFile $configPath

# --- 3. Install Sysmon or update its configuration ---------------------------------------------
$installed = Get-InstalledSysmon
$sysmonInstalledByRceGuard = $false
$replacedForeignConfig = $false

if ($null -ne $installed) {
    $ours = $null -ne $state -and $state.sysmonInstalledByRceGuard
    if (-not $ours -and -not $ReplaceExistingConfig) {
        throw @"
Sysmon is already installed on this machine (service '$($installed.ServiceName)') and was not installed by RCEGuard.
Loading the RCEGuard configuration would replace its current rules.
Merge '$configPath' into your own configuration, or run again with -ReplaceExistingConfig.
"@
    }
    if (-not $ours) {
        $backup = Join-Path $dataDir ("sysmon-rules-before-rceguard-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
        Invoke-Sysmon $installed.Exe @('-c') | Set-Content -LiteralPath $backup -Encoding UTF8
        Write-Warning "Existing Sysmon rules dumped to '$backup'. They are replaced now and are not restored by uninstall.ps1."
        $replacedForeignConfig = $true
    }
    $sysmonInstalledByRceGuard = $ours
    Invoke-Sysmon $installed.Exe @('-c', $configPath) | Out-Null
    Write-Host "Sysmon configuration updated (service '$($installed.ServiceName)')."
}
else {
    if (-not $AcceptSysmonEula) {
        throw "Sysmon is not installed. Installing it requires -AcceptSysmonEula (https://learn.microsoft.com/sysinternals/license-terms)."
    }
    if ($SysmonPath -and $DownloadSysmon) {
        throw 'Use either -SysmonPath or -DownloadSysmon, not both.'
    }
    if (-not $SysmonPath -and -not $DownloadSysmon) {
        throw "Sysmon is not installed. Pass -SysmonPath <Sysmon64.exe> or -DownloadSysmon (downloads $sysmonUrl)."
    }

    $tempDir = $null
    try {
        if ($DownloadSysmon) {
            $tempDir = Join-Path ([IO.Path]::GetTempPath()) ("rceguard-sysmon-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $tempDir | Out-Null
            $zip = Join-Path $tempDir 'Sysmon.zip'
            Write-Host "Downloading $sysmonUrl ..."
            Invoke-WebRequest -Uri $sysmonUrl -OutFile $zip -UseBasicParsing
            Expand-Archive -LiteralPath $zip -DestinationPath $tempDir
            $SysmonPath = Join-Path $tempDir 'Sysmon64.exe'
        }
        if (-not (Test-Path -LiteralPath $SysmonPath -PathType Leaf)) {
            throw "Sysmon binary not found: '$SysmonPath'."
        }
        Assert-MicrosoftSigned $SysmonPath
        Install-SysmonWithRetry $SysmonPath $configPath
    }
    catch {
        # Nothing was installed: do not leave the data folder of a sensor that does not exist.
        if (-not (Test-Path -LiteralPath $statePath)) {
            Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
            if (@(Get-ChildItem -LiteralPath $dataDir -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item -LiteralPath $dataDir -Force -ErrorAction SilentlyContinue
            }
        }
        throw
    }
    finally {
        if ($tempDir -and (Test-Path -LiteralPath $tempDir)) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force
        }
    }

    $installed = Get-InstalledSysmon
    if ($null -eq $installed) { throw 'Sysmon reported success, but its service was not found afterwards.' }
    $sysmonInstalledByRceGuard = $true
    Write-Host "Sysmon installed (service '$($installed.ServiceName)')."
}

# --- 4. Remember what was done, for uninstall.ps1 ----------------------------------------------
[ordered]@{
    clientPath                = [IO.Path]::GetFullPath($ClientPath)
    sysmonServiceName         = $installed.ServiceName
    sysmonExe                 = $installed.Exe
    sysmonInstalledByRceGuard = [bool] $sysmonInstalledByRceGuard
    replacedForeignConfig     = [bool] ($replacedForeignConfig -or ($null -ne $state -and $state.replacedForeignConfig))
    updatedUtc                = (Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

Write-Host ''
Write-Host "RCEGuard sensor is active for '$([IO.Path]::GetFullPath($ClientPath))'."
Write-Host "Watch the events with: .\show-events.ps1 -Follow"
