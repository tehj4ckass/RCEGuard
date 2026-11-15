#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs RCEGuard: the Sysmon sensor for one game client and the guard service that reacts to it.

.DESCRIPTION
    The script
      1. creates C:\ProgramData\RCEGuard, writable by administrators only,
      2. renders the Sysmon configuration for the given client,
      3. installs Sysmon with it, or loads it into a Sysmon that RCEGuard installed earlier,
      4. with -BlockChildProcesses: tells Windows Exploit Protection that the client may not
         start other programs,
      5. copies the published guard service to C:\Program Files\RCEGuard and registers it as the
         Windows service 'RCEGuard': LocalSystem, automatic start, depends on Sysmon, restarted by
         Windows after a failure. Publish the service first with '.\build.ps1 -Publish'.

    Running the script again points the sensor at another client and updates the service.
    -SkipService installs only the sensor.

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

.PARAMETER ServicePath
    Folder with the published service; default is artifacts\service of this repository.

.PARAMETER SkipService
    Installs only the sensor. A guard service that is already installed is kept and restarted.

.PARAMETER BlockChildProcesses
    Turns on the Exploit Protection setting "Do not allow child processes" for the client: Windows
    then refuses when the client tries to start another program. Off unless asked for, because it
    can break things a client does on purpose (opening a link, a crash reporter, a launcher):
    try the client with it before relying on it. It applies from the next start of the client.
    Once turned on it stays on when the script is run again without the switch; turn it off with
    -AllowChildProcesses. uninstall.ps1 puts the setting back as it was.

.PARAMETER AllowChildProcesses
    Takes back what -BlockChildProcesses did: the setting goes back to what it was before.

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
    [switch] $ReplaceExistingConfig,
    [string] $ServicePath,
    [switch] $SkipService,
    [switch] $BlockChildProcesses,
    [switch] $AllowChildProcesses
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:ProgramData 'RCEGuard'
$configPath = Join-Path $dataDir 'sysmon-config.xml'
$statePath = Join-Path $dataDir 'install-state.json'
$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'

. (Join-Path $PSScriptRoot 'SysmonTools.ps1')
. (Join-Path $PSScriptRoot 'GuardServiceTools.ps1')
. (Join-Path $PSScriptRoot 'ExploitProtectionTools.ps1')

# Check this before anything on the machine is changed.
if ($BlockChildProcesses -and $AllowChildProcesses) {
    throw 'Use either -BlockChildProcesses or -AllowChildProcesses, not both.'
}
if (-not $SkipService) {
    # Not a param default: under 'powershell.exe -File' $PSScriptRoot is still empty in the param block.
    if (-not $ServicePath) { $ServicePath = Join-Path $PSScriptRoot '..\artifacts\service' }
    $ServicePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ServicePath)
    if (-not (Test-Path -LiteralPath (Join-Path $ServicePath $script:GuardExeName) -PathType Leaf)) {
        throw "No published service in '$ServicePath'. Publish it first with '.\build.ps1 -Publish' (no admin rights needed), or pass -SkipService to install only the sensor."
    }
}

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
# What 'sysmon -u' will leave behind later. uninstall.ps1 removes it only if this installation brought it.
$sysmonLogFileCreated = $false
$sysmonEulaKeyCreated = $false
$installedBySid = ''

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
    if ($ours) {
        $sysmonLogFileCreated = [bool] (Get-StateValue $state 'sysmonLogFileCreated')
        $sysmonEulaKeyCreated = [bool] (Get-StateValue $state 'sysmonEulaKeyCreated')
        $installedBySid = [string] (Get-StateValue $state 'installedBySid' '')
    }
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

    $logFileBefore = Test-Path -LiteralPath $script:SysmonLogFile
    $eulaKeyBefore = Test-Path -LiteralPath $script:SysmonEulaKey
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
        # Nothing was installed: do not leave what the attempt wrote, nor the data folder of a sensor that does not exist.
        foreach ($problem in @(Remove-SysmonTraces (-not $logFileBefore) (-not $eulaKeyBefore))) { Write-Warning $problem }
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
    $sysmonLogFileCreated = -not $logFileBefore
    $sysmonEulaKeyCreated = -not $eulaKeyBefore
    # The licence note lies in the registry of the user who runs this script; only that user's uninstall removes it.
    $installedBySid = Get-CurrentUserSid
    Write-Host "Sysmon installed (service '$($installed.ServiceName)')."
}

# --- 4. Exploit Protection: the client may not start other programs ----------------------------
# Without the switch the setting stays as the last run of this script left it.
$blockWanted =
    if ($BlockChildProcesses) { $true }
    elseif ($AllowChildProcesses) { $false }
    else { [bool] [string] (Get-StateValue $state 'childProcessBlockPath' '') }
$block = Update-ChildProcessBlock `
    ([string] (Get-StateValue $state 'childProcessBlockPath' '')) `
    ([string] (Get-StateValue $state 'childProcessBlockBefore' 'NOTSET')) `
    ([bool] (Get-StateValue $state 'childProcessBlockEntryBefore' $false)) `
    ([IO.Path]::GetFullPath($ClientPath)) `
    $blockWanted

# --- 5. Remember what was done, for uninstall.ps1 and for the service --------------------------
# The service reads the client path from this file when it starts, so it is written first.
$replaced = [bool] ($replacedForeignConfig -or ($null -ne $state -and $state.replacedForeignConfig))
function Write-InstallState([bool] $serviceInstalled) {
    [ordered]@{
        clientPath                = [IO.Path]::GetFullPath($ClientPath)
        sysmonServiceName         = $installed.ServiceName
        sysmonExe                 = $installed.Exe
        sysmonInstalledByRceGuard = [bool] $sysmonInstalledByRceGuard
        sysmonLogFileCreated      = [bool] $sysmonLogFileCreated
        sysmonEulaKeyCreated      = [bool] $sysmonEulaKeyCreated
        installedBySid            = [string] $installedBySid
        replacedForeignConfig     = $replaced
        # The client RCEGuard turned "Do not allow child processes" on for ('' if none), and what the setting was before.
        childProcessBlockPath     = [string] $block.Path
        childProcessBlockBefore   = [string] $block.Before
        # Whether Windows had an Exploit Protection entry for that client before; if not, the entry goes completely.
        childProcessBlockEntryBefore = [bool] $block.EntryBefore
        serviceInstalled          = $serviceInstalled
        updatedUtc                = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
}

$existingService = Get-GuardService
$serviceIsOurs = $null -ne $existingService -and (Test-GuardServiceIsOurs $existingService)
Write-InstallState $serviceIsOurs

if ($block.Problem) {
    # After the state was written: it says how far the change got, so the next run and uninstall.ps1 can go on from there.
    throw "The Exploit Protection setting could not be changed: $($block.Problem)`nThe sensor is installed; the guard service was not touched. Fix the cause and run install.ps1 again."
}

Write-Host ''
Write-Host "RCEGuard sensor is active for '$([IO.Path]::GetFullPath($ClientPath))'."

# --- 6. The guard service ----------------------------------------------------------------------
if (-not $SkipService) {
    Install-GuardService $ServicePath $installed.ServiceName $dataDir
    Write-InstallState $true
    Write-Host "RCEGuard service is running (Windows service '$script:GuardServiceName', LocalSystem, starts with Windows)."
    Write-Host "Its log: $(Join-Path $dataDir $script:GuardLogName)"
}
elseif ($serviceIsOurs) {
    # The service only reads the client path when it starts.
    Restart-GuardService $dataDir
    Write-Host 'RCEGuard service restarted with the new settings.'
}
else {
    Write-Host 'The guard service was not installed (-SkipService). Watch the events with: .\show-events.ps1 -Follow'
}
