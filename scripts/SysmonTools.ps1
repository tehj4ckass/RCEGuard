# Shared Sysmon helpers for install.ps1 and uninstall.ps1. Dot-source this file; it does nothing by itself.

# Registration of Sysmon's event publisher. 'sysmon -i' writes it, 'sysmon -u' removes it.
$script:SysmonPublisherKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'

# What 'sysmon -u' leaves on the machine (seen with Sysmon 15.22 on 2026-11-13): the file of its
# event log, with everything it recorded, and the note that the licence was accepted.
$script:SysmonLogFile = Join-Path $env:windir 'System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx'
$script:SysmonEulaKey = 'HKCU:\Software\Sysinternals\System Monitor'

function Get-StateValue($state, [string] $name, $default = $false) {
    # A state file written by an earlier version of install.ps1 does not have every value.
    if ($null -ne $state -and $state.PSObject.Properties.Name -contains $name) { return $state.$name }
    return $default
}

function Get-CurrentUserSid {
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Remove-SysmonTraces([bool] $logFile, [bool] $eulaKey) {
    <#
        Removes what 'sysmon -u' leaves behind, as far as the caller says it is RCEGuard's to remove.
        Never throws: returns one line for everything that could not be removed.
    #>
    $problems = @()
    if ($logFile -and (Test-Path -LiteralPath $script:SysmonLogFile)) {
        try { Remove-Item -LiteralPath $script:SysmonLogFile -Force -ErrorAction Stop }
        catch { $problems += "The event log file of Sysmon, '$script:SysmonLogFile', could not be removed: $($_.Exception.Message) Delete it by hand after restarting Windows." }
    }
    if ($eulaKey -and (Test-Path -LiteralPath $script:SysmonEulaKey)) {
        try {
            Remove-Item -LiteralPath $script:SysmonEulaKey -Recurse -Force -ErrorAction Stop
            # The key above is shared by all Sysinternals tools: it only goes if nothing else is in it.
            $parent = Split-Path -Path $script:SysmonEulaKey -Parent
            $parentKey = Get-Item -LiteralPath $parent -ErrorAction SilentlyContinue
            if ($null -ne $parentKey -and $parentKey.SubKeyCount -eq 0 -and $parentKey.ValueCount -eq 0) {
                Remove-Item -LiteralPath $parent -Force -ErrorAction Stop
            }
        }
        catch { $problems += "The note that the Sysinternals licence was accepted, '$script:SysmonEulaKey', could not be removed: $($_.Exception.Message)" }
    }
    return $problems
}

function Invoke-SysmonRaw([string] $exe, [string[]] $arguments) {
    # Windows PowerShell 5.1 turns redirected stderr lines into terminating errors under 'Stop'.
    $ErrorActionPreference = 'Continue'
    $lines = @(& $exe @arguments 2>&1 | ForEach-Object { "$_" } |
        Where-Object { $_ -ne 'System.Management.Automation.RemoteException' })   # 5.1: an empty stderr line
    [pscustomobject]@{
        ExitCode    = $LASTEXITCODE
        Lines       = $lines
        Output      = ($lines -join "`n").Trim()
        CommandLine = "$exe $($arguments -join ' ')"
    }
}

function Invoke-Sysmon([string] $exe, [string[]] $arguments, [string] $what = 'Sysmon') {
    $result = Invoke-SysmonRaw $exe $arguments
    if ($result.ExitCode -ne 0) {
        throw "$what failed (exit code $($result.ExitCode)): $($result.CommandLine)`n$($result.Output)"
    }
    $result.Lines
}

function Get-SysmonPublisherBinary {
    # The binary the registered event publisher points to, or $null if no publisher is registered.
    if (-not (Test-Path -LiteralPath $script:SysmonPublisherKey)) { return $null }
    $key = Get-ItemProperty -LiteralPath $script:SysmonPublisherKey -ErrorAction SilentlyContinue
    if ($null -eq $key -or -not ($key.PSObject.Properties.Name -contains 'ResourceFileName')) { return '' }
    [string] $key.ResourceFileName
}

function Get-InstalledSysmon {
    # The service is named after the binary that installed it.
    $service = Get-CimInstance Win32_Service -Filter "Name='Sysmon64' OR Name='Sysmon' OR Name='Sysmon64a'" |
        Select-Object -First 1
    if ($null -eq $service) {
        # A renamed binary gives a renamed service; the event publisher still points to its binary.
        $binary = Get-SysmonPublisherBinary
        if ($binary) {
            $service = Get-CimInstance Win32_Service |
                Where-Object { $_.PathName -and [string]::Equals(($_.PathName -replace '^"([^"]+)".*$', '$1').Trim(), $binary, [StringComparison]::OrdinalIgnoreCase) } |
                Select-Object -First 1
        }
    }
    if ($null -eq $service) { return $null }
    $exe = ($service.PathName -replace '^"([^"]+)".*$', '$1').Trim()
    [pscustomobject]@{ ServiceName = $service.Name; Exe = $exe }
}

function Test-SysmonDriverPresent {
    # Also by its registration: Windows does not list the driver to everyone, and a registered driver is loaded again at the next start.
    ($null -ne (Get-CimInstance Win32_SystemDriver -Filter "Name='SysmonDrv'")) -or
        (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv')
}

function Get-SysmonRemains {
    # What of a Sysmon installation is still registered with Windows.
    $remains = @()
    if ($null -ne (Get-InstalledSysmon)) { $remains += 'service' }
    if (Test-SysmonDriverPresent) { $remains += 'driver' }
    if ($null -ne (Get-SysmonPublisherBinary)) { $remains += 'event publisher' }
    return $remains
}

function Wait-SysmonGone([int] $seconds = 10) {
    # Windows may take a moment to drop a service that was just removed. Returns what is still there after the wait.
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        $remains = @(Get-SysmonRemains)
        if ($remains.Count -eq 0 -or (Get-Date) -gt $deadline) { return $remains }
        Start-Sleep -Milliseconds 500
    }
}

function Uninstall-Sysmon([string] $exe) {
    <#
        Runs 'sysmon -u' and checks on the machine, not by the exit code, that Sysmon is gone.
        'sysmon -u' can fail half way: on 2026-11-13 the Sysmon 15.22 service crashed while it was
        being uninstalled (access violation), 'sysmon -u' ended with exit code 5, and the service
        stayed registered without its driver and its event publisher. So: look, and try once more.
        Throws with the output of both attempts if something is still there after that.
    #>
    $first = Invoke-SysmonRaw $exe @('-u')
    $remains = @(Wait-SysmonGone)
    if ($remains.Count -eq 0) {
        if ($first.ExitCode -ne 0) { Write-Warning "Sysmon ended its uninstall with exit code $($first.ExitCode), but nothing of it is left." }
        return
    }

    Write-Warning "Sysmon did not uninstall completely (exit code $($first.ExitCode); still there: $($remains -join ', ')). Trying once more ..."
    Start-Sleep -Seconds 3
    # 'force' goes on although parts are missing already. Not while the driver is still there:
    # forcing the removal of a loaded driver has restarted machines.
    $arguments = if ('driver' -in $remains) { @('-u') } else { @('-u', 'force') }
    $second = Invoke-SysmonRaw $exe $arguments
    $remains = @(Wait-SysmonGone)
    if ($remains.Count -eq 0) { return }

    throw @"
Sysmon could not be uninstalled completely; still there: $($remains -join ', ').
First attempt (exit code $($first.ExitCode)): $($first.CommandLine)
$($first.Output)
Second attempt (exit code $($second.ExitCode)): $($second.CommandLine)
$($second.Output)
Restart Windows and run uninstall.ps1 again. Nothing else was removed, so that it can go on from here.
"@
}

function Remove-SysmonLeftovers([string] $exe) {
    <#
        Cleans up what a failed 'sysmon -i' leaves behind: the event publisher is registered and the
        binary was copied to the Windows folder, but there is no service and no driver.
        Returns $true if something was removed.
    #>
    $binary = Get-SysmonPublisherBinary
    if ($null -eq $binary) { return $false }

    $installed = Get-InstalledSysmon
    if ($null -ne $installed) {
        throw "Sysmon is installed (service '$($installed.ServiceName)'); refusing to force an uninstall."
    }
    if (Test-SysmonDriverPresent) {
        # Forcing the removal of a loaded driver has restarted machines; that is the owner's call.
        throw @"
The Sysmon driver 'SysmonDrv' is present although no Sysmon service is installed.
RCEGuard does not force a driver removal. Restart Windows and run this script again.
"@
    }

    $result = Invoke-SysmonRaw $exe @('-u', 'force')
    if ($null -ne (Get-SysmonPublisherBinary)) {
        throw "Could not remove the leftovers of a failed Sysmon installation (exit code $($result.ExitCode)): $($result.CommandLine)`n$($result.Output)`nRestart Windows and run this script again."
    }

    # 'sysmon -u' leaves the copy of itself in the Windows folder. Remove it if it is the one the publisher named.
    $windowsDir = [IO.Path]::GetFullPath($env:windir).TrimEnd('\')
    if ($binary -and
        [string]::Equals([IO.Path]::GetDirectoryName($binary), $windowsDir, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($binary) -match '^Sysmon(64a?)?\.exe$' -and
        -not [string]::Equals($binary, $exe, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $binary -PathType Leaf)) {
        Remove-Item -LiteralPath $binary -Force
    }
    return $true
}

function Install-SysmonWithRetry([string] $exe, [string] $configPath) {
    <#
        Runs 'sysmon -i'. Sysmon 15 sometimes fails to register its event manifest on recent Windows
        builds (exit code 13, "wevtutil.exe returned failure") and leaves a half-registered publisher
        behind; a second attempt after removing that usually works. So: clean up, try once more, and
        leave nothing behind if that fails too.
    #>
    $arguments = @('-accepteula', '-i', $configPath)

    if (Remove-SysmonLeftovers $exe) {
        Write-Host 'Removed the leftovers of an earlier, failed Sysmon installation.'
    }

    $first = Invoke-SysmonRaw $exe $arguments
    if ($first.ExitCode -eq 0) { return }

    $manifestFailure = $first.Output -match 'Event manifest installation failed'
    $second = $null
    if ($manifestFailure) {
        Write-Warning 'Sysmon could not register its event manifest. Removing what the attempt left behind and trying once more ...'
        $null = Remove-SysmonLeftovers $exe
        Start-Sleep -Seconds 2
        $second = Invoke-SysmonRaw $exe $arguments
        if ($second.ExitCode -eq 0) { return }
    }

    # Failed for good: do not leave a half-installed sensor behind.
    $cleanupNote = ''
    try { $null = Remove-SysmonLeftovers $exe }
    catch { $cleanupNote = "`nCleaning up failed as well: $($_.Exception.Message)" }

    $message = "Sysmon failed (exit code $($first.ExitCode)): $($first.CommandLine)`n$($first.Output)"
    if ($null -ne $second) {
        $message += "`n`nSecond attempt after cleaning up (exit code $($second.ExitCode)):`n$($second.Output)"
        $message += "`n`nRestart Windows and run this script again."
    }
    throw ($message + $cleanupNote)
}
