# Helpers for the RCEGuard Windows service, shared by install.ps1, uninstall.ps1 and acceptance-test.ps1.
# Dot-source this file; it does nothing by itself.

$script:GuardServiceName = 'RCEGuard'
$script:GuardExeName = 'RCEGuard.Service.exe'
# Program Files: only administrators can write there. A service that runs as LocalSystem must never
# start from a folder a normal user can change.
$script:GuardInstallDir = Join-Path $env:ProgramFiles 'RCEGuard'
$script:GuardLogName = 'guard.log'

function Invoke-Sc([string[]] $arguments, [string] $what) {
    $ErrorActionPreference = 'Continue'
    $output = @(& sc.exe @arguments 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0) {
        throw "$what failed (sc.exe $($arguments -join ' '), exit code $LASTEXITCODE):`n$($output -join "`n")"
    }
}

function Get-GuardService {
    # $null if the service does not exist.
    Get-CimInstance Win32_Service -Filter "Name='$script:GuardServiceName'"
}

function Get-GuardServiceBinary($service) {
    ($service.PathName -replace '^"([^"]+)".*$', '$1').Trim()
}

function Test-GuardServiceIsOurs($service) {
    $expected = Join-Path $script:GuardInstallDir $script:GuardExeName
    [string]::Equals((Get-GuardServiceBinary $service), $expected, [StringComparison]::OrdinalIgnoreCase)
}

function Read-TextFrom([string] $path, [long] $offset) {
    # Reads what was appended after $offset; the service keeps the file open for writing.
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        if ($offset -gt $stream.Length) { $offset = 0 }   # the log was rotated
        $null = $stream.Seek($offset, [IO.SeekOrigin]::Begin)
        $reader = New-Object IO.StreamReader $stream
        return $reader.ReadToEnd()
    }
    finally { $stream.Dispose() }
}

function Get-FileLength([string] $path) {
    if (Test-Path -LiteralPath $path) { (Get-Item -LiteralPath $path).Length } else { [long] 0 }
}

function Stop-GuardService {
    $service = Get-Service -Name $script:GuardServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -eq 'Stopped') { return }
    Stop-Service -Name $script:GuardServiceName -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

function Start-GuardService([string] $dataDir) {
    <#
        Starts the service and waits until it reports that it is reading the Sysmon log.
        Throws with the service's own log lines if it does not get there.
    #>
    $logPath = Join-Path $dataDir $script:GuardLogName
    $offset = Get-FileLength $logPath
    try { Start-Service -Name $script:GuardServiceName -ErrorAction Stop }
    catch {
        throw "The service could not be started: $($_.Exception.Message)`nIts log ('$logPath') says:`n$((Read-TextFrom $logPath $offset).Trim())"
    }

    $deadline = (Get-Date).AddSeconds(30)
    while ($true) {
        $new = Read-TextFrom $logPath $offset
        if ($new -match 'Subscribed to') { return }
        $failed = $new -match 'RCEGuard cannot run'
        # A process that dies before it can log anything (a file of the service is missing, say) only
        # shows in the state of the service: Windows starts it again every few seconds, and in between it is stopped.
        $now = Get-GuardService
        $died = -not $failed -and ($null -eq $now -or $now.State -eq 'Stopped')
        if ($died) {
            # It may have said why in its last moment: look once more before calling it silent.
            Start-Sleep -Milliseconds 300
            $new = Read-TextFrom $logPath $offset
            $failed = $new -match 'RCEGuard cannot run'
            $died = -not $failed
        }
        if ($failed -or $died -or (Get-Date) -gt $deadline) {
            $reason =
                if ($failed) { 'The service reported that it cannot run.' }
                elseif ($died) { 'The service ended right after it was started.' }
                else { 'The service did not start watching within 30 s.' }
            throw "$reason Its log ('$logPath') says:`n$($new.Trim())"
        }
        Start-Sleep -Milliseconds 250
    }
}

function Install-GuardService([string] $sourceDir, [string] $sysmonServiceName, [string] $dataDir) {
    <#
        Copies the published service to Program Files, registers it as an automatic service running
        as LocalSystem that depends on Sysmon and is restarted after a failure, and starts it.
        Running it again updates the binaries.
    #>
    $sourceExe = Join-Path $sourceDir $script:GuardExeName
    if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
        throw "Published service not found: '$sourceExe'."
    }

    $existing = Get-GuardService
    if ($null -ne $existing -and -not (Test-GuardServiceIsOurs $existing)) {
        throw "A service named '$script:GuardServiceName' already exists and runs '$(Get-GuardServiceBinary $existing)'. RCEGuard did not install it and will not change it."
    }

    Stop-GuardService
    if (Test-Path -LiteralPath $script:GuardInstallDir) {
        Remove-Item -LiteralPath $script:GuardInstallDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:GuardInstallDir -Force | Out-Null
    Copy-Item -Path (Join-Path $sourceDir '*') -Destination $script:GuardInstallDir -Recurse -Force

    $exe = Join-Path $script:GuardInstallDir $script:GuardExeName
    # Quoted: an unquoted service path with a space lets Windows try 'C:\Program.exe' first.
    $binaryPath = "`"$exe`""
    if ($null -eq $existing) {
        New-Service -Name $script:GuardServiceName -BinaryPathName $binaryPath -DisplayName 'RCEGuard' `
            -Description 'Watches the game client from the outside and reacts to behaviour that points to remote code execution.' `
            -StartupType Automatic | Out-Null
    }
    # The binary path is not set through sc.exe: Windows PowerShell 5.1 mangles quotes inside arguments
    # of native programs. A new service gets it from New-Service; an existing one was checked above.
    Invoke-Sc @('config', $script:GuardServiceName, 'start=', 'auto', 'obj=', 'LocalSystem', 'depend=', $sysmonServiceName) 'Configuring the service'
    # Restart after a failure: twice after 5 s, then every minute; the counter resets after a day.
    Invoke-Sc @('failure', $script:GuardServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/60000') 'Setting the recovery actions'

    try { Start-GuardService $dataDir }
    catch {
        # A service that cannot run would be restarted by Windows over and over. Remove it again.
        $reason = $_.Exception.Message
        try { $null = Uninstall-GuardService }
        catch { throw "$reason`nRemoving the service failed as well: $($_.Exception.Message)`nRun uninstall.ps1 to remove what is left." }
        throw "$reason`nThe service was removed again; the sensor stays installed. Fix the cause and run install.ps1 again, or remove the sensor too with uninstall.ps1."
    }
}

function Restart-GuardService([string] $dataDir) {
    Stop-GuardService
    Start-GuardService $dataDir
}

# The running service registers itself as a source of the Windows Application log (the .NET service
# host does that): one name for "service started/stopped", one for its warnings and findings.
$script:GuardEventLogRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application'
$script:GuardEventSources = @('RCEGuard', 'RCEGuard.Service')

function Remove-GuardEventSources {
    # Returns $true if a registration was removed. The entries already in the Application log stay; Windows keeps them.
    $removed = $false
    foreach ($source in $script:GuardEventSources) {
        $key = Join-Path $script:GuardEventLogRoot $source
        if (Test-Path -LiteralPath $key) {
            Remove-Item -LiteralPath $key -Recurse -Force
            $removed = $true
        }
    }
    return $removed
}

function Get-GuardProcesses {
    # Processes running the installed service binary (not a build started from somewhere else).
    $exe = Join-Path $script:GuardInstallDir $script:GuardExeName
    @(Get-CimInstance Win32_Process -Filter "Name='$script:GuardExeName'" |
        Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $exe, [StringComparison]::OrdinalIgnoreCase) })
}

function Stop-GuardProcesses {
    foreach ($process in (Get-GuardProcesses)) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds(10)
    while (@(Get-GuardProcesses).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
}

function Uninstall-GuardService {
    <#
        Stops and removes the service, its folder in Program Files and its registrations as an
        event source. Returns $true if there was something to remove. A service of that name that
        RCEGuard did not install is left alone.
    #>
    $removed = $false
    $existing = Get-GuardService
    if ($null -ne $existing) {
        if (-not (Test-GuardServiceIsOurs $existing)) {
            Write-Warning "A service named '$script:GuardServiceName' runs '$(Get-GuardServiceBinary $existing)'. RCEGuard did not install it; it is left alone."
            return $false
        }
        # First make sure nothing starts it again. Windows restarts a service whose process died, and a
        # service that cannot run dies again and again: without this, such a restart can fall into the
        # middle of the removal. A disabled service is not started, by nobody.
        Invoke-Sc @('config', $script:GuardServiceName, 'start=', 'disabled') 'Disabling the service'
        # A service that is just starting or has just died cannot be stopped the regular way.
        try { Stop-GuardService } catch { Write-Verbose "Stopping the service the regular way failed: $($_.Exception.Message)" }
        Stop-GuardProcesses
        Invoke-Sc @('delete', $script:GuardServiceName) 'Removing the service'
        $deadline = (Get-Date).AddSeconds(15)
        while ($null -ne (Get-GuardService) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        $removed = $true
    }
    if (Test-Path -LiteralPath $script:GuardInstallDir) {
        # A process that has just ended may hold its files for a moment longer.
        $deadline = (Get-Date).AddSeconds(10)
        while ($true) {
            try { Remove-Item -LiteralPath $script:GuardInstallDir -Recurse -Force -ErrorAction Stop; break }
            catch {
                if ((Get-Date) -gt $deadline) { throw }
                Start-Sleep -Milliseconds 300
            }
        }
        $removed = $true
    }
    if (Remove-GuardEventSources) { $removed = $true }
    return $removed
}
