# Helpers for the tray application, shared by install.ps1, uninstall.ps1 and install-test.ps1.
# Dot-source this file; it does nothing by itself.
#
# The tray application is for the logged-on user and has no rights of its own. It gets a folder of
# its own in Program Files (not the folder of the service: that one is replaced whenever the
# service is installed, which fails while a program in it is running) and is started for every
# user at sign-in through the Run key of the machine.

$script:TrayExeName = 'RCEGuard.Tray.exe'
$script:TrayInstallDir = Join-Path $env:ProgramFiles 'RCEGuard Tray'
# Variables, so that a dry run can point them somewhere else.
$script:TrayRunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$script:TrayRunValue = 'RCEGuard.Tray'
$script:ProfileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

function Get-TrayProcesses {
    # Processes running the installed tray application, of every user (not a build started from somewhere else).
    $exe = Join-Path $script:TrayInstallDir $script:TrayExeName
    @(Get-CimInstance Win32_Process -Filter "Name='$script:TrayExeName'" |
        Where-Object { $null -ne $_ -and $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $exe, [StringComparison]::OrdinalIgnoreCase) })
}

function Stop-TrayProcesses {
    # The tray application holds no state that ending it could damage.
    foreach ($process in (Get-TrayProcesses)) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds(10)
    while (@(Get-TrayProcesses).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
}

function Start-GuardTray {
    <#
        Starts the installed tray application for the user at this desktop. Through Explorer:
        started directly from an administrator console it would run with administrator rights,
        which a program that only shows things must not have.
    #>
    $exe = Join-Path $script:TrayInstallDir $script:TrayExeName
    Start-Process -FilePath (Join-Path $env:windir 'explorer.exe') -ArgumentList "`"$exe`""
}

function Get-TrayRunCommand {
    # What the Run key holds for the tray application, or $null.
    $values = Get-ItemProperty -LiteralPath $script:TrayRunKey -ErrorAction SilentlyContinue
    if ($null -eq $values -or -not ($values.PSObject.Properties.Name -contains $script:TrayRunValue)) { return $null }
    [string] $values.($script:TrayRunValue)
}

function Install-GuardTray([string] $sourceDir) {
    <#
        Copies the published tray application to its folder in Program Files and registers it to
        start at every sign-in. Running it again updates the files.
    #>
    $sourceExe = Join-Path $sourceDir $script:TrayExeName
    if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
        throw "Published tray application not found: '$sourceExe'."
    }

    # A running copy keeps its files open.
    Stop-TrayProcesses
    if (Test-Path -LiteralPath $script:TrayInstallDir) {
        Remove-Item -LiteralPath $script:TrayInstallDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:TrayInstallDir -Force | Out-Null
    Copy-Item -Path (Join-Path $sourceDir '*') -Destination $script:TrayInstallDir -Recurse -Force

    $exe = Join-Path $script:TrayInstallDir $script:TrayExeName
    # Quoted: the path has a space.
    Set-ItemProperty -LiteralPath $script:TrayRunKey -Name $script:TrayRunValue -Value "`"$exe`"" -Type String
}

function Get-UserProfilePaths {
    # The profile folders of the users of this machine.
    @(Get-ChildItem -LiteralPath $script:ProfileListKey -ErrorAction SilentlyContinue | ForEach-Object {
            $values = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $values -and $values.PSObject.Properties.Name -contains 'ProfileImagePath') {
                [Environment]::ExpandEnvironmentVariables([string] $values.ProfileImagePath)
            }
            # Not Test-Path: the list also names the profiles of system accounts, and Test-Path throws
            # for a folder this user may not look into. Directory.Exists says "no" instead.
        } | Where-Object { $_ -and [IO.Directory]::Exists($_) })
}

function Get-TrayStateFolders {
    # The folders in which the tray application keeps, per user, which finding it announced last.
    # Without administrator rights the profiles of other users cannot be looked into: those count as "none".
    @(Get-UserProfilePaths | ForEach-Object { Join-Path $_ 'AppData\Local\RCEGuard' } |
        Where-Object { [IO.Directory]::Exists($_) } |
        Where-Object { @(Get-ChildItem -LiteralPath $_ -Filter 'tray-state*.txt' -File -ErrorAction SilentlyContinue).Count -gt 0 })
}

function Remove-TrayStateFiles {
    # Removes those files for every user, and the folder if nothing else is in it. Returns one line per folder that could not be cleaned.
    $problems = @()
    foreach ($folder in (Get-TrayStateFolders)) {
        try {
            Get-ChildItem -LiteralPath $folder -Filter 'tray-state*.txt' -File | Remove-Item -Force -ErrorAction Stop
            if (@(Get-ChildItem -LiteralPath $folder -Force).Count -eq 0) { Remove-Item -LiteralPath $folder -Force -ErrorAction Stop }
        }
        catch { $problems += "The state of the tray application in '$folder' could not be removed: $($_.Exception.Message)" }
    }
    return $problems
}

function Uninstall-GuardTray {
    <#
        Ends the tray application for every user and removes its folder, its start at sign-in
        and the small state files in the user profiles. Returns $true if there was something to remove.
    #>
    $removed = $false
    if (@(Get-TrayProcesses).Count -gt 0) {
        Stop-TrayProcesses
        $removed = $true
    }
    if ($null -ne (Get-TrayRunCommand)) {
        Remove-ItemProperty -LiteralPath $script:TrayRunKey -Name $script:TrayRunValue -Force
        $removed = $true
    }
    if (Test-Path -LiteralPath $script:TrayInstallDir) {
        # A process that has just ended may hold its files for a moment longer.
        $deadline = (Get-Date).AddSeconds(10)
        while ($true) {
            try { Remove-Item -LiteralPath $script:TrayInstallDir -Recurse -Force -ErrorAction Stop; break }
            catch {
                if ((Get-Date) -gt $deadline) { throw }
                Start-Sleep -Milliseconds 300
            }
        }
        $removed = $true
    }
    if (@(Get-TrayStateFolders).Count -gt 0) {
        foreach ($problem in @(Remove-TrayStateFiles)) { Write-Warning $problem }
        $removed = $true
    }
    return $removed
}
