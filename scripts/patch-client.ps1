<#
.SYNOPSIS
    Takes the execute right away from the writable and executable section (".zdata") of a 3.3.5a
    game client file, or gives it back.

.DESCRIPTION
    The 3.3.5a client has one small section, ".zdata", that is writable and executable at a fixed
    address: whatever gets written there can be run. This script changes one byte in the header
    of the client file so that Windows no longer runs anything from that section. It is the same
    change the well-known "RCEPatcher" makes; unlike that tool this script first checks that the
    file is what it expects, and can undo the change.

    What this script cannot show is whether the change stops a particular exploit, or whether a
    server minds a client file that was changed. It changes a file of the game: use it only if
    you want that. RCEGuard itself never runs this script.

    Without a switch the original file is left alone and a copy "<name>_patched.exe" is written
    next to it. Start that copy to see whether the client still runs.

    The script reads and writes only the file on disk. It never touches a running client; for
    -InPlace and -Undo the client must not be running. It needs no administrator rights if you may
    write to the game folder.

.PARAMETER ClientPath
    Full path of the client file, e.g. D:\Games\Warmane\Wow.exe.

.PARAMETER InPlace
    Change the file itself instead of writing a copy. The unchanged file is kept next to it as
    "<name>.exe.unpatched". Use this once the copy has shown that the client runs: launchers and
    RCEGuard keep working with the same path.

.PARAMETER Undo
    Give the execute right back to the section of the given file (what the file was like before).

.PARAMETER CheckOnly
    Only say what the file is like and whether the script would change it. Changes nothing.

.EXAMPLE
    .\scripts\patch-client.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -CheckOnly

.EXAMPLE
    .\scripts\patch-client.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe'
    Writes D:\Games\Warmane\Wow_patched.exe and leaves Wow.exe as it is.

.EXAMPLE
    .\scripts\patch-client.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -InPlace

.EXAMPLE
    .\scripts\patch-client.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -Undo
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ClientPath,
    [switch] $InPlace,
    [switch] $Undo,
    [switch] $CheckOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ClientFileTools.ps1')

if (@($InPlace, $Undo, $CheckOnly | Where-Object { $_ }).Count -gt 1) {
    throw 'Use only one of -InPlace, -Undo and -CheckOnly.'
}
$ClientPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ClientPath)
if (-not (Test-Path -LiteralPath $ClientPath -PathType Leaf)) {
    throw "File not found: '$ClientPath'."
}

$execute = $script:SectionExecute

function Show-File([string] $path, $info) {
    Write-Host "File: $path ($((Get-Item -LiteralPath $path).Length) bytes)"
    if (-not $info.IsProgram) { Write-Host "  Not a Windows program: $($info.Problem)"; return }
    Write-Host ("  {0}, starts in section '{1}', asks Windows to keep data from running as code (DEP): {2}" -f $(if ($info.Is32Bit) { '32-bit x86 program' } else { 'not a 32-bit x86 program' }), $info.EntrySection, $(if ($info.NxCompatible) { 'yes' } else { 'NO' }))
    foreach ($section in $info.Sections) {
        $rights = @('read'; if ($section.Writable) { 'write' }; if ($section.Executable) { 'execute' }) -join '+'
        $mark = if ($section.Writable -and $section.Executable) { '   <-- writable and executable' } else { '' }
        Write-Host ("  section {0,-8} flags 0x{1:X8} ({2}){3}" -f $section.Name, $section.Flags, $rights, $mark)
    }
}

function Set-SectionFlags([string] $path, $section, [uint32] $flags) {
    # Writes the four bytes of the flags of one section and nothing else.
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try {
        $null = $stream.Seek($section.FlagsOffset, [IO.SeekOrigin]::Begin)
        $bytes = [BitConverter]::GetBytes($flags)
        $stream.Write($bytes, 0, 4)
        $stream.Flush()
    }
    finally { $stream.Dispose() }
}

function Compare-Files([string] $a, [string] $b) {
    # The positions at which two files of the same length differ (at most 16 are listed); $null if the lengths differ.
    $x = [IO.File]::ReadAllBytes($a)
    $y = [IO.File]::ReadAllBytes($b)
    if ($x.Length -ne $y.Length) { return $null }
    if ([Convert]::ToBase64String($x) -ceq [Convert]::ToBase64String($y)) { return , @() }
    $different = New-Object Collections.Generic.List[int]
    for ($i = 0; $i -lt $x.Length -and $different.Count -lt 16; $i++) { if ($x[$i] -ne $y[$i]) { $different.Add($i) } }
    return , @($different)
}

function Assert-NotRunning([string] $path) {
    $running = @(Get-RunningCopies $path)
    if ($running.Count -gt 0) {
        throw "'$path' is running (pid $(@($running | ForEach-Object { $_.ProcessId }) -join ', ')). Close the client first: this script never changes the file of a running client."
    }
}

$info = Get-ClientFileInfo $ClientPath
Show-File $ClientPath $info

# --- only look ---------------------------------------------------------------------------------
if ($CheckOnly) {
    Write-Host ''
    $obstacles = @(Get-ClientPatchObstacles $info)
    if ($obstacles.Count -eq 0) {
        Write-Host "This script would change it: section '.zdata' would lose the execute right (one byte at position 0x$('{0:X}' -f ($info.WritableExecutable[0].FlagsOffset + 3)))."
    }
    else {
        Write-Host 'This script would not change it:'
        $obstacles | ForEach-Object { Write-Host "  - $_" }
    }
    return
}

# --- give the execute right back -----------------------------------------------------------------
if ($Undo) {
    if (-not $info.IsProgram -or -not $info.Is32Bit) { throw 'This is not a 32-bit x86 program: nothing this script could have changed.' }
    if (@($info.WritableExecutable).Count -gt 0) {
        Write-Host ''
        Write-Host "Nothing to undo: section '$($info.WritableExecutable[0].Name)' has the execute right."
        return
    }
    $section = @($info.Sections | Where-Object { $_.Name -eq '.zdata' })
    if ($section.Count -ne 1 -or -not $section[0].Writable -or $section[0].Executable) {
        throw "The file has no writable section '.zdata' without the execute right: it is not a file this script changed."
    }
    Assert-NotRunning $ClientPath
    Set-SectionFlags $ClientPath $section[0] ([uint32] ($section[0].Flags -bor $execute))
    $after = Get-ClientFileInfo $ClientPath
    if (@($after.WritableExecutable | Where-Object { $_.Name -eq '.zdata' }).Count -ne 1) { throw 'The change was written, but reading the file back does not show it.' }
    Write-Host ''
    Write-Host "Undone: section '.zdata' of '$ClientPath' has the execute right again (flags 0x$('{0:X8}' -f $after.WritableExecutable[0].Flags))."
    $backup = "$ClientPath.unpatched"
    if (Test-Path -LiteralPath $backup) {
        $different = Compare-Files $ClientPath $backup
        if ($null -ne $different -and $different.Count -eq 0) {
            Remove-Item -LiteralPath $backup -Force
            Write-Host "The file is byte for byte what '$backup' was; that copy was removed."
        }
        else { Write-Host "'$backup' differs from the file and was left where it is." }
    }
    return
}

# --- take the execute right away -----------------------------------------------------------------
$obstacles = @(Get-ClientPatchObstacles $info)
if ($obstacles.Count -gt 0) {
    if (@($info.WritableExecutable).Count -eq 0 -and $info.IsProgram) {
        Write-Host ''
        Write-Host 'Nothing to do: no section of this file is both writable and executable.'
        return
    }
    throw "This script will not change '$ClientPath':`n  - $($obstacles -join "`n  - ")"
}
if (-not $info.NxCompatible) {
    Write-Warning 'The program does not ask Windows to keep data from running as code (DEP). Unless DEP is turned on for all programs on this machine, the change has no effect.'
}

$section = $info.WritableExecutable[0]
$newFlags = [uint32] ($section.Flags -band (-bnot $execute))
if ($InPlace) {
    Assert-NotRunning $ClientPath
    $backup = "$ClientPath.unpatched"
    if (Test-Path -LiteralPath $backup) {
        $different = Compare-Files $ClientPath $backup
        if ($null -eq $different -or $different.Count -ne 0) {
            throw "'$backup' exists and is not the same as '$ClientPath'. It may be the unchanged file of another version: move it away first."
        }
    }
    else { Copy-Item -LiteralPath $ClientPath -Destination $backup }
    $target = $ClientPath
    $original = $backup
}
else {
    $target = Join-Path (Split-Path -Path $ClientPath -Parent) ([IO.Path]::GetFileNameWithoutExtension($ClientPath) + '_patched' + [IO.Path]::GetExtension($ClientPath))
    if (Test-Path -LiteralPath $target) {
        throw "'$target' exists already. Delete it first, or look at it with -CheckOnly."
    }
    Copy-Item -LiteralPath $ClientPath -Destination $target
    $original = $ClientPath
}

try {
    Set-SectionFlags $target $section $newFlags
    $after = Get-ClientFileInfo $target
    $different = Compare-Files $original $target
    if (@($after.WritableExecutable).Count -ne 0 -or $null -eq $different -or $different.Count -ne 1 -or $different[0] -ne ($section.FlagsOffset + 3)) {
        throw 'The file does not look as it should after the change.'
    }
}
catch {
    # Leave nothing half done: the copy goes, or the original comes back.
    if ($InPlace) { Copy-Item -LiteralPath $original -Destination $target -Force } else { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
    throw "The change could not be made and was taken back: $($_.Exception.Message)"
}

Write-Host ''
Write-Host ("Changed one byte at position 0x{0:X}: 0x{1:X2} -> 0x{2:X2}. Section '.zdata' is now readable and writable, not executable." -f ($section.FlagsOffset + 3), (($section.Flags -shr 24) -band 0xFF), (($newFlags -shr 24) -band 0xFF))
if ($InPlace) {
    Write-Host "Changed: '$target'. The unchanged file is kept as '$original'; '-Undo' gives the execute right back."
}
else {
    Write-Host "Written: '$target'. '$original' was not changed."
    Write-Host 'Start the new file and go as far as the login screen to see whether the client still runs.'
    Write-Host "If it does and you want to use it for good: run this script again with -InPlace, and delete '$(Split-Path $target -Leaf)'."
}
Write-Host 'What this does not tell you: whether it stops a particular exploit, and whether a server minds the changed file.'
