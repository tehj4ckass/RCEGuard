# Helpers that read the header of a client file, shared by install.ps1 and patch-client.ps1.
# Dot-source this file; it does nothing by itself. Everything here only reads the file on disk.

$script:SectionExecute = [uint32] 536870912     # 0x20000000, IMAGE_SCN_MEM_EXECUTE
$script:SectionWrite = [uint32] 2147483648      # 0x80000000, IMAGE_SCN_MEM_WRITE

function Get-ClientFileInfo([string] $path) {
    <#
        Reads the headers of a program file. Returns an object with
          IsProgram, Problem   whether it is a Windows program, and if not, why
          Is32Bit              PE32 for x86 (the 3.3.5a client is)
          NxCompatible         the program asks Windows to enforce "data is not code" (DEP)
          EntrySection         name of the section the program starts in
          Sections             Name, Flags, FlagsOffset (position of the flags in the file), RawPointer, RawSize,
                               VirtualAddress, VirtualSize, Writable, Executable, RawIsZero, HoldsTable
          WritableExecutable   the sections that are both writable and executable
        Never throws for a file that is not a program.
    #>
    $result = [pscustomobject]@{
        Path = $path; IsProgram = $false; Problem = ''; Is32Bit = $false; NxCompatible = $false
        EntrySection = ''; Sections = @(); WritableExecutable = @()
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $header = New-Object byte[] 8192
        $read = 0
        while ($read -lt $header.Length) {
            $got = $stream.Read($header, $read, $header.Length - $read)
            if ($got -le 0) { break }
            $read += $got
        }
        if ($read -lt 64 -or $header[0] -ne 0x4D -or $header[1] -ne 0x5A) { $result.Problem = 'it does not start like a Windows program'; return $result }
        $pe = [BitConverter]::ToInt32($header, 0x3C)
        if ($pe -le 0 -or $pe -gt ($read - 24) -or $header[$pe] -ne 0x50 -or $header[$pe + 1] -ne 0x45 -or $header[$pe + 2] -ne 0 -or $header[$pe + 3] -ne 0) {
            $result.Problem = 'it has no PE header where one is announced'; return $result
        }
        $machine = [BitConverter]::ToUInt16($header, $pe + 4)
        $count = [BitConverter]::ToUInt16($header, $pe + 6)
        $optionalSize = [BitConverter]::ToUInt16($header, $pe + 20)
        $optional = $pe + 24
        $table = $optional + $optionalSize
        if ($count -eq 0 -or $count -gt 96 -or ($table + $count * 40) -gt $read -or $optionalSize -lt 96) {
            $result.Problem = 'its section table cannot be read'; return $result
        }
        $magic = [BitConverter]::ToUInt16($header, $optional)
        $result.IsProgram = $true
        $result.Is32Bit = ($magic -eq 0x10B -and $machine -eq 0x14C)
        $entry = [BitConverter]::ToUInt32($header, $optional + 16)

        # Where the tables lie that Windows uses when it loads the program (imports, relocations, TLS ...).
        $tables = @()
        if ($result.Is32Bit -and $optionalSize -ge 224) {
            $result.NxCompatible = (([BitConverter]::ToUInt16($header, $optional + 70)) -band 0x0100) -ne 0
            for ($d = 0; $d -lt 16; $d++) {
                if ($d -eq 4) { continue }   # the certificate table is a file position, not an address
                $rva = [BitConverter]::ToUInt32($header, $optional + 96 + 8 * $d)
                if ($rva -ne 0) { $tables += $rva }
            }
        }

        $sections = @()
        for ($i = 0; $i -lt $count; $i++) {
            $o = $table + 40 * $i
            $nameBytes = $header[$o..($o + 7)] | Where-Object { $_ -ne 0 }
            $name = -join ($nameBytes | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char] $_ } else { '?' } })
            $flags = [BitConverter]::ToUInt32($header, $o + 36)
            $virtualSize = [BitConverter]::ToUInt32($header, $o + 8)
            $rva = [BitConverter]::ToUInt32($header, $o + 12)
            $rawSize = [BitConverter]::ToUInt32($header, $o + 16)
            $rawPointer = [BitConverter]::ToUInt32($header, $o + 20)
            $extent = [Math]::Max([uint64] $virtualSize, [uint64] $rawSize)
            $section = [pscustomobject]@{
                Name = $name; Flags = $flags; FlagsOffset = $o + 36; RawPointer = $rawPointer; RawSize = $rawSize
                VirtualAddress = $rva; VirtualSize = $virtualSize
                Writable = (($flags -band $script:SectionWrite) -ne 0); Executable = (($flags -band $script:SectionExecute) -ne 0)
                RawIsZero = $true
                HoldsTable = (@($tables | Where-Object { $_ -ge $rva -and $_ -lt ([uint64] $rva + $extent) }).Count -gt 0)
            }
            if ($entry -ge $rva -and $entry -lt ([uint64] $rva + $extent)) { $result.EntrySection = $name }
            $sections += $section
        }

        # Only for the sections in question: is anything in the file there, or is it all zero?
        foreach ($section in $sections | Where-Object { $_.Writable -and $_.Executable }) {
            if ($section.RawSize -gt 0) {
                if (([uint64] $section.RawPointer + $section.RawSize) -gt $stream.Length -or $section.RawSize -gt 67108864) { $section.RawIsZero = $false; continue }
                $null = $stream.Seek($section.RawPointer, [IO.SeekOrigin]::Begin)
                $raw = New-Object byte[] $section.RawSize
                $got = 0
                while ($got -lt $raw.Length) { $n = $stream.Read($raw, $got, $raw.Length - $got); if ($n -le 0) { break }; $got += $n }
                # Array.IndexOf for "anything but zero" is not there; a loop over a megabyte would be slow, so compare in one go.
                $section.RawIsZero = ($got -eq $raw.Length) -and ([Convert]::ToBase64String($raw).Trim('A', '=').Length -eq 0)
            }
        }

        $result.Sections = $sections
        $result.WritableExecutable = @($sections | Where-Object { $_.Writable -and $_.Executable })
        return $result
    }
    catch [IO.IOException], [UnauthorizedAccessException] {
        $result.Problem = "the file could not be read: $($_.Exception.Message)"
        return $result
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-ClientPatchObstacles($info) {
    <#
        Why patch-client.ps1 will not touch this file, as text lines; none means it can.
        The script only knows one layout: a 32-bit program with exactly one writable and executable
        section, named ".zdata", that holds nothing in the file and that the program neither starts
        in nor keeps a table in. Anything else is left alone.
    #>
    $reasons = @()
    if (-not $info.IsProgram) { return @("it is not a Windows program ($($info.Problem))") }
    if (-not $info.Is32Bit) { $reasons += 'it is not a 32-bit x86 program' }
    $found = @($info.WritableExecutable)
    if ($found.Count -eq 0) { return @('no section is both writable and executable: there is nothing to change') }
    if ($found.Count -gt 1) { $reasons += "more than one section is both writable and executable ($(@($found | ForEach-Object { $_.Name }) -join ', '))" }
    foreach ($section in $found) {
        if ($section.Name -ne '.zdata') { $reasons += "the writable and executable section is called '$($section.Name)', not '.zdata'" }
        if (-not $section.RawIsZero) { $reasons += "section '$($section.Name)' holds data in the file: the program may run code from it" }
        if ($info.EntrySection -eq $section.Name) { $reasons += "the program starts in section '$($section.Name)'" }
        if ($section.HoldsTable) { $reasons += "a table Windows needs to load the program lies in section '$($section.Name)'" }
    }
    return $reasons
}

function Get-RunningCopies([string] $path) {
    # Processes that run exactly this file.
    $full = [IO.Path]::GetFullPath($path)
    $name = [IO.Path]::GetFileName($full)
    @(Get-CimInstance Win32_Process -Filter "Name='$($name.Replace("'", "''"))'" -ErrorAction SilentlyContinue |
        Where-Object { $null -ne $_ -and $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $full, [StringComparison]::OrdinalIgnoreCase) })
}
