namespace RCEGuard.Core.Client;

/// <summary>What the header of a client file says about where code can run.</summary>
public enum ClientFileState
{
    /// <summary>The file could not be read.</summary>
    Unreadable,

    /// <summary>The file is not a Windows program (no valid PE header).</summary>
    NotAProgram,

    /// <summary>
    /// The program has a section that is both writable and executable: whatever gets written
    /// there can be run. The 3.3.5a client has one, ".zdata".
    /// </summary>
    HasWritableCode,

    /// <summary>No section is both writable and executable.</summary>
    NoWritableCode,
}

/// <summary>The result of looking at a client file.</summary>
/// <param name="State">What was found.</param>
/// <param name="WritableExecutableSections">Names of the sections that are both writable and executable.</param>
/// <param name="Problem">Why the file could not be read or is not a program; empty otherwise.</param>
public sealed record ClientFileInfo(ClientFileState State, IReadOnlyList<string> WritableExecutableSections, string Problem)
{
    /// <summary>One sentence for a person about the client of a profile, or null if there is nothing to say.</summary>
    public string? Describe(string profileName) => State switch
    {
        ClientFileState.HasWritableCode =>
            $"The client of '{profileName}' has a section that is both writable and executable ({string.Join(", ", WritableExecutableSections)}): " +
            "code that gets written there can run. See \"Patching the client\" in the README.",
        _ => null,
    };
}

/// <summary>
/// Reads the section table of a program file (the file on disk, never a running process) and says
/// whether a section is both writable and executable. Only reads.
/// </summary>
public static class ClientFileInspector
{
    private const uint MemExecute = 0x20000000;
    private const uint MemWrite = 0x80000000;
    private const int MaxSections = 96;

    /// <summary>How much of a file <see cref="InspectFile"/> reads: headers end well before this.</summary>
    public const int HeaderBytes = 8192;

    /// <summary>Looks at a file. Never throws for a file that is missing, locked or not a program.</summary>
    public static ClientFileInfo InspectFile(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[HeaderBytes];
            var read = 0;
            while (read < buffer.Length)
            {
                var got = stream.Read(buffer, read, buffer.Length - read);
                if (got == 0)
                {
                    break;
                }

                read += got;
            }

            return Inspect(buffer.AsSpan(0, read));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new ClientFileInfo(ClientFileState.Unreadable, [], ex.Message);
        }
    }

    /// <summary>Looks at the first bytes of a file.</summary>
    public static ClientFileInfo Inspect(ReadOnlySpan<byte> header)
    {
        if (header.Length < 0x40 || header[0] != (byte)'M' || header[1] != (byte)'Z')
        {
            return NotAProgram("it does not start like a Windows program");
        }

        var pe = BitConverter.ToInt32(header.Slice(0x3C, 4));
        if (pe <= 0 || pe > header.Length - 24 || header[pe] != (byte)'P' || header[pe + 1] != (byte)'E' || header[pe + 2] != 0 || header[pe + 3] != 0)
        {
            return NotAProgram("it has no PE header where one is announced");
        }

        var sectionCount = BitConverter.ToUInt16(header.Slice(pe + 6, 2));
        var optionalSize = BitConverter.ToUInt16(header.Slice(pe + 20, 2));
        var table = pe + 24 + optionalSize;
        if (sectionCount == 0 || sectionCount > MaxSections || table + (sectionCount * 40) > header.Length)
        {
            return NotAProgram("its section table cannot be read");
        }

        var found = new List<string>();
        for (var i = 0; i < sectionCount; i++)
        {
            var section = header.Slice(table + (i * 40), 40);
            var flags = BitConverter.ToUInt32(section.Slice(36, 4));
            if ((flags & MemExecute) != 0 && (flags & MemWrite) != 0)
            {
                found.Add(SectionName(section[..8]));
            }
        }

        return found.Count > 0
            ? new ClientFileInfo(ClientFileState.HasWritableCode, found, string.Empty)
            : new ClientFileInfo(ClientFileState.NoWritableCode, [], string.Empty);
    }

    private static ClientFileInfo NotAProgram(string why) => new(ClientFileState.NotAProgram, [], why);

    private static string SectionName(ReadOnlySpan<byte> raw)
    {
        var length = raw.IndexOf((byte)0);
        var name = System.Text.Encoding.ASCII.GetString(length < 0 ? raw : raw[..length]);
        // A name is shown to a person and written to a log: nothing but plain characters.
        return new string([.. name.Select(c => c is >= ' ' and < (char)127 ? c : '?')]);
    }
}
