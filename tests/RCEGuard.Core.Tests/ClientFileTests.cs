using RCEGuard.Core.Client;

namespace RCEGuard.Core.Tests;

/// <summary>Reading the section table of a client file: is a section both writable and executable?</summary>
public class ClientFileTests
{
    internal const uint Code = 0x60000020;        // execute + read
    internal const uint ReadOnlyData = 0x40000040;
    internal const uint Data = 0xC0000040;        // read + write
    internal const uint WritableCode = 0xE0000040; // read + write + execute

    /// <summary>The headers of a 32-bit program with the given sections, laid out like the 3.3.5a client's.</summary>
    internal static byte[] Program(params (string Name, uint Flags)[] sections)
    {
        var file = new byte[4096];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        const int pe = 0x110;
        BitConverter.GetBytes(pe).CopyTo(file, 0x3C);
        file[pe] = (byte)'P';
        file[pe + 1] = (byte)'E';
        BitConverter.GetBytes((ushort)0x14C).CopyTo(file, pe + 4);            // i386
        BitConverter.GetBytes((ushort)sections.Length).CopyTo(file, pe + 6);
        BitConverter.GetBytes((ushort)0xE0).CopyTo(file, pe + 20);            // size of the optional header
        BitConverter.GetBytes((ushort)0x10B).CopyTo(file, pe + 24);           // PE32
        var table = pe + 24 + 0xE0;
        for (var i = 0; i < sections.Length; i++)
        {
            var at = table + (i * 40);
            System.Text.Encoding.ASCII.GetBytes(sections[i].Name).CopyTo(file, at);
            BitConverter.GetBytes(sections[i].Flags).CopyTo(file, at + 36);
        }

        return file;
    }

    private static readonly (string, uint)[] Client =
        [(".text", Code), (".rdata", ReadOnlyData), (".data", Data), (".zdata", WritableCode), (".tls", Data), (".rsrc", ReadOnlyData)];

    [Fact]
    public void The_client_with_its_writable_and_executable_section_is_recognised()
    {
        var file = Program(Client);
        // Laid out as in the real client: the byte the well-known patcher changes is the top byte of these flags.
        Assert.Equal(0xE0, file[0x2A7]);

        var info = ClientFileInspector.Inspect(file);

        Assert.Equal(ClientFileState.HasWritableCode, info.State);
        Assert.Equal([".zdata"], info.WritableExecutableSections);
        Assert.Equal(
            "The client of 'Warmane' has a section that is both writable and executable (.zdata): code that gets written there can run. See \"Patching the client\" in the README.",
            info.Describe("Warmane"));
    }

    [Fact]
    public void A_client_whose_section_lost_the_execute_right_has_nothing_to_report()
    {
        var file = Program(Client);
        file[0x2A7] = 0xC0;   // what the patch does

        var info = ClientFileInspector.Inspect(file);

        Assert.Equal(ClientFileState.NoWritableCode, info.State);
        Assert.Empty(info.WritableExecutableSections);
        Assert.Null(info.Describe("Warmane"));
    }

    [Fact]
    public void Every_writable_and_executable_section_is_named_wherever_it_is()
    {
        var info = ClientFileInspector.Inspect(Program((".text", Code), ("UPX0", WritableCode), (".odd\u0001", WritableCode), (".data", Data)));

        Assert.Equal(["UPX0", ".odd?"], info.WritableExecutableSections);
    }

    [Theory]
    [InlineData(0)]      // empty
    [InlineData(10)]     // far too short
    [InlineData(0x200)]  // header announced beyond the end
    public void A_file_that_is_cut_off_is_not_a_program(int length)
    {
        var info = ClientFileInspector.Inspect(Program(Client).AsSpan(0, length));

        Assert.Equal(ClientFileState.NotAProgram, info.State);
        Assert.NotEmpty(info.Problem);
    }

    [Fact]
    public void Text_and_broken_headers_are_not_programs()
    {
        Assert.Equal(ClientFileState.NotAProgram, ClientFileInspector.Inspect("This is not a program at all, just a line of text that is long enough to be read."u8).State);

        var noPe = Program(Client);
        noPe[0x110] = (byte)'X';
        Assert.Equal(ClientFileState.NotAProgram, ClientFileInspector.Inspect(noPe).State);

        var noSections = Program();
        Assert.Equal(ClientFileState.NotAProgram, ClientFileInspector.Inspect(noSections).State);

        var tooMany = Program(Client);
        BitConverter.GetBytes((ushort)5000).CopyTo(tooMany, 0x110 + 6);
        Assert.Equal(ClientFileState.NotAProgram, ClientFileInspector.Inspect(tooMany).State);

        var wildOffset = Program(Client);
        BitConverter.GetBytes(-5).CopyTo(wildOffset, 0x3C);
        Assert.Equal(ClientFileState.NotAProgram, ClientFileInspector.Inspect(wildOffset).State);
    }

    [Fact]
    public void A_file_is_read_from_disk_without_changing_it_and_a_missing_one_is_no_crash()
    {
        var folder = Directory.CreateTempSubdirectory("rceguard-clientfile-").FullName;
        try
        {
            var path = Path.Combine(folder, "Wow.exe");
            var content = Program(Client);
            File.WriteAllBytes(path, content);
            var stamp = File.GetLastWriteTimeUtc(path);

            Assert.Equal(ClientFileState.HasWritableCode, ClientFileInspector.InspectFile(path).State);
            Assert.Equal(content, File.ReadAllBytes(path));
            Assert.Equal(stamp, File.GetLastWriteTimeUtc(path));

            var missing = ClientFileInspector.InspectFile(Path.Combine(folder, "nope.exe"));
            Assert.Equal(ClientFileState.Unreadable, missing.State);
            Assert.NotEmpty(missing.Problem);

            // A program that is running keeps its file open; reading must still work.
            using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Assert.Equal(ClientFileState.HasWritableCode, ClientFileInspector.InspectFile(path).State);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void This_test_program_itself_has_no_writable_and_executable_section()
    {
        // A real file written by a real linker.
        var info = ClientFileInspector.InspectFile(typeof(ClientFileInspector).Assembly.Location);

        Assert.Equal(ClientFileState.NoWritableCode, info.State);
    }
}
