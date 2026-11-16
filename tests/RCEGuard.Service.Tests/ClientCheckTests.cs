namespace RCEGuard.Service.Tests;

/// <summary>The look at the client file: the command that says what a client file is like.</summary>
public sealed class ClientCheckTests : IDisposable
{
    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-clientcheck-").FullName;

    public void Dispose() => Directory.Delete(folder, recursive: true);

    /// <summary>The headers of a 32-bit program laid out like the 3.3.5a client's; the fourth section is ".zdata".</summary>
    internal static byte[] ClientFile(bool zdataExecutable)
    {
        var file = new byte[4096];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        const int pe = 0x110;
        BitConverter.GetBytes(pe).CopyTo(file, 0x3C);
        file[pe] = (byte)'P';
        file[pe + 1] = (byte)'E';
        (string Name, uint Flags)[] sections =
        [
            (".text", 0x60000020), (".rdata", 0x40000040), (".data", 0xC0000040),
            (".zdata", zdataExecutable ? 0xE0000040 : 0xC0000040), (".tls", 0xC0000040), (".rsrc", 0x40000040),
        ];
        BitConverter.GetBytes((ushort)sections.Length).CopyTo(file, pe + 6);
        BitConverter.GetBytes((ushort)0xE0).CopyTo(file, pe + 20);
        for (var i = 0; i < sections.Length; i++)
        {
            var at = pe + 24 + 0xE0 + (i * 40);
            System.Text.Encoding.ASCII.GetBytes(sections[i].Name).CopyTo(file, at);
            BitConverter.GetBytes(sections[i].Flags).CopyTo(file, at + 36);
        }

        return file;
    }

    private string Write(string name, byte[] content)
    {
        var path = Path.Combine(folder, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    private void WriteConfig(string client) => File.WriteAllText(
        Path.Combine(folder, "appsettings.json"),
        $$"""{ "profiles": [ { "name": "Test", "clientPath": "{{client.Replace(@"\", @"\\")}}" } ] }""");

    [Fact]
    public void The_command_says_what_the_client_of_every_profile_has()
    {
        var client = Write("Wow.exe", ClientFile(zdataExecutable: true));
        WriteConfig(client);
        var output = new StringWriter();
        var error = new StringWriter();

        var exitCode = ClientCheckCommand.Run(new ServiceOptions { DataDirectory = folder, CheckClient = true }, output, error);

        Assert.Equal((0, string.Empty), (exitCode, error.ToString()));
        Assert.Contains($"'Test' ({client}): has a section that is both writable and executable (.zdata).", output.ToString());
        Assert.Contains("patch-client.ps1", output.ToString());
        Assert.Equal(ClientFile(zdataExecutable: true), File.ReadAllBytes(client));   // only read
    }

    [Fact]
    public void The_command_takes_a_file_and_says_when_there_is_nothing_or_nothing_to_read()
    {
        var patched = Write("patched.exe", ClientFile(zdataExecutable: false));
        var output = new StringWriter();
        Assert.Equal(0, ClientCheckCommand.Run(new ServiceOptions { DataDirectory = folder, CheckClient = true, CheckClientPath = patched }, output, new StringWriter()));
        Assert.Contains("no section is both writable and executable", output.ToString());

        var text = Write("notes.txt", "just text, long enough to be more than a few bytes of nothing at all"u8.ToArray());
        var error = new StringWriter();
        Assert.Equal(1, ClientCheckCommand.Run(new ServiceOptions { DataDirectory = folder, CheckClient = true, CheckClientPath = text }, new StringWriter(), error));
        Assert.Contains("not a Windows program", error.ToString());

        error = new StringWriter();
        Assert.Equal(1, ClientCheckCommand.Run(new ServiceOptions { DataDirectory = folder, CheckClient = true, CheckClientPath = Path.Combine(folder, "nope.exe") }, new StringWriter(), error));
        Assert.Contains("could not be read", error.ToString());
    }

    [Theory]
    [InlineData(new[] { "--check-client" }, true, false)]
    [InlineData(new[] { "--check-client", "C:\\Games\\Wow.exe" }, true, true)]
    [InlineData(new[] { "--check-client", "--data-dir", "C:\\X" }, true, false)]
    [InlineData(new[] { "--dry-run" }, false, false)]
    public void The_check_argument_takes_an_optional_file(string[] args, bool check, bool withFile)
    {
        var options = ServiceOptions.Parse(args, out var error);

        Assert.NotNull(options);
        Assert.Empty(error);
        Assert.Equal((check, withFile), (options.CheckClient, options.CheckClientPath is not null));
    }
}
