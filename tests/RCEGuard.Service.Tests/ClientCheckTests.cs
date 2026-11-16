using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Client;

namespace RCEGuard.Service.Tests;

/// <summary>The look at the client file: the command, and the line the guard writes at its start.</summary>
public sealed class ClientCheckTests : IDisposable
{
    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-clientcheck-").FullName;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(folder, recursive: true);
    }

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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task The_guard_says_at_its_start_if_the_client_has_such_a_section(bool executable)
    {
        var client = Write("Wow.exe", ClientFile(executable));
        WriteConfig(client);
        var logger = new ListLogger();
        var worker = new GuardWorker(new ServiceOptions { DataDirectory = folder, LogName = "Application" }, logger, new Lifetime())
        {
            OpenFirewall = () => new FakeFirewall(),
            DeliveryGrace = TimeSpan.FromSeconds(1),
            OpenTail = (_, _, _, _) => new MemoryStream(),
        };

        await worker.StartAsync(CancellationToken.None);
        var watch = Stopwatch.StartNew();
        while (!logger.Lines.Any(line => line.Contains("Subscribed to") || line.Contains("cannot run")) && watch.ElapsedMilliseconds < 20_000)
        {
            await Task.Delay(50);
        }

        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();

        Assert.DoesNotContain(logger.Lines, line => line.Contains("cannot run"));
        var notes = logger.Lines.Where(line => line.Contains("both writable and executable")).ToList();
        if (executable)
        {
            Assert.Equal("Warning: The client of 'Test' has a section that is both writable and executable (.zdata): code that gets written there can run. See \"Patching the client\" in the README.", Assert.Single(notes));
        }
        else
        {
            Assert.Empty(notes);
        }
    }

    private sealed class ListLogger : ILogger<GuardWorker>
    {
        public ConcurrentQueue<string> Lines { get; } = new();

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Enqueue($"{logLevel}: {formatter(state, exception)}");
    }

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication()
        {
        }
    }
}
