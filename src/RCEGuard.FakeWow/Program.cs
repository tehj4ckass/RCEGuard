using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.Win32;

namespace RCEGuard.FakeWow;

/// <summary>
/// Simulator for RCEGuard: runs under the name Wow.exe and triggers, one per switch, the
/// behaviour a detection rule looks for. Everything it does is harmless and is undone
/// before it exits. It contains no exploit and touches no other process.
/// </summary>
internal static class Program
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValueName = "RCEGuardTest";
    private const string DropFileName = "rceguard-test.exe";

    private static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "/?")
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        try
        {
            switch (args[0])
            {
                case "--spawn":
                    Spawn();
                    break;
                case "--connect":
                    Connect(args.Length > 1 ? args[1] : "1.1.1.1:443");
                    break;
                case "--drop":
                    Drop();
                    break;
                case "--runkey":
                    RunKey();
                    break;
                case "--cpu":
                    Cpu(args.Length > 1 ? int.Parse(args[1]) : 300);
                    break;
                case "--miner-args":
                    MinerArgs();
                    break;
                default:
                    Console.Error.WriteLine($"Unknown scenario '{args[0]}'.");
                    PrintUsage();
                    return 2;
            }
        }
        catch (Exception ex)
        {
            // A blocked scenario (e.g. child process creation disallowed) is a valid outcome.
            Console.WriteLine($"Scenario {args[0]} was stopped: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            RCEGuard simulator (runs as Wow.exe). One scenario per call:

              --spawn                 start 'cmd.exe /c echo'            -> R1 child process
              --connect [host:port]   open a TCP connection (1.1.1.1:443) -> R2 unknown remote
              --drop                  create %APPDATA%\rceguard-test.exe -> R3 file outside game folder
              --runkey                set and remove an HKCU Run value    -> R4 autostart key
              --cpu [seconds]         full load on all cores (300 s)      -> R8 background CPU
              --miner-args            child with 'stratum+tcp://' argument -> R9 miner command line
            """);
    }

    private static void Spawn()
    {
        Console.WriteLine("R1: starting a child process (cmd.exe /c echo).");
        RunChild("/c echo RCEGuard child process test");
    }

    private static void MinerArgs()
    {
        Console.WriteLine("R9: starting a child process with a miner-like command line.");
        RunChild("/c echo stratum+tcp://rceguard-test.invalid:3333 --donate-level 1");
    }

    private static void RunChild(string arguments)
    {
        var startInfo = new ProcessStartInfo("cmd.exe", arguments) { UseShellExecute = false };
        using var child = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The child process could not be started.");
        child.WaitForExit();
        Console.WriteLine($"Child {child.Id} exited with code {child.ExitCode}.");
    }

    private static void Connect(string endpoint)
    {
        var separator = endpoint.LastIndexOf(':');
        if (separator <= 0 || !int.TryParse(endpoint[(separator + 1)..], out var port))
        {
            throw new ArgumentException($"Expected host:port, got '{endpoint}'.");
        }

        var host = endpoint[..separator];
        Console.WriteLine($"R2: connecting to {host}:{port}.");
        using var client = new TcpClient();
        if (!client.ConnectAsync(host, port).Wait(TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException($"No connection to {host}:{port} within 5 s.");
        }

        Console.WriteLine("Connected; closing again without sending data.");
    }

    private static void Drop()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), DropFileName);
        Console.WriteLine($"R3: creating {path}.");
        try
        {
            // Plain text, not a program: only the name and location matter to the sensor.
            File.WriteAllText(path, "RCEGuard test file - safe to delete.");
            Thread.Sleep(500);
        }
        finally
        {
            File.Delete(path);
            Console.WriteLine("Test file removed.");
        }
    }

    private static void RunKey()
    {
        Console.WriteLine($@"R4: setting HKCU\{RunKeyPath}\{RunValueName}.");
        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true)
            ?? throw new InvalidOperationException("The Run key could not be opened.");
        try
        {
            // The value never survives this call, and it would only start a no-op.
            key.SetValue(RunValueName, "cmd.exe /c rem RCEGuard test");
            Thread.Sleep(500);
        }
        finally
        {
            key.DeleteValue(RunValueName, throwOnMissingValue: false);
            Console.WriteLine("Run value removed.");
        }
    }

    private static void Cpu(int seconds)
    {
        Console.WriteLine($"R8: full load on {Environment.ProcessorCount} cores for {seconds} s (Ctrl+C to stop).");
        var end = Stopwatch.GetTimestamp() + (seconds * Stopwatch.Frequency);
        var threads = new Thread[Environment.ProcessorCount];
        for (var i = 0; i < threads.Length; i++)
        {
            threads[i] = new Thread(() =>
            {
                while (Stopwatch.GetTimestamp() < end)
                {
                    Thread.SpinWait(10_000);
                }
            })
            { IsBackground = true, Priority = ThreadPriority.BelowNormal };
            threads[i].Start();
        }

        foreach (var thread in threads)
        {
            thread.Join();
        }

        Console.WriteLine("Load finished.");
    }
}
