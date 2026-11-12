using System.Globalization;
using System.Text;

namespace RCEGuard.Service;

/// <summary>
/// Writes the log lines to a text file, because a Windows service has no console.
/// One line per entry, same wording as the console. The file is replaced by a fresh one when it
/// grows past the limit; the previous one is kept as "&lt;name&gt;.1".
/// A log file that cannot be written never stops the guard: the provider then goes quiet.
/// </summary>
public sealed class FileLogProvider : ILoggerProvider
{
    private const long MaxBytes = 5 * 1024 * 1024;

    private readonly string path;
    private readonly object gate = new();
    private StreamWriter? writer;
    private bool broken;

    /// <summary>Creates a provider that appends to the given file.</summary>
    public FileLogProvider(string path) => this.path = path;

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    /// <inheritdoc />
    public void Dispose()
    {
        lock (gate)
        {
            writer?.Dispose();
            writer = null;
            broken = true;
        }
    }

    private void Write(string line)
    {
        lock (gate)
        {
            if (broken)
            {
                return;
            }

            try
            {
                writer ??= Open();
                writer.WriteLine(line);
                if (writer.BaseStream.Length > MaxBytes)
                {
                    writer.Dispose();
                    File.Move(path, path + ".1", overwrite: true);
                    writer = Open();
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                broken = true;
                writer?.Dispose();
                writer = null;
            }
        }
    }

    private StreamWriter Open()
    {
        // Readers (the acceptance test, later the tray app) may have the file open at the same time.
        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        return new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)) { AutoFlush = true };
    }

    private sealed class FileLogger(FileLogProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var level = logLevel switch
            {
                LogLevel.Trace => "trce",
                LogLevel.Debug => "dbug",
                LogLevel.Information => "info",
                LogLevel.Warning => "warn",
                LogLevel.Error => "fail",
                _ => "crit",
            };
            var text = formatter(state, exception).ReplaceLineEndings(" ");
            if (exception is not null)
            {
                text += " | " + exception.GetType().Name + ": " + exception.Message.ReplaceLineEndings(" ");
            }

            var time = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
            provider.Write($"{time} {level}: {category}[{eventId.Id}] {text}");
        }
    }
}
