using System.Globalization;
using Microsoft.Data.Sqlite;
using RCEGuard.Core.Rules;

namespace RCEGuard.Service;

/// <summary>Writes findings and what was done about them to a SQLite database.</summary>
public sealed class FindingStore : IDisposable
{
    private readonly SqliteConnection connection;
    private readonly object gate = new();

    /// <summary>Opens (and if needed creates) the database file.</summary>
    public FindingStore(string databasePath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            CREATE TABLE IF NOT EXISTS findings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                time_utc     TEXT    NOT NULL,
                rule         TEXT    NOT NULL,
                severity     TEXT    NOT NULL,
                action       TEXT    NOT NULL,
                action_taken TEXT    NOT NULL,
                profile      TEXT    NOT NULL,
                image        TEXT    NOT NULL,
                pid          INTEGER,
                target       TEXT    NOT NULL,
                command_line TEXT    NOT NULL,
                summary      TEXT    NOT NULL,
                record_id    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_findings_time ON findings (time_utc);
            """;
        command.ExecuteNonQuery();

        // Added later: how often the finding repeated within the repeat window, and when last.
        AddColumnIfMissing("repeats", "INTEGER NOT NULL DEFAULT 0");
        AddColumnIfMissing("last_time_utc", "TEXT");
    }

    private void AddColumnIfMissing(string name, string definition)
    {
        using var probe = connection.CreateCommand();
        probe.CommandText = "SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name = $name;";
        probe.Parameters.AddWithValue("$name", name);
        if (Convert.ToInt64(probe.ExecuteScalar(), CultureInfo.InvariantCulture) > 0)
        {
            return;
        }

        using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE findings ADD COLUMN {name} {definition};";
        alter.ExecuteNonQuery();
    }

    /// <summary>Counts one repeat of a finding that was stored earlier.</summary>
    /// <param name="rowId">Row id returned by <see cref="Add"/>.</param>
    /// <param name="time">Time of the repeated event.</param>
    public void AddRepeat(long rowId, DateTimeOffset time)
    {
        lock (gate)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE findings SET repeats = repeats + 1, last_time_utc = $time WHERE id = $id;";
            command.Parameters.AddWithValue("$time", time.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$id", rowId);
            command.ExecuteNonQuery();
        }
    }

    /// <summary>Stores one finding together with a description of the action that was taken.</summary>
    /// <returns>The row id of the stored finding.</returns>
    public long Add(Finding finding, string actionTaken)
    {
        lock (gate)
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                """
                INSERT INTO findings (time_utc, rule, severity, action, action_taken, profile, image, pid, target, command_line, summary, record_id)
                VALUES ($time, $rule, $severity, $action, $taken, $profile, $image, $pid, $target, $commandLine, $summary, $recordId);
                """;
            command.Parameters.AddWithValue("$time", finding.Time.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$rule", finding.RuleId);
            command.Parameters.AddWithValue("$severity", finding.Severity.ToString());
            command.Parameters.AddWithValue("$action", finding.Action.ToString());
            command.Parameters.AddWithValue("$taken", actionTaken);
            command.Parameters.AddWithValue("$profile", finding.Profile);
            command.Parameters.AddWithValue("$image", finding.Image);
            command.Parameters.AddWithValue("$pid", (object?)finding.ProcessId ?? DBNull.Value);
            command.Parameters.AddWithValue("$target", finding.Target);
            command.Parameters.AddWithValue("$commandLine", finding.CommandLine);
            command.Parameters.AddWithValue("$summary", finding.Summary);
            command.Parameters.AddWithValue("$recordId", finding.RecordId);
            command.ExecuteNonQuery();

            using var id = connection.CreateCommand();
            id.CommandText = "SELECT last_insert_rowid();";
            return Convert.ToInt64(id.ExecuteScalar(), CultureInfo.InvariantCulture);
        }
    }

    /// <inheritdoc />
    public void Dispose() => connection.Dispose();
}
