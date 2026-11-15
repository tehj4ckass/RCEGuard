using System.Globalization;
using Microsoft.Data.Sqlite;

namespace RCEGuard.Tray.Model;

/// <summary>One finding as the service stored it in findings.db.</summary>
internal sealed record FindingRow(
    long Id, DateTimeOffset Time, string Rule, string Severity, string Action, string ActionTaken, string Profile, string Target, string Summary, long Repeats)
{
    /// <summary>True for findings the user is told about: everything that alerted or terminated.</summary>
    public bool Notifies => !string.Equals(Action, "Log", StringComparison.OrdinalIgnoreCase);

    /// <summary>Local time for the list.</summary>
    public string TimeText => Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    /// <summary>Severity in capitals, as in the log of the service.</summary>
    public string SeverityText => Severity.ToUpperInvariant();

    /// <summary>What the guard did; empty for findings that were only logged or alerted.</summary>
    public string ActionText => string.Equals(Action, "Kill", StringComparison.OrdinalIgnoreCase) ? ActionTaken : Action.ToLowerInvariant();

    /// <summary>"+3" if the finding repeated within the repeat window, otherwise empty.</summary>
    public string RepeatsText => Repeats > 0 ? $"+{Repeats}" : string.Empty;

    /// <summary>How serious the finding is, for sorting: 3 critical ... 0 info.</summary>
    public int Rank => Severity.ToUpperInvariant() switch { "CRITICAL" => 3, "HIGH" => 2, "MEDIUM" => 1, _ => 0 };
}

/// <summary>
/// Reads findings.db of the service. The file is opened read only: the tray application runs as a
/// normal user, who may read the data folder but not write to it.
/// </summary>
internal static class FindingReader
{
    private const string Columns = "id, time_utc, rule, severity, action, action_taken, profile, target, summary, repeats";

    /// <summary>The newest findings, newest first. Empty if there is no database yet.</summary>
    public static IReadOnlyList<FindingRow> ReadNewest(string databasePath, int limit) =>
        Read(databasePath, $"SELECT {Columns} FROM findings ORDER BY id DESC LIMIT $n;", limit);

    /// <summary>The findings stored after the one with this id, oldest first.</summary>
    public static IReadOnlyList<FindingRow> ReadAfter(string databasePath, long afterId) =>
        Read(databasePath, $"SELECT {Columns} FROM findings WHERE id > $n ORDER BY id;", afterId);

    /// <summary>The id of the newest finding; 0 if there is none.</summary>
    public static long MaxId(string databasePath)
    {
        if (!File.Exists(databasePath))
        {
            return 0;
        }

        using var connection = Open(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COALESCE(MAX(id), 0) FROM findings;";
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static List<FindingRow> Read(string databasePath, string sql, long parameter)
    {
        var rows = new List<FindingRow>();
        if (!File.Exists(databasePath))
        {
            return rows;
        }

        using var connection = Open(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$n", parameter);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var time = DateTimeOffset.TryParse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
                ? parsed
                : DateTimeOffset.MinValue;
            rows.Add(new FindingRow(
                reader.GetInt64(0), time, reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5),
                reader.GetString(6), reader.GetString(7), reader.GetString(8), reader.GetInt64(9)));
        }

        return rows;
    }

    private static SqliteConnection Open(string databasePath)
    {
        // No pooling: a pooled connection would keep the file open after the service was uninstalled.
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }
}

/// <summary>What the pop-up for new findings says.</summary>
internal static class ToastText
{
    /// <summary>Title and text for one or several new findings the user is told about.</summary>
    public static (string Title, string Text) For(IReadOnlyList<FindingRow> findings)
    {
        var worst = findings.OrderByDescending(finding => finding.Rank).ThenByDescending(finding => finding.Id).First();
        var profile = worst.Profile.Length > 0 ? $" [{worst.Profile}]" : string.Empty;
        return findings.Count == 1
            ? ($"RCEGuard: {worst.Rule} {worst.SeverityText}{profile}", Shorten(worst.Summary))
            : ($"RCEGuard: {findings.Count} new findings", Shorten($"Most serious: {worst.Rule} {worst.SeverityText}{profile}. {worst.Summary}"));
    }

    // Windows cuts the text of a pop-up; a path that is cut in the middle reads worse than one that ends in "...".
    private static string Shorten(string text) => text.Length <= 200 ? text : text[..197] + "...";
}
