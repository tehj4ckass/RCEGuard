using System.Globalization;

namespace RCEGuard.Core.Sysmon;

/// <summary>One event from the Sysmon operational log, reduced to what the rules need.</summary>
/// <param name="EventId">Sysmon event id (1 = ProcessCreate, 3 = NetworkConnect ...).</param>
/// <param name="RecordId">Record id in the event log; unique and increasing per machine.</param>
/// <param name="TimeCreated">Time the event was written.</param>
/// <param name="Data">The named values of the event's EventData block; names are case-insensitive.</param>
public sealed record SysmonEvent(
    int EventId,
    long RecordId,
    DateTimeOffset TimeCreated,
    IReadOnlyDictionary<string, string> Data)
{
    /// <summary>Name of the Sysmon rule that recorded the event (R1, client-start ...), may be empty.</summary>
    public string RuleName => Get("RuleName");

    /// <summary>Returns the value of a field, or an empty string if the event does not have it.</summary>
    public string Get(string name) => Data.TryGetValue(name, out var value) ? value : string.Empty;

    /// <summary>Returns a numeric field, or null if it is missing or not a number.</summary>
    public int? GetInt(string name) =>
        int.TryParse(Get(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;
}

/// <summary>Sysmon event ids used by RCEGuard.</summary>
public static class SysmonEventIds
{
    /// <summary>Process creation.</summary>
    public const int ProcessCreate = 1;

    /// <summary>Network connection.</summary>
    public const int NetworkConnect = 3;

    /// <summary>Process terminated.</summary>
    public const int ProcessTerminate = 5;

    /// <summary>Module loaded into a process.</summary>
    public const int ImageLoad = 7;

    /// <summary>Thread created in another process.</summary>
    public const int CreateRemoteThread = 8;

    /// <summary>Another process opened.</summary>
    public const int ProcessAccess = 10;

    /// <summary>File created or overwritten.</summary>
    public const int FileCreate = 11;

    /// <summary>Registry key or value created or deleted.</summary>
    public const int RegistryCreateDelete = 12;

    /// <summary>Registry value set.</summary>
    public const int RegistrySetValue = 13;

    /// <summary>Registry key or value renamed.</summary>
    public const int RegistryRename = 14;
}
