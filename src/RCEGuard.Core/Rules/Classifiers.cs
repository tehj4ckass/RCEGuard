namespace RCEGuard.Core.Rules;

/// <summary>What a registry write means for R4.</summary>
public enum RegistryConcern
{
    /// <summary>Not a location R4 cares about.</summary>
    None,

    /// <summary>Run, RunOnce and similar autostart keys.</summary>
    Autostart,

    /// <summary>Winlogon (Shell, Userinit ...).</summary>
    Winlogon,

    /// <summary>Image File Execution Options or SilentProcessExit (debugger hijack).</summary>
    ImageFileExecutionOptions,

    /// <summary>A service is created or its program, start type or account is changed.</summary>
    ServiceConfiguration,

    /// <summary>Some other write below Services; recorded for review only.</summary>
    ServicesOther,
}

/// <summary>Classifies registry paths as Sysmon reports them (HKLM\..., HKU\&lt;SID&gt;\...).</summary>
public static class RegistryRules
{
    private const string ServicesPrefix = @"HKLM\System\CurrentControlSet\Services\";

    // Windows bookkeeping that is written in the name of whichever process starts a child:
    // Background and Desktop Activity Moderator.
    private static readonly HashSet<string> BookkeepingServices = new(StringComparer.OrdinalIgnoreCase) { "bam", "dam" };

    private static readonly HashSet<string> ServiceConfigurationValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "ImagePath", "ServiceDll", "Start", "Type", "ObjectName", "FailureCommand",
    };

    /// <summary>
    /// Classifies a registry target. The root name is not compared, because the current user's hive
    /// appears as HKU\&lt;SID&gt; and 32-bit views add WOW6432Node.
    /// </summary>
    /// <param name="targetObject">TargetObject of the Sysmon event.</param>
    /// <param name="eventType">EventType of the Sysmon event (CreateKey, SetValue, DeleteValue ...).</param>
    public static RegistryConcern Classify(string targetObject, string eventType)
    {
        if (Has(targetObject, @"\Microsoft\Windows\CurrentVersion\Run")
            || Has(targetObject, @"\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"))
        {
            return RegistryConcern.Autostart;
        }

        if (Has(targetObject, @"\Microsoft\Windows NT\CurrentVersion\Winlogon"))
        {
            return RegistryConcern.Winlogon;
        }

        if (Has(targetObject, @"\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\")
            || Has(targetObject, @"\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\"))
        {
            return RegistryConcern.ImageFileExecutionOptions;
        }

        if (!targetObject.StartsWith(ServicesPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return RegistryConcern.None;
        }

        var segments = targetObject[ServicesPrefix.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || BookkeepingServices.Contains(segments[0]))
        {
            return RegistryConcern.None;
        }

        // Services\<name> itself being created, or Services\<name>\ImagePath, ...\Parameters\ServiceDll and the like.
        var createsService = segments.Length == 1 && string.Equals(eventType, "CreateKey", StringComparison.OrdinalIgnoreCase);
        var changesService = segments.Length is 2 or 3 && ServiceConfigurationValues.Contains(segments[^1]);
        return createsService || changesService ? RegistryConcern.ServiceConfiguration : RegistryConcern.ServicesOther;
    }

    /// <summary>True for events that remove a key or value instead of writing one.</summary>
    public static bool IsDeletion(string eventType) =>
        eventType.StartsWith("Delete", StringComparison.OrdinalIgnoreCase);

    private static bool Has(string text, string part) => text.Contains(part, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Path checks shared by the file and module rules. All comparisons ignore case.</summary>
public static class PathRules
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".pif", ".msi", ".jar",
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk",
    };

    /// <summary>True if both paths name the same file.</summary>
    public static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    /// <summary>True if the path lies below the directory (which must end with a backslash).</summary>
    public static bool IsUnder(string path, string directory) =>
        directory.Length > 0 && path.StartsWith(directory, StringComparison.OrdinalIgnoreCase);

    /// <summary>True if the file name ends with an extension that Windows runs or loads.</summary>
    public static bool HasExecutableExtension(string path)
    {
        var dot = path.LastIndexOf('.');
        var slash = path.LastIndexOf('\\');
        return dot > slash && ExecutableExtensions.Contains(path[dot..]);
    }

    /// <summary>True for a user's or the machine's Startup folder.</summary>
    public static bool IsStartupFolder(string path) =>
        path.Contains(@"\Microsoft\Windows\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True for locations a normal user can write to: user profiles, ProgramData and temp folders.
    /// The service runs as SYSTEM and does not know the player's profile path, so this matches by shape.
    /// </summary>
    public static bool IsUserWritableLocation(string path)
    {
        if (path.Length < 4 || path[1] != ':' || path[2] != '\\')
        {
            return true; // UNC and device paths count as user-writable: the client never loads code from there.
        }

        var rest = path[3..];
        return rest.StartsWith(@"Users\", StringComparison.OrdinalIgnoreCase)
            || rest.StartsWith(@"ProgramData\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Tmp\", StringComparison.OrdinalIgnoreCase);
    }
}
