namespace RCEGuard.Core.Learning;

/// <summary>What the guard saw a client do while its profile was in learning mode.</summary>
public sealed class LearnedProfile
{
    /// <summary>Name of the profile.</summary>
    public string Profile { get; set; } = string.Empty;

    /// <summary>Time of the first event that was noted.</summary>
    public DateTimeOffset? FirstEventUtc { get; set; }

    /// <summary>Time of the latest event that was noted.</summary>
    public DateTimeOffset? LastEventUtc { get; set; }

    /// <summary>How often the client was started.</summary>
    public int Sessions { get; set; }

    /// <summary>Addresses the client connected to.</summary>
    public List<LearnedRemote> Remotes { get; set; } = [];

    /// <summary>Host names the client asked the name service for.</summary>
    public List<LearnedHost> Hosts { get; set; } = [];

    /// <summary>Folders outside the game folder in which the client created files.</summary>
    public List<LearnedFolder> Folders { get; set; } = [];

    /// <summary>Other programs the client opened (not the ones it started itself).</summary>
    public List<LearnedProgram> Programs { get; set; } = [];

    /// <summary>
    /// The highest processor load of the client: busy cores on average over the time R8 looks at
    /// (1.0 = one core fully busy). 0 if no whole such stretch was measured.
    /// </summary>
    public double PeakCpuCores { get; set; }

    /// <summary>True if one of the lists was full and something was left out.</summary>
    public bool Truncated { get; set; }
}

/// <summary>An address and port the client connected to.</summary>
public sealed class LearnedRemote
{
    /// <summary>The remote address.</summary>
    public string Address { get; set; } = string.Empty;

    /// <summary>The remote port.</summary>
    public int Port { get; set; }

    /// <summary>How many connections were recorded.</summary>
    public int Count { get; set; }
}

/// <summary>A host name the client resolved.</summary>
public sealed class LearnedHost
{
    /// <summary>The name that was asked for.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The addresses the answers named.</summary>
    public List<string> Addresses { get; set; } = [];

    /// <summary>How many queries were recorded.</summary>
    public int Count { get; set; }
}

/// <summary>A folder outside the game folder in which the client created files.</summary>
public sealed class LearnedFolder
{
    /// <summary>The folder, with a trailing backslash.</summary>
    public string Folder { get; set; } = string.Empty;

    /// <summary>The extensions of the files, lower case, with the dot; an empty string for none.</summary>
    public List<string> Extensions { get; set; } = [];

    /// <summary>How many files were recorded.</summary>
    public int Count { get; set; }
}

/// <summary>Another program the client opened.</summary>
public sealed class LearnedProgram
{
    /// <summary>Full path of the program.</summary>
    public string Image { get; set; } = string.Empty;

    /// <summary>The access rights the client asked for, as Sysmon writes them (e.g. 0x1410).</summary>
    public List<string> Access { get; set; } = [];

    /// <summary>How many accesses were recorded.</summary>
    public int Count { get; set; }
}
