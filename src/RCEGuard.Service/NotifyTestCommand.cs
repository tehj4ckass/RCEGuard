using RCEGuard.Core.Notifications;

namespace RCEGuard.Service;

/// <summary>
/// 'RCEGuard.Service.exe --notify-test': sends one test notification to the configured ntfy topic
/// and says whether the server took it. Needs no administrator rights: the configuration is
/// readable for every user, and nothing on the machine is changed.
/// </summary>
internal static class NotifyTestCommand
{
    /// <summary>Runs the command. Returns the exit code of the process.</summary>
    /// <param name="options">Where the configuration is.</param>
    /// <param name="output">Receives what was done.</param>
    /// <param name="error">Receives what went wrong.</param>
    /// <param name="handler">Replaces the network in tests.</param>
    public static async Task<int> RunAsync(ServiceOptions options, TextWriter output, TextWriter error, HttpMessageHandler? handler = null)
    {
        Core.Configuration.GuardConfig config;
        string source;
        try
        {
            config = options.LoadConfig(out source);
        }
        catch (Exception ex) when (ex is FileNotFoundException or FormatException or IOException or UnauthorizedAccessException)
        {
            error.WriteLine(ex.Message);
            return 1;
        }

        if (config.Notify?.Ntfy is not { Enabled: true } ntfy)
        {
            error.WriteLine($"No ntfy topic is turned on in '{source}'. Add \"notify\": {{ \"ntfy\": {{ \"url\": \"https://<server>/<topic>\" }} }} to the configuration.");
            return 1;
        }

        using var notifier = new NtfyNotifier(ntfy, (_, _) => { }, handler);
        output.WriteLine($"Sending a test notification to ntfy at {notifier.Server} ...");
        var problem = await notifier.SendNowAsync(NotificationText.Test(Environment.MachineName), CancellationToken.None);
        if (problem is not null)
        {
            error.WriteLine($"It was not delivered: {problem}.");
            return 1;
        }

        output.WriteLine("The server took it. It should arrive on the devices that subscribe to the topic.");
        return 0;
    }
}
