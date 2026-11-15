using System.Net.Http.Headers;
using System.Text;
using System.Threading.Channels;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Notifications;

namespace RCEGuard.Service;

/// <summary>Takes notifications for the owner. Never blocks and never throws: the guard loop calls it.</summary>
internal interface INotifier
{
    /// <summary>Hands a notification over; it is delivered in the background.</summary>
    void Send(Notification notification);

    /// <summary>Waits until everything handed over was delivered or given up, at most <paramref name="timeout"/>.</summary>
    Task FlushAsync(TimeSpan timeout);
}

/// <summary>Notifies nobody.</summary>
internal sealed class NullNotifier : INotifier
{
    /// <summary>The one instance.</summary>
    public static readonly NullNotifier Instance = new();

    /// <inheritdoc />
    public void Send(Notification notification)
    {
    }

    /// <inheritdoc />
    public Task FlushAsync(TimeSpan timeout) => Task.CompletedTask;
}

/// <summary>
/// Sends notifications to an ntfy topic (HTTP POST, the message as body, title and priority as
/// headers). A notification that cannot be delivered is tried again twice and then given up; the
/// log says so once per outage, not once per notification.
/// </summary>
internal sealed class NtfyNotifier : INotifier, IDisposable
{
    private const int QueueLength = 100;

    private readonly NtfyConfig config;
    private readonly Action<LogLevel, string> log;
    private readonly HttpClient client;
    private readonly TimeSpan[] retryDelays;
    private readonly Channel<Notification> queue;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task pump;
    private int pending;
    private int undelivered;
    private bool failing;

    /// <summary>Creates the notifier and starts delivering in the background.</summary>
    /// <param name="config">Topic and token.</param>
    /// <param name="log">Receives what went wrong.</param>
    /// <param name="handler">Replaces the network in tests.</param>
    /// <param name="retryDelays">Waits before the second and third attempt; tests shorten them.</param>
    public NtfyNotifier(NtfyConfig config, Action<LogLevel, string> log, HttpMessageHandler? handler = null, TimeSpan[]? retryDelays = null)
    {
        this.config = config;
        this.log = log;
        this.retryDelays = retryDelays ?? [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10)];
        client = handler is null ? new HttpClient() : new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(10);
        // More than this at once is a flood: the newest are worth more than the oldest.
        queue = Channel.CreateBounded<Notification>(
            new BoundedChannelOptions(QueueLength) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true },
            _ =>
            {
                Interlocked.Decrement(ref pending);
                Interlocked.Increment(ref undelivered);
            });
        pump = Task.Run(PumpAsync);
    }

    /// <summary>The server the topic is on, without the topic: the topic name is all that protects an open topic.</summary>
    public string Server => Uri.TryCreate(config.Url, UriKind.Absolute, out var uri) ? $"{uri.Scheme}://{uri.Authority}" : "(invalid address)";

    /// <inheritdoc />
    public void Send(Notification notification)
    {
        Interlocked.Increment(ref pending);
        if (!queue.Writer.TryWrite(notification))
        {
            Interlocked.Decrement(ref pending);
        }
    }

    /// <inheritdoc />
    public async Task FlushAsync(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (Volatile.Read(ref pending) > 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(25);
        }
    }

    /// <summary>Sends one notification now, once. Returns null if the server took it, otherwise the reason.</summary>
    public async Task<string?> SendNowAsync(Notification notification, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, config.Url)
            {
                Content = new StringContent(notification.Body, Encoding.UTF8, "text/plain"),
            };
            // Header values must be ASCII.
            request.Headers.TryAddWithoutValidation("Title", Ascii(notification.Title));
            request.Headers.TryAddWithoutValidation("Priority", notification.Priority.ToString().ToLowerInvariant());
            request.Headers.TryAddWithoutValidation("Tags", notification.Priority >= NotificationPriority.Urgent ? "rotating_light" : "shield");
            if (!string.IsNullOrWhiteSpace(config.Token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", config.Token.Trim());
            }

            using var response = await client.SendAsync(request, cancellationToken);
            return response.IsSuccessStatusCode ? null : $"the server answered {(int)response.StatusCode} {response.ReasonPhrase}";
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return "no answer within 10 s";
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or UriFormatException)
        {
            return ex.InnerException?.Message ?? ex.Message;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        queue.Writer.TryComplete();
        stopping.Cancel();
        try
        {
            pump.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // The pump was cancelled.
        }

        client.Dispose();
        stopping.Dispose();
    }

    private static string Ascii(string text) => new([.. text.Select(c => c is >= ' ' and <= '~' ? c : '?')]);

    private async Task PumpAsync()
    {
        try
        {
            await foreach (var notification in queue.Reader.ReadAllAsync(stopping.Token))
            {
                var problem = await SendNowAsync(notification, stopping.Token);
                foreach (var delay in retryDelays)
                {
                    if (problem is null)
                    {
                        break;
                    }

                    await Task.Delay(delay, stopping.Token);
                    problem = await SendNowAsync(notification, stopping.Token);
                }

                Report(notification, problem);
                Interlocked.Decrement(ref pending);
            }
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
    }

    private void Report(Notification notification, string? problem)
    {
        if (problem is null)
        {
            var lost = Interlocked.Exchange(ref undelivered, 0);
            if (failing || lost > 0)
            {
                failing = false;
                log(LogLevel.Information, $"Notifications reach ntfy at {Server} again; {lost} could not be delivered before");
            }

            return;
        }

        Interlocked.Increment(ref undelivered);
        if (!failing)
        {
            failing = true;
            log(
                LogLevel.Warning,
                $"The notification '{notification.Title}' could not be delivered to ntfy at {Server}: {problem}. Further failures are only counted until one gets through; the findings themselves are in the log and the database");
        }
    }
}
