using Microsoft.Extensions.Logging.Console;
using RCEGuard.Service;

if (args.Any(arg => arg is "--help" or "-h" or "/?"))
{
    Console.WriteLine(ServiceOptions.Usage);
    return 0;
}

var options = ServiceOptions.Parse(args, out var error);
if (options is null)
{
    Console.Error.WriteLine(error);
    Console.Error.WriteLine(ServiceOptions.Usage);
    return 2;
}

// The arguments are deliberately not passed on: they are not host configuration.
var builder = Host.CreateApplicationBuilder();
builder.Services.AddWindowsService(service => service.ServiceName = "RCEGuard");
builder.Logging.AddSimpleConsole(console =>
{
    console.SingleLine = true;
    console.TimestampFormat = "HH:mm:ss.fff ";
    console.ColorBehavior = LoggerColorBehavior.Default; // colours in a console, plain text when redirected
});
builder.Logging.AddFilter("Microsoft", LogLevel.Warning);
if (options.ReplayPath is null)
{
    // The live guard also logs to a file: as a Windows service it has no console.
    builder.Logging.AddProvider(new FileLogProvider(Path.Combine(options.DataDirectory, ServiceOptions.LogFileName)));
}

builder.Services.AddSingleton(options);
builder.Services.AddHostedService<GuardWorker>();

await builder.Build().RunAsync();
return Environment.ExitCode;
