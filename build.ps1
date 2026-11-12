<#
.SYNOPSIS
    Builds the solution (and runs the tests once there are any) with a real .NET 8 SDK.

.DESCRIPTION
    A machine can have only a .NET runtime on the PATH; 'dotnet build' then prints
    "No .NET SDKs were found" and still exits with code 0. This wrapper prefers the
    user-local SDK under %LOCALAPPDATA%\Microsoft\dotnet and fails loudly without an SDK.

.PARAMETER Configuration
    Build configuration, Release by default.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')] [string] $Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$localDotnet = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet'
if (Test-Path (Join-Path $localDotnet 'dotnet.exe')) {
    $env:DOTNET_ROOT = $localDotnet
    $env:PATH = "$localDotnet;$env:PATH"
}

$sdks = @(& dotnet --list-sdks 2>$null)
if ($sdks.Count -eq 0) {
    throw 'No .NET SDK found. Install the .NET 8 SDK (https://dotnet.microsoft.com/download/dotnet/8.0).'
}

$solution = Join-Path $PSScriptRoot 'RCEGuard.sln'
& dotnet build $solution -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "Build failed (exit code $LASTEXITCODE)." }

if (Test-Path (Join-Path $PSScriptRoot 'tests')) {
    & dotnet test $solution -c $Configuration --no-build --nologo
    if ($LASTEXITCODE -ne 0) { throw "Tests failed (exit code $LASTEXITCODE)." }
}
