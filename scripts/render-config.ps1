<#
.SYNOPSIS
    Renders the Sysmon configuration for one game client from the template.

.DESCRIPTION
    Replaces the placeholders in sysmon/rceguard-sysmon.template.xml with the client path and
    writes the result. Needs no admin rights and changes nothing on the system, so it can be
    used to review the configuration before installing it.

.PARAMETER ClientPath
    Full path of the monitored client, e.g. D:\Games\Warmane\Wow.exe.

.PARAMETER OutFile
    Where the rendered configuration is written.

.PARAMETER AllowMissingClient
    Skips the check that ClientPath exists (for reviewing a configuration on another machine).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ClientPath,
    [Parameter(Mandatory)] [string] $OutFile,
    [switch] $AllowMissingClient
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [IO.Path]::IsPathRooted($ClientPath)) {
    throw "ClientPath must be a full path, got '$ClientPath'."
}
if ([IO.Path]::GetExtension($ClientPath) -ne '.exe') {
    throw "ClientPath must point to an .exe, got '$ClientPath'."
}
if (-not $AllowMissingClient -and -not (Test-Path -LiteralPath $ClientPath -PathType Leaf)) {
    throw "Client not found: '$ClientPath'."
}
# Sysmon separates the values of "contains any" with ';' and the template is XML.
if ($ClientPath -match '[;<>"{}]') {
    throw "ClientPath contains a character that is not supported (; < > `" { }): '$ClientPath'."
}

$clientImage = [IO.Path]::GetFullPath($ClientPath)
$gameDir = [IO.Path]::GetDirectoryName($clientImage)
if ([string]::IsNullOrEmpty($gameDir)) {
    throw "ClientPath has no parent folder: '$ClientPath'."
}
if (-not $gameDir.EndsWith('\')) { $gameDir += '\' }

$templatePath = Join-Path $PSScriptRoot '..\sysmon\rceguard-sysmon.template.xml'
$template = [IO.File]::ReadAllText($templatePath)

$escape = { param($value) [Security.SecurityElement]::Escape($value) }
$rendered = $template.Replace('{{CLIENT_IMAGE}}', (& $escape $clientImage)).Replace('{{GAME_DIR}}', (& $escape $gameDir))

if ($rendered -match '\{\{[A-Z_]+\}\}') {
    throw "Unresolved placeholder in the template: $($Matches[0])"
}
# Fail here rather than inside Sysmon if the result is not well-formed XML.
$null = [xml] $rendered

$outDir = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutFile))
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
[IO.File]::WriteAllText($OutFile, $rendered, [Text.UTF8Encoding]::new($false))

Write-Host "Sysmon configuration for '$clientImage' written to '$OutFile'."
