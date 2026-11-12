#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Shows the Sysmon events the RCEGuard sensor recorded.

.DESCRIPTION
    Reads Microsoft-Windows-Sysmon/Operational (administrators only) and prints one line per
    event: time, event id, RCEGuard rule name and the fields that matter for that event type.
    Meant for checking milestone M1 with the simulator; the service replaces it in M2.

.PARAMETER Last
    Number of most recent events to show first.

.PARAMETER Follow
    Keeps running and prints new events as they arrive (Ctrl+C to stop).

.PARAMETER Raw
    Prints the full event XML instead of one line (e.g. to save test fixtures).
#>
[CmdletBinding()]
param(
    [int] $Last = 30,
    [switch] $Follow,
    [switch] $Raw
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$logName = 'Microsoft-Windows-Sysmon/Operational'

# Fields worth showing per event id; everything else is in -Raw.
$fieldsById = @{
    1  = 'Image', 'CommandLine', 'ParentImage'
    3  = 'Image', 'DestinationIp', 'DestinationPort', 'DestinationHostname'
    5  = 'Image'
    7  = 'ImageLoaded', 'Signed', 'Signature'
    8  = 'SourceImage', 'TargetImage', 'StartModule'
    10 = 'SourceImage', 'TargetImage', 'GrantedAccess'
    11 = 'Image', 'TargetFilename'
    12 = 'EventType', 'Image', 'TargetObject'
    13 = 'EventType', 'Image', 'TargetObject', 'Details'
    14 = 'EventType', 'Image', 'TargetObject', 'NewName'
    22 = 'Image', 'QueryName', 'QueryResults'
}

function Format-SysmonEvent($entry) {
    if ($Raw) { return $entry.ToXml() }

    $data = @{}
    foreach ($node in ([xml] $entry.ToXml()).Event.EventData.Data) {
        $data[$node.Name] = $node.InnerText
    }
    $ruleName = if ($data.ContainsKey('RuleName') -and $data['RuleName']) { $data['RuleName'] } else { '-' }
    $wanted = if ($fieldsById.ContainsKey($entry.Id)) { $fieldsById[$entry.Id] } else { @() }
    $details = foreach ($name in $wanted) {
        if ($data.ContainsKey($name) -and $data[$name]) { "$name=$($data[$name])" }
    }
    '{0:HH:mm:ss.fff}  id={1,-2}  rule={2,-12}  {3}' -f $entry.TimeCreated, $entry.Id, $ruleName, ($details -join '  ')
}

$recent = @(Get-WinEvent -LogName $logName -MaxEvents $Last -ErrorAction SilentlyContinue)
[array]::Reverse($recent)
$lastRecordId = 0
foreach ($entry in $recent) {
    Format-SysmonEvent $entry
    $lastRecordId = $entry.RecordId
}
if ($recent.Count -eq 0) { Write-Host "No events in $logName yet." }

if (-not $Follow) { return }

Write-Host '--- waiting for new events (Ctrl+C to stop) ---'
while ($true) {
    Start-Sleep -Milliseconds 500
    $query = "*[System[EventRecordID > $lastRecordId]]"
    $new = @(Get-WinEvent -LogName $logName -FilterXPath $query -Oldest -ErrorAction SilentlyContinue)
    foreach ($entry in $new) {
        Format-SysmonEvent $entry
        $lastRecordId = $entry.RecordId
    }
}
