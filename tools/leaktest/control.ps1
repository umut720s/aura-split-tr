# Send only to a maintainer-owned UDP receiver. No routes, service or WFP changes.
param(
    [Parameter(Mandatory=$true)][ValidateSet('direct','tunnel')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$RunDir,
    [Parameter(Mandatory=$true)][string]$LocalIP,
    [Parameter(Mandatory=$true)][string]$RemoteIP,
    [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$RemotePort,
    [ValidateRange(5,60)][int]$Seconds=8
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
$folder=(Resolve-Path -LiteralPath $RunDir).ProviderPath.TrimEnd('\')
if ($folder -eq $repo -or $folder.StartsWith($repo+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Controls must be stored outside repository.' }
$walk=$folder
while ($walk) {
    if ((Get-Item -LiteralPath $walk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point evidence path refused.' }
    $walk=Split-Path -Parent $walk
}
if (-not (Test-Path -LiteralPath (Join-Path $folder 'run.json'))) { throw 'Select an active capture run directory.' }
$local=[Net.IPAddress]::Parse($LocalIP);$remote=[Net.IPAddress]::Parse($RemoteIP)
$socket=New-Object Net.Sockets.UdpClient($local.AddressFamily)
try {
    $socket.Client.Bind((New-Object Net.IPEndPoint($local,0)))
    $socket.Connect($remote,$RemotePort)
    $process=Get-Process -Id $PID
    $record=@{mode=$Mode;nonce=('AURA-P0B-'+[guid]::NewGuid().ToString('N'));pid=$PID;process_started=$process.StartTime.ToUniversalTime().ToString('o');local_ip=$local.ToString();local_port=$socket.Client.LocalEndPoint.Port;remote_ip=$remote.ToString();remote_port=$RemotePort;started=[DateTime]::UtcNow.ToString('o')}
    $bytes=[Text.Encoding]::ASCII.GetBytes($record.nonce)
    $until=[DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $until) { [void]$socket.Send($bytes,$bytes.Length); Start-Sleep -Milliseconds 200 }
    $record['ended']=[DateTime]::UtcNow.ToString('o')
    $record | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $folder 'controls.jsonl') -Encoding UTF8
} finally { $socket.Dispose() }
Write-Host 'Control sent; this is not proof of delivery or tunnel routing. Correlate receiver nonce telemetry.'
