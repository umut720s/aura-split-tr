# Windows PowerShell 5.1. Run manually in an elevated maintainer shell.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$Scenario,
    [ValidateRange(1, 86400)][int]$Seconds = 120,
    [string]$OutDir = 'C:\AuraTest\evidence\leak',
    [string]$Adapter = 'Ethernet'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Pktmon {
    param([string[]]$Arguments)
    $result = & pktmon.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "pktmon failed: $($Arguments[0]) (exit $LASTEXITCODE)" }
    return $result
}

function Find-Component {
    param($Nic)
    # Match the physical NIC MAC first. Names/descriptions can be shared by multiple NICs.
    $mac = ($Nic.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($mac.Length -ne 12) { throw 'Physical adapter has no usable MAC address.' }
    $ids = New-Object 'System.Collections.Generic.HashSet[int]'
    $jsonOK = $false
    try {
        $raw = & pktmon.exe comp list --json 2>$null
        $jsonOK = $LASTEXITCODE -eq 0
    } catch {
        # PS 5.1 can turn native stderr into a terminating error under Stop.
        $raw = @()
    }
    if ($jsonOK) {
        try {
            $tree = ($raw -join "`n") | ConvertFrom-Json
            function Visit-Component {
                param($Node)
                if ($null -eq $Node -or $Node -is [string] -or $Node -is [ValueType]) { return }
                if ($Node -is [System.Array]) {
                    foreach ($child in $Node) { Visit-Component $child }
                    return
                }
                $id = $null
                $match = $false
                foreach ($prop in $Node.PSObject.Properties) {
                    # Culture-invariant keys matter on Turkish Windows (I/i casing).
                    $key = ($prop.Name -creplace '[^a-zA-Z]', '').ToLowerInvariant()
                    if ($key -cmatch '^(id|componentid)$' -and [string]$prop.Value -match '^\d+$') {
                        $id = [int]$prop.Value
                    }
                    if ($key -cmatch '^(mac|macaddress|physicaladdress)$' -and
                        (([string]$prop.Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $mac)) {
                        $match = $true
                    }
                }
                if ($match -and $null -ne $id) { [void]$ids.Add($id) }
                foreach ($prop in $Node.PSObject.Properties) { Visit-Component $prop.Value }
            }
            Visit-Component $tree
        } catch {
            # Builds differ in JSON schema/support; use built-in text listing below.
            $ids.Clear()
        }
    }
    if ($ids.Count -eq 0) {
        $lines = Invoke-Pktmon -Arguments @('list')
        foreach ($line in $lines) {
            # pktmon list: Id, MAC address, name. Avoid localized headings/descriptions.
            if ([string]$line -match '^\s*(\d+)\s+((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})\s+') {
                $id = [int]$Matches[1]
                $candidate = ($Matches[2] -replace '[-:]', '').ToUpperInvariant()
                if ($candidate -eq $mac) { [void]$ids.Add($id) }
            }
        }
    }
    if ($ids.Count -ne 1) {
        throw 'Could not uniquely map the physical NIC MAC to a pktmon component. No capture started.'
    }
    return @($ids)[0]
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script manually in an elevated Windows PowerShell shell.'
}
Get-Command pktmon.exe -ErrorAction Stop | Out-Null
$nic = @(Get-NetAdapter -Name $Adapter -Physical -ErrorAction Stop)
if ($nic.Count -ne 1 -or $nic[0].Name -eq 'AuraSplitTR') {
    throw 'Select exactly one physical NIC; TUN capture is forbidden.'
}
$component = Find-Component $nic[0]
$destination = [IO.Path]::GetFullPath($OutDir)
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
if ($destination -eq $repo -or $destination.StartsWith($repo + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Evidence must be stored outside the repository.'
}
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$stem = Join-Path $destination ('{0}_{1}_{2}' -f $Scenario, (Get-Date -Format 'yyyyMMdd_HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8))
$etl = $stem + '.etl'
$pcap = $stem + '.pcapng'
$sidecar = $stem + '.json'
$localIps = @(Get-NetIPAddress -InterfaceIndex $nic[0].ifIndex -ErrorAction Stop | Select-Object -ExpandProperty IPAddress)
$endpoint = $null
$endpointNote = 'unavailable; no whitelist'
# status is read-only; never start/stop the AURA service here.
$exe = Get-Command aurasplit.exe -ErrorAction SilentlyContinue
if ($null -eq $exe) {
    foreach ($candidate in @((Join-Path (Get-Location) 'aurasplit.exe'), (Join-Path $env:ProgramFiles 'AuraSplitTR\aurasplit.exe'))) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $exe = Get-Item -LiteralPath $candidate; break }
    }
}
if ($null -ne $exe) {
    try {
        $exePath = if ($exe -is [System.Management.Automation.ApplicationInfo]) { $exe.Source } else { $exe.FullName }
        $status = & $exePath status 2>$null
        foreach ($line in $status) {
            if ([string]$line -match '^\s*Sunucu:\s*(?:\[([^\]]+)\]|([0-9.]+)):(\d+)\s*$') {
                $addressText = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
                $port = [int]$Matches[3]
                $address = $null
                if ([Net.IPAddress]::TryParse($addressText, [ref]$address) -and $port -ge 1 -and $port -le 65535) {
                    $endpoint = @{ ip = $address.ToString(); port = $port }
                    $endpointNote = 'aurasplit.exe status / Sunucu'
                }
            }
        }
    } catch { $endpointNote = 'status failed; no whitelist' }
}
if ($null -eq $endpoint) { Write-Warning 'WireGuard endpoint unavailable. Analyzer will not whitelist any flow.' }
$metadata = [ordered]@{
    scenario = $Scenario; adapter = $Adapter; component_id = $component
    packet_size = 256; seconds = $Seconds; started_utc = [DateTime]::UtcNow.ToString('o')
    local_ips = $localIps; wireguard_endpoint = $endpoint; endpoint_source = $endpointNote
    capture_complete = $false
}
$metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $sidecar -Encoding UTF8
$cleanupFailed = $false
try {
    Invoke-Pktmon -Arguments @('filter', 'remove') | Out-Null
    # Component selection is the NIC filter. No IP/port filter: retain all protocols for leak detection.
    Invoke-Pktmon -Arguments @('start', '--capture', '--comp', [string]$component, '--pkt-size', '256', '--file-name', $etl, '--file-size', '1024', '--log-mode', 'multi-file') | Out-Null
    Write-Host "Capturing physical adapter '$Adapter' for $Seconds seconds. Perform scenario $Scenario now."
    Start-Sleep -Seconds $Seconds
} finally {
    # Independent cleanup attempts: a failed stop must not prevent filter removal.
    try { Invoke-Pktmon -Arguments @('stop') | Out-Null } catch { $cleanupFailed = $true; Write-Warning 'pktmon stop failed; maintainer must inspect pktmon status.' }
    try { Invoke-Pktmon -Arguments @('filter', 'remove') | Out-Null } catch { $cleanupFailed = $true; Write-Warning 'pktmon filter remove failed; maintainer must remove filters.' }
    # Include addresses acquired during a cable replug, as well as initial addresses.
    try {
        $metadata.local_ips = @($localIps + @(Get-NetIPAddress -InterfaceIndex $nic[0].ifIndex | Select-Object -ExpandProperty IPAddress) | Sort-Object -Unique)
    } catch { Write-Warning 'Could not refresh local IP inventory; initial addresses retained.' }
    $metadata['ended_utc'] = [DateTime]::UtcNow.ToString('o')
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $sidecar -Encoding UTF8
}
if ($cleanupFailed) { throw 'Capture cleanup failed; ETL retained privately for inspection.' }
# Multi-file mode must not silently produce a partial report when the size limit is hit.
$segments = @(Get-ChildItem -LiteralPath $destination -Filter ((Split-Path $stem -Leaf) + '*.etl'))
if ($segments.Count -ne 1) { throw 'Multiple/no ETL segments: retained privately. Repeat a shorter capture; no partial conversion.' }
Invoke-Pktmon -Arguments @('etl2pcap', $segments[0].FullName, '--out', $pcap) | Out-Null
if (-not (Test-Path -LiteralPath $pcap -PathType Leaf) -or (Get-Item -LiteralPath $pcap).Length -eq 0) {
    throw 'Conversion produced no pcapng; ETL retained privately.'
}
Remove-Item -LiteralPath $segments[0].FullName
$metadata.capture_complete = $true
$metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $sidecar -Encoding UTF8
Write-Output $pcap
