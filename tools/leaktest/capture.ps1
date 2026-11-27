# Windows PowerShell 5.1. Private evidence only; never reads a WireGuard configuration.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^L([1-9]|1[0-4])$')][string]$Scenario,
    [Parameter(Mandatory=$true)][string]$OutDir,
    # Verify this ID against `pktmon list --all` and the AURA adapter before running.
    [int]$TunComponentId=0,
    # Optional private file containing {"component_id":42}; may be supplied after activation.
    [string]$TunComponentFile,
    [Parameter(Mandatory=$true)][string]$PeerIP,
    [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$PeerPort,
    # Optional private JSON {"ip":"literal runtime peer", "port":51820}; reread each sample.
    [string]$PeerFile,
    [ValidateRange(1,86400)][int]$Seconds=120,
    [ValidateRange(250,5000)][int]$SampleMilliseconds=1000
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator shell required.' }
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
$destination=[IO.Path]::GetFullPath($OutDir).TrimEnd('\')
if ($destination -eq $repo -or $destination.StartsWith($repo+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Choose a private folder outside the repository.' }
# Reject reparse points along the destination: lexical checks alone permit junction escapes.
$walk=$destination
while ($walk) {
    if (Test-Path -LiteralPath $walk) {
        if ((Get-Item -LiteralPath $walk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point evidence path refused.' }
    }
    $walk=Split-Path -Parent $walk
}
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$run=Join-Path $destination ($Scenario+'_'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run | Out-Null
# Limit access to the invoking administrator and SYSTEM. Do not inherit broad parent ACLs.
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')) {
    $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $run -AclObject $acl
$script:commands=Join-Path $run 'commands.jsonl'
function Pkt {
    param([string[]]$Arguments)
    @{time=[DateTime]::UtcNow.ToString('o');exe='pktmon.exe';arguments=$Arguments} | ConvertTo-Json -Compress | Add-Content -LiteralPath $script:commands -Encoding UTF8
    $output=& pktmon.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'pktmon command failed; inspect private logs.' }
    return $output
}
function Save-Json($Value,$Path) { $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8 }
function Peer {
    $p=if ($PeerFile) { Get-Content -LiteralPath $PeerFile -Raw | ConvertFrom-Json } else { @{ip=$PeerIP;port=$PeerPort} }
    $address=[Net.IPAddress]::Parse($p.ip)
    if ([int]$p.port -lt 1 -or [int]$p.port -gt 65535) { throw 'Invalid peer port.' }
    return @{ip=$address.ToString();port=[int]$p.port}
}
function Physical-Component($Nic,$Listing) {
    $mac=($Nic.MacAddress -replace '[^0-9a-fA-F]','').ToUpperInvariant()
    $ids=@(foreach ($line in $Listing) {
        if ([string]$line -match '^\s*(\d+)\s+((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})\s+') {
            if (($Matches[2] -replace '[-:]','').ToUpperInvariant() -eq $mac) { [int]$Matches[1] }
        }
    })
    if ($ids.Count -ne 1) { throw 'Cannot uniquely map physical NIC MAC to pktmon component.' }
    return $ids[0]
}
$meta=[ordered]@{version=2;scenario=$Scenario;started=[DateTime]::UtcNow.ToString('o');capture_complete=$false;executable_manifest=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'executable_manifest.json') -Raw | ConvertFrom-Json);max_snapshot_gap=([Math]::Max(5,4*$SampleMilliseconds/1000));interfaces=@();inventory_errors=@();peer_source='operator supplied runtime literal; verify against engine/receiver telemetry'}
$known=@{}
$previous=@{}
function Snapshot {
    $time=[DateTime]::UtcNow.ToString('o')
    $physical=@(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    $tun=@(Get-NetAdapter -Name 'AuraSplitTR' -ErrorAction SilentlyContinue)
    $listing=@(Pkt -Arguments @('list','--all'))
    $listing | Set-Content -LiteralPath (Join-Path $run 'components-latest.txt') -Encoding UTF8
    foreach ($nic in @($physical)+@($tun)) {
        $kind=if ($nic.Name -eq 'AuraSplitTR') {'tun'} else {'physical'}
        $component=if ($kind -eq 'tun') {
            $selected=$TunComponentId
            if ($TunComponentFile -and (Test-Path -LiteralPath $TunComponentFile)) { $selected=[int](Get-Content -LiteralPath $TunComponentFile -Raw | ConvertFrom-Json).component_id }
            # A TUN mapping must be independently verified, never guessed from an alias.
            if ($selected -le 0) { continue }
            $selected
        } else {Physical-Component $nic $listing}
        if (-not ($listing | Where-Object { [string]$_ -match ('^\s*'+$component+'\s+') })) { throw 'Selected component not present.' }
        $key=[string]$nic.ifIndex+':'+[string]$component
        if ($kind -eq 'tun' -and @($meta.interfaces | Where-Object { $_.kind -eq 'tun' -and $_.guid -ne [string]$nic.InterfaceGuid }).Count) {
            $meta.inventory_errors+=@('TUN identity changed; component mapping must be reverified')
        }
        $ips=@(Get-NetIPAddress -InterfaceIndex $nic.ifIndex | Select-Object -ExpandProperty IPAddress)
        if (-not $known.ContainsKey($key)) {
            $item=@{if_index=[int]$nic.ifIndex;component_id=$component;kind=$kind;name=$nic.Name;guid=[string]$nic.InterfaceGuid;local_ips=$ips;pcapng=@();drops_pcapng=@()}
            $known[$key]=$item
            $meta.interfaces+=@($item)
        } else {
            if ($known[$key].guid -ne [string]$nic.InterfaceGuid) { $meta.inventory_errors+=@('Interface index/component reused by a different GUID') }
            $known[$key].local_ips=@($known[$key].local_ips+$ips | Sort-Object -Unique)
        }
    }
    $processes=@(Get-Process | ForEach-Object {
        $exe=$null;$started=$null
        try { $exe=$_.Path;$started=$_.StartTime.ToUniversalTime().ToString('o') } catch {}
        @{pid=$_.Id;exe=$exe;started=$started}
    })
    $current=@{}
    foreach ($p in $processes) {
        $key=[string]$p.pid+':'+[string]$p.started
        $current[$key]=$p
        if (-not $previous.ContainsKey($key)) {
            @{event='observed_start';time=$time;process=$p} | ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath (Join-Path $run 'process-events.jsonl') -Encoding UTF8
        }
    }
    foreach ($key in @($previous.Keys)) {
        if (-not $current.ContainsKey($key)) {
            @{event='observed_stop';time=$time;process=$previous[$key]} | ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath (Join-Path $run 'process-events.jsonl') -Encoding UTF8
        }
    }
    $script:previous=$current
    $sockets=@(Get-NetTCPConnection | ForEach-Object { @{proto=6;pid=$_.OwningProcess;local_ip=$_.LocalAddress;local_port=$_.LocalPort;remote_ip=$_.RemoteAddress;remote_port=$_.RemotePort;state=[string]$_.State} })
    $sockets+=@(Get-NetUDPEndpoint | ForEach-Object { @{proto=17;pid=$_.OwningProcess;local_ip=$_.LocalAddress;local_port=$_.LocalPort} })
    $snapshot=@{time=$time;active_physical=@($physical | ForEach-Object {[int]$_.ifIndex});adapters=@(Get-NetAdapter | Select-Object ifIndex,Name,InterfaceGuid,Status,MacAddress);routes=@(Get-NetRoute | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric);peer=(Peer);processes=$processes;sockets=$sockets}
    $snapshot | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath (Join-Path $run 'snapshots.jsonl') -Encoding UTF8
    Save-Json $meta (Join-Path $run 'run.json')
}
$started=$false
try {
    Snapshot
    if (-not ($meta.interfaces | Where-Object kind -eq 'physical')) { throw 'No active physical interface.' }
    # One global recorder; all components includes NICs appearing after the initial snapshot.
    # Full packets, both directions, no port/IP filters; multi-file avoids circular overwrite.
    Pkt -Arguments @('filter','remove') | Out-Null
    Pkt -Arguments @('start','--capture','--comp','all','--type','all','--pkt-size','0','--flags','0x033','--file-name',(Join-Path $run 'capture.etl'),'--file-size','1024','--log-mode','multi-file') | Out-Null
    $started=$true
    Write-Host 'Fiziksel kayıt başladı; aktivasyon öncesi trafik temel kayıt olarak saklanacak. Korumayı etkinleştirin, status çıktısında politika uygulandı ve tünel açık bilgisini doğrulayın; TUN bileşenini eşleyin. Bu doğrulamalardan sonra bu pencerede A tuşuna basın; ardından kontrol uyaranlarını çalıştırın.'
    $end=[DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $end) {
        try { Snapshot } catch { $meta.inventory_errors+=@([DateTime]::UtcNow.ToString('o')) }
        # Never pause inventory sampling while waiting for operator confirmation.
        if (-not $meta.Contains('activation') -and -not [Console]::IsInputRedirected -and [Console]::KeyAvailable) {
            $key=[Console]::ReadKey($true)
            if ($key.Key -eq [ConsoleKey]::A) {
                $mapped=@($meta.interfaces | Where-Object kind -eq 'tun').Count -gt 0
                $up=@(Get-NetAdapter -Name 'AuraSplitTR' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up').Count -gt 0
                if ($mapped -and $up) {
                    $meta['activation']=@{time=[DateTime]::UtcNow.ToString('o');source='capture_operator_confirmation';policy_applied=$true;tunnel_up=$true}
                    Save-Json $meta (Join-Path $run 'run.json')
                    Write-Host 'Aktivasyon sınırı kaydedildi. Artık test ve pozitif kontrol uyaranlarını çalıştırın.'
                } else { Write-Host 'Aktivasyon kaydedilmedi: açık ve eşlenmiş TUN bekleniyor.' }
            }
        }
        Start-Sleep -Milliseconds $SampleMilliseconds
    }
    $meta.capture_complete=$true
} finally {
    if ($started) {
        try { Pkt -Arguments @('counters','--json') | Set-Content -LiteralPath (Join-Path $run 'counters.json') -Encoding UTF8 } catch { $meta.capture_complete=$false }
        try { Pkt -Arguments @('stop') | Set-Content -LiteralPath (Join-Path $run 'stop.txt') -Encoding UTF8 } catch { $meta.capture_complete=$false }
        try { Snapshot } catch { $meta.capture_complete=$false }
    }
    $meta['ended']=[DateTime]::UtcNow.ToString('o')
    Save-Json $meta (Join-Path $run 'run.json')
}
# Keep every segment and the raw ETLs. Conversion never collapses different interfaces.
try {
    $segments=@(Get-ChildItem -LiteralPath $run -Filter '*.etl')
    if ($segments.Count -eq 0) { throw 'No ETL segments.' }
    foreach ($segment in $segments) {
        Pkt -Arguments @('etl2txt',$segment.FullName,'--out',($segment.FullName+'.txt'),'--timestamp','--metadata','--verbose') | Out-Null
        Pkt -Arguments @('etl2txt',$segment.FullName,'--stats') | Set-Content -LiteralPath ($segment.FullName+'.stats.txt') -Encoding UTF8
        foreach ($iface in $meta.interfaces) {
            $base=$segment.BaseName+'-if'+$iface.if_index+'-c'+$iface.component_id
            $pcap=$base+'.pcapng';$drop=$base+'-drops.pcapng'
            Pkt -Arguments @('etl2pcap',$segment.FullName,'--component-id',[string]$iface.component_id,'--out',(Join-Path $run $pcap)) | Out-Null
            Pkt -Arguments @('etl2pcap',$segment.FullName,'--component-id',[string]$iface.component_id,'--drop-only','--out',(Join-Path $run $drop)) | Out-Null
            $iface.pcapng+=@($pcap);$iface.drops_pcapng+=@($drop)
        }
    }
} catch { $meta.capture_complete=$false; throw } finally { Save-Json $meta (Join-Path $run 'run.json') }
Write-Host 'Private capture complete. Review ETL loss statistics and component/edge mappings before analysis.'
