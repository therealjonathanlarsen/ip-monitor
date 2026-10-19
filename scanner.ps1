#Requires -Version 5.1
<#
Network Security Auditor - local, read-only diagnostics.
Windows 10/11, PowerShell 5.1+. No credential extraction, no remote subnet scan.
External services: ipify, ipwho.is, api.ipapi.is (optional key), bash.ws,
OpenAI API (optional), Telegram Bot API (opt-in).
Run ONLY on machines and networks you own or administer.
#>
[CmdletBinding()]
param(
    [switch]$SendTelegram,
    [switch]$IncludeLocalDetails,
    [switch]$AttachJson,
    [switch]$SkipBrowserTest,
    [switch]$CheckGatewayPorts,
    [string]$OutputDir = (Join-Path $env:USERPROFILE 'Documents\NetworkAudit'),
    [string]$TelegramBotToken = "8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk",
    [string]$TelegramChatIds = "8640543929,8362186234",
    [string]$IpIntelApiKey = $env:IPAPI_IS_KEY,
    [string]$OpenAiApiKey = $env:OPENAI_API_KEY,
    [string]$OpenAiModel = 'gpt-5.6-terra'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$errorsList = New-Object 'System.Collections.Generic.List[string]'
$findings = New-Object 'System.Collections.Generic.List[object]'

function Safe([scriptblock]$Action, [string]$What) {
    try { return (& $Action) } catch {
        $script:errorsList.Add("${What}: $($_.Exception.Message)")
        return $null
    }
}
function OneLine($s, [string]$Default = 'unknown') {
    if ($null -eq $s -or [string]::IsNullOrWhiteSpace([string]$s)) { return $Default }
    return ([string]$s).Trim()
}
function Html($s) {
    if ($null -eq $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$s)
}
function Add-Finding([string]$Level, [string]$Ru, [string]$En, [int]$Penalty) {
    $script:findings.Add([ordered]@{level=$Level;ru=$Ru;en=$En;penalty=$Penalty})
}
function Get-JsonUrl([string]$Url) {
    Invoke-RestMethod -Uri $Url -TimeoutSec 12 -Headers @{'User-Agent'='NetworkSecurityAuditor/1.0'}
}
function Get-TextUrl([string]$Url) {
    return (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10).Content.Trim()
}
function Ping-Sample([string]$HostName, [int]$Count=3) {
    $p = New-Object System.Net.NetworkInformation.Ping
    $times = @()
    for ($i=0; $i -lt $Count; $i++) {
        try {
            $r = $p.Send($HostName,1200)
            if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $times += [int]$r.RoundtripTime }
        } catch {}
    }
    $p.Dispose()
    $avg=$null
    if ($times.Count -gt 0) { $avg=[math]::Round((($times | Measure-Object -Average).Average),1) }
    return [ordered]@{sent=$Count;received=$times.Count;loss_percent=[math]::Round(100*($Count-$times.Count)/$Count,1);avg_ms=$avg;samples_ms=@($times)}
}
function Tcp-Connect([string]$HostName,[int]$Port,[int]$TimeoutMs=600) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async=$client.BeginConnect($HostName,$Port,$null,$null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs,$false)) { return $false }
        $client.EndConnect($async); return $true
    } catch { return $false }
    finally { $client.Close() }
}
function Get-WebRtcBrowserTest {
    # An actual browser ICE/STUN test on a localhost-only HTTP listener.
    # Some corporate policies block the listener/STUN; that is 'unknown', not 'safe'.
    $listener=$null
    try {
        $portPicker=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
        $portPicker.Start(); $port=$portPicker.LocalEndpoint.Port; $portPicker.Stop()
        $listener=New-Object Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:${port}/")
        $listener.Start()
        $htmlPage=@'
<!doctype html><html lang="ru"><meta charset="utf-8"><title>WebRTC network test</title>
<style>body{font:16px system-ui;max-width:660px;margin:9vh auto;padding:18px;background:#101727;color:#f5f7ff}article{border:1px solid #34415a;border-radius:14px;padding:24px}small{color:#b5c0d6}</style>
<article><h2>🧪 WebRTC / ICE / STUN</h2><p id="status">Тест браузера выполняется...</p>
<small>Тест запускается только в этом браузере. Извлекаются ICE-кандидаты, не cookies, пароли и не история.</small><pre id="result"></pre></article>
<script>
(async function(){
 const status=document.querySelector('#status'),result=document.querySelector('#result');
 let candidates=[],failure=null;
 try {
  if(!window.RTCPeerConnection) throw Error('WebRTC API disabled/unavailable');
  const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun.cloudflare.com:3478'}]});
  pc.onicecandidate=(e)=>{if(!e.candidate)return; const s=e.candidate.candidate;
   const m=s.match(/(?:^|\s)([a-fA-F0-9:.%-]+|[a-fA-F0-9-]+\.local)\s+\d+\s+typ\s+(host|srflx|relay|prflx)/i);
   if(m)candidates.push({address:m[1],type:m[2]});};
  pc.createDataChannel('probe');
  await pc.setLocalDescription(await pc.createOffer());
  await Promise.race([new Promise(r=>{if(pc.iceGatheringState==='complete')r();else pc.addEventListener('icegatheringstatechange',()=>{if(pc.iceGatheringState==='complete')r()})}),new Promise(r=>setTimeout(r,8500))]);
  pc.close();
 } catch(e){failure=String(e.message||e)}
 const value={status:failure?'error':'finished',error:failure,candidates:[...new Map(candidates.map(c=>[c.type+'|'+c.address,c])).values()]};
 result.textContent=JSON.stringify(value,null,2);
 try {const r=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
 status.textContent=r.ok?'Тест завершён. Можно закрыть вкладку.':'Не удалось передать результат программе.';}
 catch(e){status.textContent='Результат не передан программе. '+e.message}
})();
</script></html>
'@
        Start-Process "http://127.0.0.1:${port}/" | Out-Null
        $deadline=(Get-Date).AddSeconds(23)
        while ((Get-Date) -lt $deadline) {
            $remaining=[math]::Max(100,[int](($deadline-(Get-Date)).TotalMilliseconds))
            $task=$listener.GetContextAsync()
            if (-not $task.Wait($remaining)) { break }
            $ctx=$task.Result
            if ($ctx.Request.HttpMethod -eq 'GET') {
                $body=[Text.Encoding]::UTF8.GetBytes($htmlPage)
                $ctx.Response.ContentType='text/html; charset=utf-8'
                $ctx.Response.ContentLength64=$body.Length
                $ctx.Response.OutputStream.Write($body,0,$body.Length)
                $ctx.Response.Close()
            } elseif ($ctx.Request.HttpMethod -eq 'POST' -and $ctx.Request.Url.AbsolutePath -eq '/submit') {
                if ($ctx.Request.ContentLength64 -gt 16384) { $ctx.Response.StatusCode=413; $ctx.Response.Close(); break }
                $reader=New-Object IO.StreamReader($ctx.Request.InputStream,[Text.Encoding]::UTF8)
                $raw=$reader.ReadToEnd(); $reader.Dispose()
                $ctx.Response.StatusCode=200; $ctx.Response.Close()
                return ($raw | ConvertFrom-Json)
            } else { $ctx.Response.StatusCode=404; $ctx.Response.Close() }
        }
        return [pscustomobject]@{status='timeout';error='Browser did not return WebRTC result';candidates=@()}
    } catch {
        return [pscustomobject]@{status='unavailable';error=$_.Exception.Message;candidates=@()}
    } finally { if ($null -ne $listener) { try {$listener.Stop();$listener.Close()}catch{} } }
}
function Send-Tg([string]$Content) {
    if (-not $SendTelegram) { return }
    if ([string]::IsNullOrWhiteSpace($TelegramBotToken) -or [string]::IsNullOrWhiteSpace($TelegramChatIds)) {
        throw 'For Telegram, set TG_BOT_TOKEN and TG_CHAT_IDS environment variables.'
    }
    $targetIds=$TelegramChatIds -split '[,; ]+' | Where-Object { $_ }
    foreach ($id in $targetIds) {
        $uri="https://api.telegram.org/bot${TelegramBotToken}/sendMessage"
        $req=@{chat_id=$id;text=$Content;parse_mode='HTML';disable_web_page_preview=$true}
        $bytes=[Text.Encoding]::UTF8.GetBytes(($req | ConvertTo-Json -Depth 4 -Compress))
        Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 20 | Out-Null
    }
}
function Send-TgLong([string]$Title,[string]$Content) {
    if (-not $SendTelegram) { return }
    $heading='<b>━━ '+(Html $Title)+' ━━</b>'
    $buffer=$heading
    foreach ($line in ($Content -split "`r?`n")) {
        $line=[string]$line
        if ($line -match '^([^:]{1,52}):\s*(.*)$') {
            $formatted='<b>'+(Html $Matches[1])+'</b>: <code>'+(Html $Matches[2])+'</code>'
        } elseif ($line -match '^[^a-zа-я0-9]*[A-ZА-Я][A-ZА-Я\s/&•0-9—-]+$' -and $line.Length -lt 80) {
            $formatted='<b>'+(Html $line)+'</b>'
        } else {
            $formatted=Html $line
        }
        # Respect Telegram's 4096-character post-entity limit.
        if ($formatted.Length -gt 3300) {
            $formatted=(Html ($line.Substring(0,[math]::Min(600,$line.Length))))+' ... [truncated in Telegram; see local TXT/JSON]'
        }
        if ($buffer.Length+$formatted.Length+1 -gt 3700) {
            Send-Tg $buffer
            $buffer=$heading
        }
        $buffer+="`n"+$formatted
    }
    if ($buffer -ne $heading) { Send-Tg $buffer }
}
function Send-TgDocument([string]$Path) {
    if (-not ($SendTelegram -and $AttachJson)) { return }
    # HttpClient multipart POST is compatible with Windows PowerShell 5.1.
    $http=New-Object System.Net.Http.HttpClient
    try {
        foreach ($chatId in ($TelegramChatIds -split '[,; ]+' | Where-Object { $_ })) {
            $form=New-Object System.Net.Http.MultipartFormDataContent
            $form.Add(([System.Net.Http.StringContent]::new([string]$chatId)),'chat_id')
            $bytes=[IO.File]::ReadAllBytes($Path)
            $fileBytes=[System.Net.Http.ByteArrayContent]::new([byte[]]$bytes)
            $fileBytes.Headers.ContentType=[System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
            $form.Add($fileBytes,'document',[IO.Path]::GetFileName($Path))
            $res=$http.PostAsync("https://api.telegram.org/bot${TelegramBotToken}/sendDocument",$form).GetAwaiter().GetResult()
            $res.EnsureSuccessStatusCode() | Out-Null
            $form.Dispose()
        }
    } finally {$http.Dispose()}
}

Write-Host 'Network Security Auditor | local, read-only audit' -ForegroundColor Cyan
Write-Host '[1/6] Interfaces, gateway, WAN IP, GeoIP' -ForegroundColor Cyan
$route=Safe { Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 } 'Default route'
$adapter=$null;$config=$null
if ($route) {
    $adapter=Safe { Get-NetAdapter -InterfaceIndex $route.InterfaceIndex } 'Adapter'
    $config=Safe { Get-NetIPConfiguration -InterfaceIndex $route.InterfaceIndex } 'IP configuration'
}
$gateway=if($route){OneLine $route.NextHop}else{'unknown'}
$allAdapters=Safe { @(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,InterfaceIndex) } 'Adapters list'
$dnsList=@()
if($route) { $dnsList=@(Safe { (Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex).ServerAddresses | Where-Object {$_} } 'DNS settings' | Where-Object {$_}) }
$ipv4=if($config){@($config.IPv4Address | ForEach-Object {$_.IPv4Address})}else{@()}
$ipv6=if($config){@($config.IPv6Address | ForEach-Object {$_.IPv6Address} | Where-Object {$_ -notlike 'fe80:*'})}else{@()}
$publicV4=Safe { Get-TextUrl 'https://api4.ipify.org' } 'Public IPv4'
$publicV6=Safe { Get-TextUrl 'https://api6.ipify.org' } 'Public IPv6'
$geo=$null
if($publicV4) { $geo=Safe { Get-JsonUrl ("https://ipwho.is/{0}" -f [uri]::EscapeDataString($publicV4)) } 'GeoIP lookup' }
$intel=$null
if($publicV4) {
    if($IpIntelApiKey) {
        $intel=Safe { Invoke-RestMethod -Method Post -Uri 'https://api.ipapi.is/' -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes((@{q=$publicV4;key=$IpIntelApiKey}|ConvertTo-Json -Compress))) -TimeoutSec 15 } 'IP risk intelligence'
    } else {
        $intel=Safe { Get-JsonUrl ("https://api.ipapi.is/?q={0}" -f [uri]::EscapeDataString($publicV4)) } 'IP/ASN intelligence'
    }
}
$isp=if($geo -and $geo.connection){OneLine $geo.connection.isp}else{'unknown'}
$asn=if($geo -and $geo.connection){OneLine $geo.connection.asn}else{'unknown'}
$company=if($intel){if($intel.company -is [string]){$intel.company}else{OneLine $intel.company.name}}else{'unknown'}
$net=@{
 public_ipv4=$publicV4;public_ipv6=$publicV6
 location=@{
  country_code=if($geo){$geo.country_code}else{$null};country=if($geo){$geo.country}else{$null}
  region=if($geo){$geo.region}else{$null};city=if($geo){$geo.city}else{$null}
  street='Unavailable from IP geolocation';house='Unavailable from IP geolocation'
  postal=if($geo){$geo.postal}else{$null}
  timezone=if($geo -and $geo.timezone){$geo.timezone.id}else{$null}
  accuracy='approximate, not a verified physical address'
 }
 isp=$isp;asn=$asn;registered_company=$company
 vpn=if($IpIntelApiKey -and $intel){$intel.is_vpn}else{$null}
 proxy=if($IpIntelApiKey -and $intel){$intel.is_proxy}else{$null}
 tor=if($IpIntelApiKey -and $intel){$intel.is_tor}else{$null}
 datacenter=if($IpIntelApiKey -and $intel){$intel.is_datacenter}else{$null}
 active_adapter=if($adapter){$adapter.Name}else{$null}
 adapter_description=if($adapter){$adapter.InterfaceDescription}else{$null}
 link_speed=if($adapter){[string]$adapter.LinkSpeed}else{$null}
 local_ipv4=@($ipv4);local_ipv6=@($ipv6)
 gateway=$gateway;dns_configured=@($dnsList)
 all_adapters=@($allAdapters)
}
$os=Safe { Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption } 'Operating system'

Write-Host '[2/6] Wi-Fi, latency, router reachability and heuristics' -ForegroundColor Cyan
$wifi=@{signal_percent=$null;channel=$null;connection='not Wi-Fi or unavailable'}
$wlan=Safe { (& netsh wlan show interfaces 2>$null | Out-String) } 'Wi-Fi netsh'
if($wlan) {
    if($wlan -match '(?im)^\s*(?:Signal|Сигнал)\s*:\s*(\d+)\s*%') {$wifi.signal_percent=[int]$Matches[1];$wifi.connection='Wi-Fi connected'}
    if($wlan -match '(?im)^\s*(?:Channel|Канал)\s*:\s*(\d+)') {$wifi.channel=[int]$Matches[1]}
}
$pingWan=Ping-Sample '1.1.1.1' 3
$pingGate=if($gateway -ne 'unknown'){Ping-Sample $gateway 3}else{$null}
$gatewayPorts=[ordered]@{}
if($CheckGatewayPorts -and $gateway -ne 'unknown') {
    foreach($p in @(21,22,23,80,443,8080,8443)) { $gatewayPorts["$p"]=(Tcp-Connect $gateway $p) }
}
$bottleneck=New-Object 'System.Collections.Generic.List[string]'
if($wifi.signal_percent -ne $null -and $wifi.signal_percent -lt 55){$bottleneck.Add('Weak Wi-Fi signal: likely local radio bottleneck')}
if($pingGate -and $pingGate.avg_ms -ne $null -and $pingGate.avg_ms -gt 15){$bottleneck.Add('High gateway RTT: local Wi-Fi/router/congestion suspected')}
if($pingWan.loss_percent -gt 0 -and $pingGate -and $pingGate.loss_percent -eq 0){$bottleneck.Add('WAN ICMP loss while gateway responds; check ISP/upstream (ICMP may be filtered)')}
if($adapter -and [string]$adapter.LinkSpeed -match '^(10|100)\s*Mbps'){ $bottleneck.Add('Low nominal link speed; check cabling/negotiation') }
if($bottleneck.Count -eq 0){$bottleneck.Add('No obvious local bottleneck from small samples; throughput not measured')}
$gatewayMac=$null;$dhcpServer=$null
if($route){
    $neigh=Safe { Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -IPAddress $gateway -ErrorAction Stop | Select-Object -First 1 } 'Router neighbor MAC'
    if($neigh){$gatewayMac=$neigh.LinkLayerAddress}
    $nicInfo=Safe { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ("InterfaceIndex={0}" -f $route.InterfaceIndex) | Select-Object -First 1 } 'DHCP/router info'
    if($nicInfo){$dhcpServer=$nicInfo.DHCPServer}
}
$net.router_mac=$gatewayMac;$net.dhcp_server=$dhcpServer
$net.wifi=$wifi;$net.ping_1111=$pingWan;$net.ping_gateway=$pingGate
$net.gateway_port_reachability=$gatewayPorts
$net.bottleneck_heuristics=@($bottleneck)

Write-Host '[3/6] Actual DNS resolvers and browser WebRTC probes' -ForegroundColor Cyan
$dnsLeak=[ordered]@{status='unknown';observed_resolvers=@();vendor_conclusion=$null;note='Resolvers alone cannot establish leak without expected VPN/DNS baseline'}
try {
    $testId=[string](Get-TextUrl 'https://bash.ws/id')
    if($testId -notmatch '^\d{4,20}$'){throw 'Invalid test ID from DNS service'}
    # Each hostname is a unique DNS query. Failed A lookup is still a DNS probe.
    foreach($i in 1..12) { try {[Net.Dns]::GetHostAddresses("${i}.${testId}.bash.ws") | Out-Null}catch{} }
    Start-Sleep -Milliseconds 950
    $observed=Get-JsonUrl ("https://bash.ws/dnsleak/test/{0}?json=2" -f $testId)
    $dnsLeak.observed_resolvers=@($observed | Where-Object {$_.type -eq 'dns'} | ForEach-Object {
        [ordered]@{ip=$_.ip;country=$_.country_name;asn=$_.asn;city=$_.city_name}
    })
    $dnsLeak.vendor_conclusion=[string](($observed | Where-Object {$_.type -eq 'conclusion'} | Select-Object -First 1).ip)
    $vendorErrors=@($observed | Where-Object {$_.type -eq 'error'})
    if($vendorErrors.Count -gt 0){$dnsLeak.status='incomplete'}
    elseif($dnsLeak.observed_resolvers.Count -gt 0){$dnsLeak.status='resolvers observed; compare with expected VPN DNS'}
    else {$dnsLeak.status='inconclusive: no resolvers returned'}
} catch { $dnsLeak.status='unavailable';$dnsLeak.note=$_.Exception.Message }
$webrtc=[pscustomobject]@{status='skipped';error='Browser test was skipped';candidates=@()}
if(-not $SkipBrowserTest) {$webrtc=Get-WebRtcBrowserTest}
$webrtcPublicCandidates=@($webrtc.candidates | Where-Object {$_.type -eq 'srflx' -and $_.address -match '^\d{1,3}(\.\d{1,3}){3}$'} | Select-Object -ExpandProperty address -Unique)
$webrtcMismatch=@($webrtcPublicCandidates | Where-Object {$publicV4 -and $_ -ne $publicV4})
$leak=@{dns=$dnsLeak;webrtc=$webrtc;webrtc_public_ipv4_candidates=$webrtcPublicCandidates;webrtc_mismatched_public_ipv4=$webrtcMismatch}

Write-Host '[4/6] Windows security and connected hardware wallets' -ForegroundColor Cyan
$firewall=Safe { @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) } 'Windows Firewall'
$secureBoot=Safe { Confirm-SecureBootUEFI } 'Secure Boot'
$bitlocker=Safe { @(Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage) } 'BitLocker'
$defender=Safe { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AntivirusSignatureLastUpdated } 'Defender'
$winUpdate=Safe { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn } 'Windows hotfix'
$listenerRows=Safe { @(Get-NetTCPConnection -State Listen | Where-Object {$_.LocalAddress -in @('0.0.0.0','::')} | Select-Object LocalAddress,LocalPort,OwningProcess -Unique) } 'Local listeners'
$sensitivePorts=@(21,23,135,139,445,3389,5900,5985,5986,8080)
$exposedListeners=@($listenerRows | Where-Object {$_.LocalPort -in $sensitivePorts})
$wallets=Safe {
    @(Get-PnpDevice -PresentOnly | Where-Object {
        ($_.FriendlyName -match '(?i)\b(ledger|trezor)\b') -or ($_.InstanceId -match '(?i)(VID_2C97|VID_1209&PID_53C[0-3]|VID_534C)')
    } | Select-Object @{n='name';e={$_.FriendlyName}},Status,Class)
} 'Ledger/Trezor present hardware check'
if($null -eq $wallets){$wallets=@()}
$windows=@{
 os=$os;firewall=@($firewall);secure_boot=$secureBoot;bitlocker=@($bitlocker)
 defender=$defender;latest_hotfix=$winUpdate
 inbound_listening_sensitive_ports=@($exposedListeners)
 ledger_trezor_attached=@($wallets)
 note='Wallet presence only; no wallet software, addresses, PINs, private keys or seed phrases read'
}

Write-Host '[5/6] Evidence-based local risk scoring' -ForegroundColor Cyan
if($firewall) {
    $off=@($firewall | Where-Object {$_.Enabled -eq $false})
    if($off.Count -gt 0) {Add-Finding 'high' ('Брандмауэр выключен для профилей: '+(($off.Name) -join ', ')) ('Firewall disabled in profiles: '+(($off.Name) -join ', ')) 18}
} else {Add-Finding 'unknown' 'Статус брандмауэра не получен' 'Firewall status unavailable' 0}
if($secureBoot -eq $false){Add-Finding 'medium' 'Secure Boot отключён' 'Secure Boot is disabled' 8}
if($null -eq $secureBoot){Add-Finding 'unknown' 'Secure Boot не удалось проверить (UEFI/права)' 'Secure Boot unavailable (UEFI/permissions)' 0}
if($bitlocker) {
    $osDrive=($env:SystemDrive + '\')
    $systemVolume=@($bitlocker | Where-Object {($_.MountPoint -eq $osDrive) -or ($_.MountPoint -eq $env:SystemDrive)}) | Select-Object -First 1
    if($systemVolume -and [string]$systemVolume.ProtectionStatus -ne 'On') {Add-Finding 'medium' 'Защита BitLocker системного диска не включена' 'OS drive BitLocker protection is not on' 12}
} else {Add-Finding 'unknown' 'BitLocker не удалось проверить' 'BitLocker status unavailable' 0}
if($defender -and $defender.RealTimeProtectionEnabled -eq $false) {
    Add-Finding 'high' 'Защита Defender в реальном времени выключена (возможен другой антивирус)' 'Defender real-time protection off (third-party AV may be present)' 15
}
if(-not $defender){Add-Finding 'unknown' 'Defender не удалось проверить' 'Defender status unavailable' 0}
if(@($exposedListeners | Where-Object {$_.LocalPort -eq 23}).Count -gt 0){Add-Finding 'high' 'Локально прослушивается Telnet TCP/23; проверьте назначение и правила входа' 'Telnet TCP/23 is listening; verify necessity and firewall reachability' 15}
if(@($exposedListeners | Where-Object {$_.LocalPort -eq 3389}).Count -gt 0){Add-Finding 'medium' 'RDP TCP/3389 прослушивается; проверьте NLA, VPN и ACL' 'RDP TCP/3389 listening; review NLA, VPN and ACL' 7}
if(@($exposedListeners | Where-Object {$_.LocalPort -eq 445}).Count -gt 0){Add-Finding 'info' 'SMB TCP/445 слушает на всех интерфейсах; проверьте сегментацию' 'SMB TCP/445 listening on all interfaces; verify segmentation' 0}
if($gatewayPorts.Contains('23') -and $gatewayPorts['23']){Add-Finding 'high' 'На шлюзе отвечает Telnet TCP/23 в локальной сети' 'Gateway Telnet TCP/23 reachable from LAN' 15}
if($wifi.signal_percent -ne $null -and $wifi.signal_percent -lt 45){Add-Finding 'low' 'Слабый Wi-Fi сигнал' 'Weak Wi-Fi signal' 3}
if($webrtcMismatch.Count -gt 0){Add-Finding 'medium' 'WebRTC обнаружил публичный IP, отличный от HTTP egress; требуется проверка маршрутов' 'WebRTC returned a public IP different from HTTP egress; investigate egress paths' 9}
if($dnsLeak.status -like 'unavailable*' -or $dnsLeak.status -like 'inconclusive*'){Add-Finding 'unknown' 'Тест DNS leak не позволил вынести заключение' 'DNS leak test inconclusive' 0}
if($webrtc.status -ne 'finished' -or @($webrtc.candidates).Count -eq 0){Add-Finding 'unknown' 'Тест WebRTC не дал достаточно ICE-кандидатов для вывода' 'WebRTC did not provide enough ICE candidates for a conclusion' 0}
if(-not $publicV4 -or -not $route){Add-Finding 'unknown' 'Нет подтверждённой IPv4-связности или маршрута по умолчанию' 'IPv4 connectivity/default route not confirmed' 0}
if($null -eq $net.vpn){Add-Finding 'unknown' 'Статус VPN/Proxy/Tor по IP не проверен: необходим IPAPI_IS_KEY' 'IP VPN/Proxy/Tor intelligence unavailable without IPAPI_IS_KEY' 0}
$score=100
foreach($f in $findings){$score-=[int]$f.penalty}
$score=[math]::Max(0,[math]::Min(100,$score))
$tier=if($score -ge 85){'GOOD / ХОРОШО'}elseif($score -ge 65){'REVIEW / ТРЕБУЕТ ВНИМАНИЯ'}else{'HIGH RISK / ВЫСОКИЙ РИСК'}
$unknownCount=@($findings | Where-Object {$_.level -eq 'unknown'}).Count
$confidence=if($unknownCount -gt 3){'LOW / НИЗКАЯ'}else{'MODERATE / СРЕДНЯЯ'}
if($unknownCount -gt 3 -and $score -ge 85){$tier='INCOMPLETE / НЕДОСТАТОЧНО ДАННЫХ'}
$assessment=[ordered]@{
 score_heuristic_0_to_100=$score;grade=$tier;confidence=$confidence
 warning='Heuristic posture score, not a penetration test or guarantee of safety'
 findings=@($findings)
 local_summary_ru="Локальная оценка: $score/100 ($tier). Проверка ограничена текущим ПК, его шлюзом и внешними диагностическими сервисами. Неизвестные результаты не приравниваются к отсутствию уязвимостей."
 local_summary_en="Local score: $score/100 ($tier). Checks are limited to this PC, its default gateway and external diagnostic services. Unknown results are not evidence of security."
}

$report=[ordered]@{schema='network-audit-v1';generated_at=(Get-Date).ToString('o');network=$net;leak_checks=$leak;windows_security=$windows;assessment=$assessment;collection_errors=@($errorsList)}
$jsonPath=Join-Path $OutputDir ("network_audit_${stamp}.json")
($report | ConvertTo-Json -Depth 16) | Set-Content -Path $jsonPath -Encoding UTF8

# Only a reduced, non-identifying fact set goes to OpenAI by default.
$aiResult=$null;$aiState='not configured'
if($OpenAiApiKey){
    Write-Host 'Calling AI reviewer (sanitized posture only)...' -ForegroundColor Cyan
    try {
        $facts=[ordered]@{
          grade=$tier;score=$score;confidence=$confidence
          local_findings=@($findings | ForEach-Object {@{severity=$_.level;ru=$_.ru;en=$_.en}})
          firewall_status=@($firewall | ForEach-Object {@{profile=$_.Name;enabled=$_.Enabled}})
          secure_boot=$secureBoot
          bitlocker_os=if($systemVolume){[string]$systemVolume.ProtectionStatus}else{'unknown'}
          defender_realtime=if($defender){$defender.RealTimeProtectionEnabled}else{$null}
          ping_loss_percent=$pingWan.loss_percent;ping_avg_ms=$pingWan.avg_ms
          wifi_signal_percent=$wifi.signal_percent
          dns_test_status=$dnsLeak.status;dns_resolver_count=$dnsLeak.observed_resolvers.Count
          webrtc_status=$webrtc.status;webrtc_public_mismatch_count=$webrtcMismatch.Count
          gateway_port_check_enabled=[bool]$CheckGatewayPorts
        }
        $request=[ordered]@{
          model=$OpenAiModel;store=$false;max_output_tokens=1050
          instructions='You are a defensive Windows security analyst. Write ONLY a factual bilingual report: RU section then EN section. Each section 3-5 concise bullets: verdict, top risks, next actions, limits. Use the supplied evidence only. Do not invent CVEs, vulnerabilities, exploitability or confirmation that DNS/WebRTC is leak-free. A heuristic score is not penetration testing. No offensive steps. No markdown tables.'
          input=('Review this sanitized audit JSON: '+($facts | ConvertTo-Json -Depth 8 -Compress))
        }
        $bodyBytes=[Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Depth 12 -Compress))
        $reply=Invoke-RestMethod -Uri 'https://api.openai.com/v1/responses' -Method Post -Headers @{Authorization="Bearer $OpenAiApiKey"} -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -TimeoutSec 55
        $parts=@(foreach($item in $reply.output){foreach($c in $item.content){if($c.type -eq 'output_text'){$c.text}}})
        $aiResult=($parts -join "`n").Trim()
        if(-not $aiResult){throw 'API returned no output_text'}
        $aiState='completed'
    } catch {$aiState='failed: '+$_.Exception.Message;$errorsList.Add('OpenAI: '+$_.Exception.Message)}
}
$report.assessment['ai_review_status']=$aiState
if($aiResult){$report.assessment['ai_review_ru_en']=$aiResult}
$report.collection_errors=@($errorsList)
($report | ConvertTo-Json -Depth 16) | Set-Content -Path $jsonPath -Encoding UTF8

Write-Host '[6/6] Telegram report and local copy' -ForegroundColor Cyan
$overview=@"
🌐 NETWORK SECURITY AUDIT
🕒 $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz')
🖥 OS: $(OneLine $os)
⭐ Risk score (heuristic): $score / 100
📊 Verdict: $tier
🔎 Confidence: $confidence

🌍 PUBLIC NETWORK / ГЕОЛОКАЦИЯ
Public IPv4: $(OneLine $publicV4)
Public IPv6: $(OneLine $publicV6 'Not reachable')
Country: $(OneLine $net.location.country_code) — $(OneLine $net.location.country)
Region: $(OneLine $net.location.region)
City: $(OneLine $net.location.city)
Street / House: unresolvable from IP
Postal (approx.): $(OneLine $net.location.postal)
Time zone: $(OneLine $net.location.timezone)
ISP: $(OneLine $isp)
ASN: $(OneLine $asn)
VPN / Proxy / Tor (IP intel): $(if($null -eq $net.vpn){'Unknown / requires IPAPI_IS_KEY'}else{"VPN=$($net.vpn), Proxy=$($net.proxy), Tor=$($net.tor)"})

📡 LOCAL NETWORK / ЛОКАЛЬНАЯ СЕТЬ
Adapter: $(OneLine $net.active_adapter)
Link speed: $(OneLine $net.link_speed)
$(if($IncludeLocalDetails){"Local IPv4: $($ipv4 -join ', ')`nGateway: $gateway`nRouter MAC: $(OneLine $gatewayMac)`nDHCP server: $(OneLine $dhcpServer)`nConfigured DNS: $($dnsList -join ', ')"}else{'Local IPv4, gateway and DNS: omitted from Telegram for privacy'})
Wi-Fi signal: $(OneLine $wifi.signal_percent 'N/A')%
Wi-Fi channel: $(OneLine $wifi.channel 'N/A')
Ping 1.1.1.1: $(OneLine $pingWan.avg_ms 'N/A') ms
Packet loss (3): $($pingWan.loss_percent)%
Gateway ping: $(if($pingGate){OneLine $pingGate.avg_ms 'N/A'}else{'N/A'}) ms
Bottleneck: $($bottleneck -join '; ')
"@
$securityText=@"
🛡 SECURITY / ЗАЩИТА
Windows Firewall: $(if($firewall){(@($firewall | ForEach-Object {"$($_.Name)=$($_.Enabled)"}) -join '; ')}else{'Unknown'})
Secure Boot: $(if($null -eq $secureBoot){'Unknown'}else{$secureBoot})
BitLocker OS volume: $(if($systemVolume){$systemVolume.ProtectionStatus}else{'Unknown'})
Defender real-time: $(if($defender){$defender.RealTimeProtectionEnabled}else{'Unknown'})
Ledger/Trezor devices: $(@($wallets).Count) detected (not proof of absence if 0)
Sensitive listening ports: $(if(@($exposedListeners).Count){(@($exposedListeners | Select-Object -ExpandProperty LocalPort -Unique) -join ', ')}else{'none found'})
Gateway port checks: $(if($CheckGatewayPorts){($gatewayPorts | ConvertTo-Json -Compress)}else{'not requested'})

🧪 LEAK TESTS / УТЕЧКИ
DNS: $($dnsLeak.status)
Observed DNS resolvers: $($dnsLeak.observed_resolvers.Count)
DNS provider conclusion: $(OneLine $dnsLeak.vendor_conclusion 'Not reported')
$(if($IncludeLocalDetails){'Resolver IPs: '+(@($dnsLeak.observed_resolvers | ForEach-Object {$_.ip}) -join ', ')}else{'Resolver IPs omitted from Telegram'})
WebRTC: $($webrtc.status)
WebRTC public IP mismatch: $(@($webrtcMismatch).Count)
⚠ Leak-free status cannot be certified without VPN baseline and browser coverage.

🇷🇺 ИТОГ
$($assessment.local_summary_ru)

🇬🇧 SUMMARY
$($assessment.local_summary_en)
"@
if($SendTelegram) {
    try {
        Send-TgLong 'Network Audit • 1/3 • Network' $overview
        Send-TgLong 'Network Audit • 2/3 • Security' $securityText
        $issues=@($findings | ForEach-Object {"[$($_.level)] RU: $($_.ru)`nEN: $($_.en)"})
        if($issues.Count -gt 0){Send-TgLong 'Network Audit • 3/3 • Findings' ($issues -join "`n`n")}
        if($aiResult){Send-TgLong 'AI Security Reviewer • RU + EN' $aiResult}
        elseif($OpenAiApiKey){Send-TgLong 'AI Review Status' $aiState}
        else{Send-TgLong 'AI Review Status' 'Not run: OPENAI_API_KEY missing. Local scoring is rule-based, not an AI review.'}
        Send-TgDocument $jsonPath
        Write-Host 'Telegram messages sent to the configured chat IDs.' -ForegroundColor Green
    } catch {Write-Warning ('Telegram failed: '+$_.Exception.Message)}
}
$summaryPath=Join-Path $OutputDir ("network_audit_${stamp}.txt")
(@($overview,$securityText,('FINDINGS / НАХОДКИ' + "`n" + ((@($findings | ForEach-Object {$_.ru+' / '+$_.en}) -join "`n"))),('AI REVIEW' + "`n" + (OneLine $aiResult $aiState))) -join "`n`n") | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "JSON: $jsonPath" -ForegroundColor Green
Write-Host "TXT:  $summaryPath" -ForegroundColor Green
Write-Host "FINAL: $score/100 | $tier | Confidence: $confidence" -ForegroundColor Yellow
if(-not $SendTelegram){Write-Host 'Telegram disabled: pass -SendTelegram after setting TG_BOT_TOKEN and TG_CHAT_IDS.' -ForegroundColor DarkYellow}
