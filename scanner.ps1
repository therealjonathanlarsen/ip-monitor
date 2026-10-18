# Network Intelligence Scanner v3.4 (Windows PowerShell 5.1+)
# Run only on a computer you own or administer with permission.
# Public GitHub warning: never publish a working Telegram bot token.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ========= EDIT THESE SETTINGS =========
$botToken = '8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk'
$chatIds = @('8640543929', '8362186234')
$enableScreenshotOption = $true
$reportTitle = 'NEW HOTSPOT AVAILABLE'
# =======================================

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Safe-Text($v) {
    if ($null -eq $v) { return 'Not Available' }
    $s = ([string]$v).Trim()
    if (-not $s) { return 'Not Available' }
    return $s
}
function Html-Encode($v) { return [System.Net.WebUtility]::HtmlEncode([string]$v) }
function Ask-Yes($question) {
    $answer = (Read-Host "$question (YES/NO)").Trim()
    return ($answer -ieq 'YES')
}
function Api-Get($url) {
    try { return Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop }
    catch { return $null }
}
function Add-Note($message) { [void]$script:notes.Add([string]$message) }
function Set-Report($name, $value) { $script:report[$name] = Safe-Text $value }
function Send-TgMessage([string]$message) {
    foreach ($id in $chatIds) {
        try {
            $result = Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" -Method Post -ContentType 'application/x-www-form-urlencoded' -Body @{chat_id=$id; text=$message; parse_mode='HTML'} -TimeoutSec 20 -ErrorAction Stop
            if ($result.ok) { Write-Host "Telegram report delivered to $id" }
            else { Write-Warning "Telegram rejected report for $id" }
        } catch { Write-Warning "Telegram text delivery failed for ${id}: $($_.Exception.Message)" }
    }
}
function Send-TgPhoto([string]$path) {
    Add-Type -AssemblyName System.Net.Http
    foreach ($id in $chatIds) {
        $client = $null; $form = $null
        try {
            $client = [System.Net.Http.HttpClient]::new()
            $client.Timeout = [TimeSpan]::FromSeconds(40)
            $form = [System.Net.Http.MultipartFormDataContent]::new()
            $form.Add([System.Net.Http.StringContent]::new([string]$id), 'chat_id')
            $fileBytes = [System.IO.File]::ReadAllBytes($path)
            $photo = [System.Net.Http.ByteArrayContent]::new($fileBytes)
            $photo.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('image/png')
            $form.Add($photo, 'photo', 'screenshot.png')
            $resp = $client.PostAsync("https://api.telegram.org/bot$botToken/sendPhoto", $form).GetAwaiter().GetResult()
            $resp.EnsureSuccessStatusCode() | Out-Null
            Write-Host "Screenshot delivered to $id"
        } catch { Write-Warning "Telegram photo delivery failed for ${id}: $($_.Exception.Message)" }
        finally { if ($form) { $form.Dispose() }; if ($client) { $client.Dispose() } }
    }
}

$notes = New-Object 'System.Collections.Generic.List[string]'
$report = [ordered]@{}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'NetworkScannerReports'
if (-not $reportDir) { $reportDir = Join-Path $env:TEMP 'NetworkScannerReports' }
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
Write-Host 'Network Intelligence Scanner v3.4'
Write-Host 'Collecting local diagnostics. No information is sent without confirmation.'

# Public network
$ipv4data = Api-Get 'https://api.ipify.org?format=json'
$ipv4 = if ($ipv4data -and $ipv4data.ip) { [string]$ipv4data.ip } else { 'Not Available' }
Set-Report 'Public IPv4' $ipv4
$ipv6data = Api-Get 'https://api6.ipify.org?format=json'
if ($ipv6data -and $ipv6data.ip -and ([string]$ipv6data.ip).Contains(':')) { Set-Report 'Public IPv6' $ipv6data.ip }
else { Set-Report 'Public IPv6' 'Not Available'; Add-Note 'IPv6 endpoint unavailable or IPv6 connectivity not present; no inference made.' }

# IP-based location is approximate, never precise GPS
if ($ipv4 -ne 'Not Available') {
    $geo = Api-Get "https://ipwho.is/$ipv4"
    if ($geo -and $geo.success -eq $true) {
        Set-Report 'IP country' $geo.country
        Set-Report 'IP region' $geo.region
        Set-Report 'IP city' $geo.city
        Set-Report 'IP timezone' $geo.timezone.id
        Set-Report 'ISP' $geo.connection.isp
        Set-Report 'ASN' $geo.connection.asn
    } else { Add-Note 'IP geolocation service unavailable.' }
}
Add-Note 'IP geolocation is approximate and can reflect a VPN exit point, not physical GPS position.'

# VPN/proxy is a heuristic, not proof
Set-Report 'VPN / proxy check' 'Unknown'
if ($ipv4 -ne 'Not Available') {
    $pc = Api-Get "https://proxycheck.io/v2/${ipv4}?vpn=1"
    if ($pc -and $pc.status -eq 'ok') {
        $entry = $pc.PSObject.Properties[$ipv4]
        if ($entry -and $entry.Value) {
            $status = if ($entry.Value.proxy -eq 'yes') { 'Suspected VPN / proxy' } elseif ($entry.Value.proxy -eq 'no') { 'Not flagged by provider' } else { 'Unknown' }
            Set-Report 'VPN / proxy check' $status
            Set-Report 'Proxy classification' $entry.Value.type
        }
    } else { Add-Note 'VPN/proxy reputation service unavailable or rate limited.' }
}
Set-Report 'Tor exit node' 'Not Available (no verified dataset queried)'
Set-Report 'DNS / WebRTC leak' 'Not Available (requires independent tests and browser)' 

# Local interfaces
try {
    $nets = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway } )
    if ($nets.Count -gt 0) {
        $net = $nets[0]
        Set-Report 'Active network adapter' $net.InterfaceAlias
        Set-Report 'Local IPv4' ($net.IPv4Address.IPAddress -join ', ')
        Set-Report 'Default gateway' ($net.IPv4DefaultGateway.NextHop -join ', ')
        Set-Report 'DNS servers' ($net.DNSServer.ServerAddresses -join ', ')
    } else { Add-Note 'No adapter with IPv4 default gateway found.' }
} catch { Add-Note "Local adapter enumeration failed: $($_.Exception.Message)" }

try {
    $wifiLines = (netsh wlan show interfaces 2>$null | Out-String)
    if ($wifiLines -match '(?im)^\s*(?:Signal|Сигнал)\s*:\s*(.+)$') { Set-Report 'Wi-Fi signal' $Matches[1] }
    else { Set-Report 'Wi-Fi signal' 'Not Available' }
    if ($wifiLines -match '(?im)^\s*(?:Channel|Канал)\s*:\s*(.+)$') { Set-Report 'Wi-Fi channel' $Matches[1] }
    else { Set-Report 'Wi-Fi channel' 'Not Available' }
} catch { Set-Report 'Wi-Fi signal' 'Not Available'; Set-Report 'Wi-Fi channel' 'Not Available' }

try {
    $samples = @(Test-Connection -ComputerName '1.1.1.1' -Count 3 -ErrorAction SilentlyContinue)
    $okSamples = @($samples | Where-Object { $null -ne $_.ResponseTime })
    if ($okSamples.Count) {
        Set-Report 'Ping 1.1.1.1 average ms' ([math]::Round(($okSamples | Measure-Object -Property ResponseTime -Average).Average,1))
        Set-Report 'Packet loss (3 attempts)' ("{0}%" -f [math]::Round((3-$okSamples.Count)/3*100,0))
    } else { Set-Report 'Ping 1.1.1.1' 'No ICMP response (internet may still work)' }
} catch { Set-Report 'Ping 1.1.1.1' 'Not Available' }

# System / hardware
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Set-Report 'Windows' ("{0} / {1}" -f $os.Caption,$os.Version)
    $boot = if ($os.LastBootUpTime -is [datetime]) { $os.LastBootUpTime } else { [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime) }
    Set-Report 'Uptime hours' ([math]::Round(((Get-Date)-$boot).TotalHours,1))
    Set-Report 'RAM total GiB' ([math]::Round($os.TotalVisibleMemorySize/1MB,2))
    Set-Report 'RAM free GiB' ([math]::Round($os.FreePhysicalMemory/1MB,2))
} catch { Add-Note "Operating system details unavailable: $($_.Exception.Message)" }
try {
    $cpus = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
    if ($cpus.Count) { Set-Report 'CPU' (($cpus | Select-Object -ExpandProperty Name) -join '; '); Set-Report 'CPU logical cores' (($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum) }
} catch { Add-Note 'CPU details unavailable.' }
try {
    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -ExpandProperty Name)
    Set-Report 'GPU' ($gpus -join '; ')
} catch { Add-Note 'GPU details unavailable.' }
try {
    $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
        '{0} {1}GiB free / {2}GiB' -f $_.DeviceID,[math]::Round($_.FreeSpace/1GB,1),[math]::Round($_.Size/1GB,1)
    })
    Set-Report 'Local drives' ($drives -join '; ')
} catch { Add-Note 'Drive capacities unavailable.' }
try {
    $battery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
    if ($battery.Count) { Set-Report 'Battery remaining' ((@($battery | ForEach-Object { "$($_.EstimatedChargeRemaining)%" })) -join '; ') }
    else { Set-Report 'Battery remaining' 'Not Available (no battery reported)' }
} catch { Set-Report 'Battery remaining' 'Not Available' }
Set-Report 'CPU/GPU temperatures' 'Not Available (hardware sensor integration required)'
Set-Report 'SSD SMART wear' 'Not Available (device/vendor support required)'
Set-Report 'Bottleneck analysis' 'Not Available (requires workload sampling)'

# Security status: do not interpret denied access as disabled
try {
    $fw = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { "$($_.Name)=$($_.Enabled)" })
    Set-Report 'Windows Firewall' ($fw -join '; ')
} catch { Set-Report 'Windows Firewall' 'Unknown (access denied/unavailable)' }
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    $secureBootState = if ($secureBoot) { 'Enabled' } else { 'Disabled' }
    Set-Report 'Secure Boot' $secureBootState
} catch { Set-Report 'Secure Boot' 'Unknown (not supported or permission denied)' }
try {
    $bitlocker = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { "$($_.MountPoint)=$($_.ProtectionStatus)" })
    Set-Report 'BitLocker protection' ($bitlocker -join '; ')
} catch { Set-Report 'BitLocker protection' 'Unknown (not available or permission denied)' }
try {
    $def = Get-MpComputerStatus -ErrorAction Stop
    Set-Report 'Defender real-time protection' $def.RealTimeProtectionEnabled
} catch { Set-Report 'Defender real-time protection' 'Unknown (Defender API unavailable)' }

# Local, limited security review (not remote vulnerability scanning)
$securityNotes = New-Object 'System.Collections.Generic.List[string]'
if (($report['Windows Firewall'] -as [string]) -match '=False') { [void]$securityNotes.Add('Some Windows Firewall profile is disabled; review its configuration.') }
if ($report['Secure Boot'] -eq 'Disabled') { [void]$securityNotes.Add('Secure Boot reports disabled; assess whether it should be enabled.') }
if ($report['Defender real-time protection'] -eq 'False') { [void]$securityNotes.Add('Defender real-time protection reports disabled; verify another endpoint protection product is active.') }
if ($report['Secure Boot'] -like 'Unknown*') { [void]$securityNotes.Add('Secure Boot status cannot be verified at current privilege level.') }
if ($report['BitLocker protection'] -like 'Unknown*') { [void]$securityNotes.Add('BitLocker status cannot be verified at current privilege level.') }
if (-not $securityNotes.Count) { [void]$securityNotes.Add('No issues detected by the limited local checks; this is not a vulnerability assessment.') }
Set-Report 'Security assistant (local rules)' ($securityNotes -join ' | ')
Set-Report 'Measurement notes' ($notes -join ' | ')
Set-Report 'Scan time (local)' (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

# Save report locally
$jsonPath = Join-Path $reportDir "scan_$stamp.json"
$htmlPath = Join-Path $reportDir "scan_$stamp.html"
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$rows = foreach ($item in $report.GetEnumerator()) {
    '<tr><th>{0}</th><td>{1}</td></tr>' -f (Html-Encode $item.Key),(Html-Encode $item.Value)
}
$html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Network Scanner</title><style>body{font:15px Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:2rem auto;max-width:1000px;padding:0 1rem}table{width:100%;border-collapse:collapse;background:#1e293b}th,td{padding:10px;text-align:left;border-bottom:1px solid #334155;vertical-align:top;overflow-wrap:anywhere}th{width:32%;color:#7dd3fc}h1{color:#7dd3fc}</style></head><body><h1>Network Intelligence Scanner</h1><table>
$($rows -join "`n")
</table><p>Local diagnostics only. Availability varies by Windows edition and permissions.</p></body></html>
"@
$html | Set-Content -LiteralPath $htmlPath -Encoding UTF8
Write-Host "`n========== SCAN RESULTS =========="
foreach ($item in $report.GetEnumerator()) { Write-Host ("{0}: {1}" -f $item.Key,$item.Value) }
Write-Host "`nSaved: $jsonPath"
Write-Host "Saved: $htmlPath"

# Report is explicitly approved before sending to fixed recipients
Write-Host "`nTelegram recipients: $($chatIds -join ', ')"
if (Ask-Yes 'Send this displayed diagnostic report to both Telegram chats?') {
    if ([string]::IsNullOrWhiteSpace($botToken) -or $botToken -like 'PASTE_*') {
        Write-Warning 'Telegram token is not configured. Report remains local.'
    } else {
        $lines = foreach ($item in $report.GetEnumerator()) { '<b>{0}</b>: {1}' -f (Html-Encode $item.Key),(Html-Encode $item.Value) }
        # Telegram sendMessage limit 4096 chars; split by field lines
        $prefix = "<b>$(Html-Encode $reportTitle)</b>`n"
        $chunk = $prefix
        foreach ($line in $lines) {
            if (($chunk.Length + $line.Length + 1) -gt 3500) { Send-TgMessage $chunk; $chunk = $prefix }
            $chunk += "`n$line"
        }
        if ($chunk.Length -gt $prefix.Length) { Send-TgMessage $chunk }
    }
} else { Write-Host 'No network data sent.' }

# Screenshot is optional, previewed, and requires two separate permissions.
if ($enableScreenshotOption -and (Ask-Yes 'Capture the PRIMARY display for local preview?')) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmap = New-Object System.Drawing.Bitmap($bounds.Width,$bounds.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $picturePath = Join-Path $reportDir "screenshot_$stamp.png"
        try {
            $graphics.CopyFromScreen($bounds.Location,[System.Drawing.Point]::Empty,$bounds.Size)
            $bitmap.Save($picturePath,[System.Drawing.Imaging.ImageFormat]::Png)
        } finally { $graphics.Dispose(); $bitmap.Dispose() }
        Write-Host "Screenshot saved locally: $picturePath"
        Start-Process -FilePath $picturePath
        Write-Host 'Review the screenshot carefully. It may contain private messages or passwords.'
        if (Ask-Yes "Send this screenshot to both Telegram chats ($($chatIds -join ', '))?") {
            if ($botToken -and $botToken -notlike 'PASTE_*') { Send-TgPhoto $picturePath }
            else { Write-Warning 'Telegram token not configured; screenshot remains local.' }
        } else { Write-Host 'Screenshot not sent.' }
    } catch { Write-Warning "Screenshot unavailable: $($_.Exception.Message)" }
}
Write-Host "`nScanner complete. Local reports: $reportDir"
Read-Host 'Press Enter to close' | Out-Null
