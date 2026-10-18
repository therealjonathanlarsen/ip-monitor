# Network Intelligence Scanner v2.3
# Run on a computer you own or have permission to diagnose.
# Windows PowerShell 5.1+ / PowerShell 7+
# This script never captures or sends a screenshot without separate explicit consent.
# Network report sharing also requires explicit consent.

$ErrorActionPreference = 'Stop'

# TELEGRAM SETTINGS - Edit these values before uploading.
# WARNING: A public GitHub repository exposes this token to everyone.
# Revoke any previously exposed token and use a new one.
$botToken = '8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk'
$chatIds = @(
    '8640543929',
    '8399897686'
)

if ([string]::IsNullOrWhiteSpace($botToken) -or $botToken -eq 'PASTE_YOUR_NEW_BOT_TOKEN_HERE') {
    throw 'Edit $botToken at the top of scanner.ps1 before sending reports.'
}
$reportDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'NetworkScannerReports'

function SafeValue($v) {
    if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { return 'Unknown' }
    return [string]$v
}
function CheckFlag($obj, $name) {
    if ($null -eq $obj -or $null -eq $obj.PSObject.Properties[$name]) { return 'Unknown (API key required)' }
    if ($obj.$name -eq $true) { return 'Detected' }
    if ($obj.$name -eq $false) { return 'Not detected' }
    return 'Unknown'
}
function Html($text) { return [System.Net.WebUtility]::HtmlEncode([string]$text) }
function Get-RemoteJson([string]$uri) {
    try { return Invoke-RestMethod -Uri $uri -TimeoutSec 12 -ErrorAction Stop }
    catch { Write-Warning "Request failed: $($_.Exception.Message)"; return $null }
}

Write-Host 'Network Intelligence Scanner v2.3' -ForegroundColor Cyan
Write-Host 'Collecting network diagnostics locally...' -ForegroundColor Gray

# Public IPv4 and IPv6 independently (VPN may affect results).
$v4Response = Get-RemoteJson 'https://api4.ipify.org?format=json'
# IPv6 is optional. Failure here is expected on IPv4-only networks.
try {
    $v6Response = Invoke-RestMethod -Uri 'https://api6.ipify.org?format=json' -TimeoutSec 5 -ErrorAction Stop
} catch {
    $v6Response = $null
}
$ipv4 = SafeValue $v4Response.ip
$ipv6 = if ($null -eq $v6Response) { 'Not available' } else { SafeValue $v6Response.ip }

# IP ownership and security intelligence. Full flags require optional API key.
$apiKey = $env:IPAPI_IS_KEY
$lookup = $null
if ($ipv4 -ne 'Unknown') {
    $uri = 'https://api.ipapi.is/?q=' + [uri]::EscapeDataString($ipv4)
    if ($apiKey) { $uri += '&key=' + [uri]::EscapeDataString($apiKey) }
    $lookup = Get-RemoteJson $uri
}

# The unauthenticated response has flattened fields. The keyed one uses objects.
$country = 'Unknown'; $region = 'Unknown'; $city = 'Unknown'; $timezone = 'Unknown'
$provider = 'Unknown'; $asn = 'Unknown'
if ($lookup) {
    if ($lookup.location) {
        $country = SafeValue $lookup.location.country
        $region = SafeValue $lookup.location.state
        $city = SafeValue $lookup.location.city
        $timezone = SafeValue $lookup.location.timezone
    } else {
        $country = SafeValue $lookup.country
        $region = SafeValue $lookup.region
        $city = SafeValue $lookup.city
        $timezone = SafeValue $lookup.timezone
    }
    if ($lookup.company -is [string]) { $provider = SafeValue $lookup.company }
    elseif ($lookup.company) { $provider = SafeValue $lookup.company.name }
    if ($lookup.asn -is [string]) { $asn = SafeValue $lookup.asn }
    elseif ($lookup.asn) { $asn = 'AS' + (SafeValue $lookup.asn.asn) + ' / ' + (SafeValue $lookup.asn.org) }
}

$vpn = CheckFlag $lookup 'is_vpn'
$proxy = CheckFlag $lookup 'is_proxy'
$tor = CheckFlag $lookup 'is_tor'
$hosting = CheckFlag $lookup 'is_datacenter'

# Local network: only the active default-route adapter.
$localIp = 'Unknown'; $adapterName = 'Unknown'; $gateway = 'Unknown'; $dns = 'Unknown'
try {
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    if ($route) {
        $adapterName = SafeValue (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex).Name
        $gateway = SafeValue $route.NextHop
        $localIp = SafeValue ((Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress)
        $dns = SafeValue ((Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4).ServerAddresses -join ', ')
    }
} catch { Write-Warning 'Local adapter details unavailable.' }

# System proxy setting is not proof of VPN or traffic routing.
$systemProxy = 'Unknown'
try {
    $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($p.ProxyEnable -eq 1) { $systemProxy = 'Enabled: ' + (SafeValue $p.ProxyServer) }
    else { $systemProxy = 'Disabled (Windows user settings)' }
} catch { }

$latency = 'Unavailable'
try {
    $pings = @(Test-Connection -ComputerName '1.1.1.1' -Count 2 -ErrorAction Stop)
    $times = @($pings | ForEach-Object {
        if ($null -ne $_.ResponseTime) { [double]$_.ResponseTime }
        elseif ($null -ne $_.Latency) { [double]$_.Latency }
    })
    if ($times.Count -gt 0) {
        $avg = ($times | Measure-Object -Average).Average
        $latency = ([math]::Round($avg,1)).ToString() + ' ms'
    }
} catch { }

$os = SafeValue ((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
$report = [ordered]@{
    'Scan time'=$stamp; 'Public IPv4'=$ipv4; 'Public IPv6'=$ipv6
    'Country'=$country; 'Region'=$region; 'City'=$city; 'Timezone'=$timezone
    'Provider'=$provider; 'ASN'=$asn
    'VPN exit'=$vpn; 'Public proxy'=$proxy; 'Tor exit'=$tor; 'Datacenter'=$hosting
    'Local IPv4'=$localIp; 'Adapter'=$adapterName; 'Gateway'=$gateway; 'DNS'=$dns
    'Windows proxy'=$systemProxy; 'Ping 1.1.1.1'=$latency; 'Operating system'=$os
}

Write-Host "`n===== NETWORK REPORT =====" -ForegroundColor Cyan
foreach ($entry in $report.GetEnumerator()) { '{0,-21} {1}' -f ($entry.Key + ':'),$entry.Value | Write-Host }
Write-Host "`nVPN/Proxy/Tor detection reflects IP reputation, not certainty." -ForegroundColor Yellow

# Save local copies (no secrets included).
New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
$filename = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonPath = Join-Path $reportDir "scan-$filename.json"
$htmlPath = Join-Path $reportDir "scan-$filename.html"
[pscustomobject]$report | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8

$rows = foreach ($entry in $report.GetEnumerator()) {
    '<tr><th>' + (Html $entry.Key) + '</th><td>' + (Html $entry.Value) + '</td></tr>'
}
$rowsText = $rows -join "`n"
$localHtml = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Network Scan</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 18px;background:#f5f7fb;color:#202b39}table{width:100%;border-collapse:collapse;background:white}th,td{text-align:left;border-bottom:1px solid #dce3eb;padding:12px}th{width:38%;background:#edf2f7}h1{font-size:24px}p{color:#566}</style></head><body>
<h1>Network Intelligence Scanner v2.3</h1><p>Results are estimates; IP reputation is not definitive.</p>
<table>$rowsText</table></body></html>
"@
$localHtml | Set-Content -Path $htmlPath -Encoding UTF8
Write-Host "`nSaved JSON: $jsonPath" -ForegroundColor Green
Write-Host "Saved HTML: $htmlPath" -ForegroundColor Green

# Optional screenshot: user must opt in BEFORE capture.
# Capture only the primary display. Preview it before offering to share.
$screenshotPath = $null
Write-Host "`nOPTIONAL SCREENSHOT" -ForegroundColor Cyan
Write-Host 'A screenshot can contain private messages, passwords and other sensitive data.' -ForegroundColor Yellow
$captureAnswer = (Read-Host 'Capture the primary screen for local preview? Type YES to allow').Trim()
if ($captureAnswer -eq 'YES') {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bmp)
            try {
                $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
                $screenshotPath = Join-Path $reportDir "screenshot-$filename.png"
                $bmp.Save($screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
            } finally {
                if ($graphics) { $graphics.Dispose() }
            }
        } finally {
            $bmp.Dispose()
        }
        Write-Host "Screenshot saved: $screenshotPath" -ForegroundColor Green
        Write-Host 'Review the image before deciding whether to share it.' -ForegroundColor Yellow
        Start-Process -FilePath $screenshotPath
        Read-Host 'Review the screenshot, then press Enter to continue'
    } catch {
        $screenshotPath = $null
        Write-Warning "Screenshot not captured: $($_.Exception.Message)"
    }
}

# Screenshot permission is independent from permission to share network data.
$sendScreenshot = $false
if ($screenshotPath -and (Test-Path -LiteralPath $screenshotPath)) {
    Write-Host "Screenshot recipient chats: $($chatIds -join ', ')" -ForegroundColor Yellow
    $screenshotAnswer = (Read-Host 'Send this reviewed screenshot to BOTH Telegram chats? Type YES to confirm').Trim()
    $sendScreenshot = ($screenshotAnswer -eq 'YES')
}

# Explicit opt-in: no automatic sharing of device/network information.
Write-Host "`nRecipients: $($chatIds -join ', ')" -ForegroundColor Yellow
$consent = (Read-Host 'Send this network report to BOTH Telegram chats? Type YES to confirm').Trim()
if ($consent -ne 'YES' -and -not $sendScreenshot) { Write-Host 'No data sent to Telegram.'; Read-Host 'Press Enter to close'; exit 0 }

# Telegram Rich Message HTML table (Bot API sendRichMessage).
$tgRows = foreach ($entry in $report.GetEnumerator()) {
    '<tr><td>' + (Html $entry.Key) + '</td><td>' + (Html $entry.Value) + '</td></tr>'
}
$telegramHtml = '<h3>NEW HOTSPOT AVAILABLE</h3><table><tr><th>Parameter</th><th>Value</th></tr>' + ($tgRows -join '') + '</table>'
if ($consent -eq 'YES') {
foreach ($chatId in $chatIds) {
    try {
        $payload = @{ chat_id=$chatId; rich_message=@{ html=$telegramHtml } } | ConvertTo-Json -Depth 6 -Compress
        $utf8 = [Text.Encoding]::UTF8.GetBytes($payload)
        $null = Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendRichMessage" `
            -Method Post -Body $utf8 -ContentType 'application/json; charset=utf-8' -TimeoutSec 20
        Write-Host "Sent to chat $chatId" -ForegroundColor Green
    } catch {
        Write-Warning "Rich table failed for chat ${chatId}: $($_.Exception.Message). Trying regular Telegram message."
        try {
            # Standard HTML formatting is supported by the regular Bot API.
            # Plain rows are more compatible than rich tables on older clients.
            $lines = foreach ($entry in $report.GetEnumerator()) {
                '<b>' + (Html $entry.Key) + ':</b> ' + (Html $entry.Value)
            }
            $fallbackText = '<b>NEW HOTSPOT AVAILABLE</b>' + "`n`n" + ($lines -join "`n")
            $body = @{ chat_id=$chatId; text=$fallbackText; parse_mode='HTML' } | ConvertTo-Json -Compress
            $null = Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" `
                -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($body)) `
                -ContentType 'application/json; charset=utf-8' -TimeoutSec 20 -ErrorAction Stop
            Write-Host "Sent standard message to chat $chatId" -ForegroundColor Green
        } catch {
            Write-Warning "Telegram delivery to chat ${chatId} failed: $($_.Exception.Message)"
        }
    }
}
}

# Only send the screenshot if it was reviewed AND independently authorized.
if ($sendScreenshot -and $screenshotPath -and (Test-Path -LiteralPath $screenshotPath)) {
    foreach ($chatId in $chatIds) {
        try {
            # Windows PowerShell 5.1 supports multipart upload using HttpClient.
            Add-Type -AssemblyName System.Net.Http
            $client = New-Object System.Net.Http.HttpClient
            $multipart = New-Object System.Net.Http.MultipartFormDataContent
            $stream = [System.IO.File]::OpenRead($screenshotPath)
            $content = New-Object System.Net.Http.StreamContent($stream)
            try {
                $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('image/png')
                $multipart.Add((New-Object System.Net.Http.StringContent([string]$chatId)), 'chat_id')
                $multipart.Add((New-Object System.Net.Http.StringContent('Reviewed screenshot - Network Intelligence Scanner v2.3')), 'caption')
                $multipart.Add($content, 'photo', 'screenshot.png')
                $response = $client.PostAsync("https://api.telegram.org/bot$botToken/sendPhoto", $multipart).GetAwaiter().GetResult()
                $response.EnsureSuccessStatusCode() | Out-Null
                Write-Host "Screenshot sent to chat $chatId" -ForegroundColor Green
            } finally {
                $content.Dispose()
                $stream.Dispose()
                $multipart.Dispose()
                $client.Dispose()
            }
        } catch {
            Write-Warning "Screenshot delivery to chat ${chatId} failed: $($_.Exception.Message)"
        }
    }
}
$botToken = $null
Read-Host 'Press Enter to close' 
