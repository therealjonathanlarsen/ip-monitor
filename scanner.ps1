
# TELEGRAM BOT SETTINGS
$botToken = "8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk"

$chatIds = @(
    "8640543929",
    "8399897686"
)

# NETWORK REPORT
$ip = Read-Host "Public IP"
$country = Read-Host "Country"
$city = Read-Host "City"
$isp = Read-Host "ISP"
$asn = Read-Host "ASN"
$vpn = Read-Host "VPN status"
$proxy = Read-Host "Proxy status"

$scanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Escape HTML values
function Escape-Html($value) {
    return [System.Net.WebUtility]::HtmlEncode(
        [string]$value
    )
}

# BUILD TELEGRAM RICH MESSAGE
$html = @"
<h3>NEW HOTSPOT AVAILABLE</h3>

<table>
<tr><th>PARAMETER</th><th>VALUE</th></tr>
<tr><td>Public IP</td><td>$(Escape-Html $ip)</td></tr>
<tr><td>Country</td><td>$(Escape-Html $country)</td></tr>
<tr><td>City</td><td>$(Escape-Html $city)</td></tr>
<tr><td>ISP</td><td>$(Escape-Html $isp)</td></tr>
<tr><td>ASN</td><td>$(Escape-Html $asn)</td></tr>
<tr><td>VPN</td><td>$(Escape-Html $vpn)</td></tr>
<tr><td>Proxy</td><td>$(Escape-Html $proxy)</td></tr>
<tr><td>Scan Time</td><td>$scanTime</td></tr>
</table>
"@

# SHOW REPORT AND REQUEST CONFIRMATION
Write-Host ""
Write-Host $html
Write-Host ""

$confirm = Read-Host "Send report to both chats? (YES/NO)"

if ($confirm -ne "YES") {
    Write-Host "Cancelled"
    exit
}

# SEND RICH MESSAGE
$richMessage = @{
    html = $html
}

foreach ($chatId in $chatIds) {
    try {
        $body = @{
            chat_id = $chatId
            rich_message = $richMessage
        } | ConvertTo-Json -Depth 10

        Invoke-RestMethod `
            -Uri "https://api.telegram.org/bot$botToken/sendRichMessage" `
            -Method Post `
            -ContentType "application/json; charset=utf-8" `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
            -ErrorAction Stop | Out-Null

        Write-Host "Sent to $chatId"
    }
    catch {
        Write-Host "Error for $chatId"
        Write-Host $_.Exception.Message
    }
}

Read-Host "Press Enter to exit"
