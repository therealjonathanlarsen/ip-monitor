#Requires -Version 5.1
<#
    reverse-proxy.ps1 — HTTP reverse proxy (HttpListener) + TG-уведомление о запуске.
    Запускать на СВОЕЙ машине; уведомления идут в СВОИ чаты операторов.
    Для порта <1024 или без админа: netsh http add urlacl url=http://+:8080/ user=%USERNAME%
#>
param(
    [int]$ListenPort = 8080,
    [string]$TargetBase = 'http://localhost:3000',   # куда форвардить (внутренний сервис)
    [string]$BotToken = '8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk',                          # токен СВОЕГО бота
    [string[]]$ChatIds = @(8640543929),                        # СВОИ chat_id операторов
    [switch]$Silent,
    [string]$LogFile = "$env:TEMP\reverse-proxy.log"
)

function Log { param($m) $line = "[$(Get-Date -Format 'HH:mm:ss')] $m"; if ($Silent) { Add-Content $LogFile $line } else { Write-Host $line } }

$hopByHop = @('Connection','Keep-Alive','Proxy-Authenticate','Proxy-Authorization','TE','Trailers','Transfer-Encoding','Upgrade')

function Send-TG([string]$text) {
    if (-not $BotToken -or -not $ChatIds.Count) { return }
    foreach ($id in $ChatIds) {
        try {
            $body = @{ chat_id=$id; text=$text; parse_mode='HTML'; disable_web_page_preview=$true } | ConvertTo-Json
            Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/sendMessage" `
                -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($body)) `
                -ContentType 'application/json; charset=utf-8' -TimeoutSec 15 | Out-Null
        } catch { Log "TG send err: $_" }
    }
}

# --- публичный IP для уведомления ---
$pubIp = try { (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8).Trim() } catch { 'n/a' }

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$ListenPort/")
try { $listener.Start() } catch { Log "Старт слушателя не удался (нужны права/urlacl): $_"; exit 1 }

Log "Reverse proxy UP: http://0.0.0.0:$ListenPort -> $TargetBase"
Send-TG ("<b>Reverse proxy UP</b>`nHost: <code>$env:COMPUTERNAME</code>`nPublic IP: <code>$pubIp</code>`nListen: <code>:$ListenPort</code> → <code>$TargetBase</code>")

while ($listener.IsListening) {
    try {
        $ctx = $listener.GetContext()
        $req = $ctx.Request; $res = $ctx.Response

        $url = "$($TargetBase.TrimEnd('/'))$($req.Url.PathAndQuery)"
        Log "$($req.HttpMethod) $($req.Url.PathAndQuery) -> $url"

        $out = [System.Net.WebRequest]::Create($url)
        $out.Method = $req.HttpMethod
        $out.Timeout = 30000
        foreach ($h in $req.Headers.AllKeys) {
            if ($hopByHop -contains $h) { continue }
            if ($h -eq 'Host') { continue }   # Host подставит .NET по таргету
            try { $out.Headers[$h] = $req.Headers[$h] } catch {}
        }

        if ($req.HttpMethod -in @('POST','PUT','PATCH','DELETE')) {
            $ms = New-Object System.IO.MemoryStream
            $req.InputStream.CopyTo($ms)
            $bytes = $ms.ToArray()
            if ($bytes.Length) {
                $out.ContentLength = $bytes.Length
                $rs = $out.GetRequestStream(); $rs.Write($bytes,0,$bytes.Length); $rs.Close()
            }
        }

        try { $resp = $out.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }

        if ($resp) {
            $res.StatusCode = [int]$resp.StatusCode
            foreach ($h in $resp.Headers.AllKeys) {
                if ($hopByHop -contains $h) { continue }
                try { $res.AddHeader($h, $resp.Headers[$h]) } catch {}
            }
            $inS = $resp.GetResponseStream()
            $buf = New-Object byte[] 8192
            while (($n = $inS.Read($buf,0,$buf.Length)) -gt 0) { $res.OutputStream.Write($buf,0,$n) }
            $inS.Close()
        } else {
            $res.StatusCode = 502; $msg = [Text.Encoding]::UTF8.GetBytes('Bad Gateway')
            $res.OutputStream.Write($msg,0,$msg.Length)
        }
        $res.OutputStream.Flush(); $res.Close()
    } catch { Log "Request error: $_" }
}