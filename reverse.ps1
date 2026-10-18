
#Requires -Version 5.1

# ========= НАСТРОЙКИ =========
$BotToken = "8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk"
$ChatId   = "8640543929"

# Локальный сервис, который нужно проксировать
$Backend = "127.0.0.1:3000"

# Адрес reverse proxy
$Listen = "127.0.0.1:8080"

# ========= ПОДГОТОВКА =========
$ErrorActionPreference = "Stop"

$WorkDir = Join-Path $env:LOCALAPPDATA "MyReverseProxy"
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

$Caddy = Join-Path $WorkDir "caddy.exe"
$Config = Join-Path $WorkDir "Caddyfile"

# ========= УСТАНОВКА CADDY =========
if (-not (Test-Path $Caddy)) {
    Write-Host "Downloading Caddy..."

    # Официальный бинарный релиз для Windows AMD64
    $Release = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/caddyserver/caddy/releases/latest"

    $Asset = $Release.assets |
        Where-Object { $_.name -match '^caddy_.*_windows_amd64\.zip$' } |
        Select-Object -First 1

    if (-not $Asset) {
        throw "Windows AMD64 release not found."
    }

    $Zip = Join-Path $WorkDir "caddy.zip"

    Invoke-WebRequest `
        -Uri $Asset.browser_download_url `
        -OutFile $Zip

    Expand-Archive -Path $Zip -DestinationPath $WorkDir -Force
    Remove-Item $Zip
}

# ========= КОНФИГУРАЦИЯ =========
@"
{
    auto_https off
}

http://$Listen {
    reverse_proxy $Backend
}
"@ | Set-Content -Path $Config -Encoding ASCII

# ========= ЗАПУСК =========
$Process = Start-Process `
    -FilePath $Caddy `
    -ArgumentList @("run", "--config", "`"$Config`"", "--adapter", "caddyfile") `
    -PassThru `
    -WindowStyle Hidden

Start-Sleep -Seconds 2

if ($Process.HasExited) {
    throw "Reverse proxy failed to start."
}

# ========= TELEGRAM =========
$ProxyUrl = "http://$Listen"

$Message = @"
Reverse proxy started

PC: $env:COMPUTERNAME
User: $env:USERNAME
Proxy: $ProxyUrl
Backend: $Backend
PID: $($Process.Id)
Status: RUNNING
"@

$TelegramApi = "https://api.telegram.org/bot$BotToken/sendMessage"

Invoke-RestMethod `
    -Uri $TelegramApi `
    -Method Post `
    -Body @{
        chat_id = $ChatId
        text = $Message
    } | Out-Null

Write-Host "Reverse proxy: $ProxyUrl"
Write-Host "Telegram notification sent."
Write-Host "Process ID: $($Process.Id)"
