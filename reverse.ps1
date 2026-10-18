
#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ==========================================
# 1. SETTINGS
# ==========================================

$BotToken = "8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk"

$Recipients = @(
    @{
        ChatId = "8362186234"
        Username = "sovdev"
    },
    @{
        ChatId = "8640543929"
        Username = "jimbo"
    },
)

$ProxyPort = 1080

# Set to public DDNS domain if available.
# Leave empty to send the detected public IPv4.
$PublicHost = ""

# Restrict incoming IPs if known.
# Example: @("203.0.113.10", "198.51.100.25")
# Empty means any remote IP can attempt login.
$AllowedClientIPs = @()

$InstallDir = Join-Path $env:ProgramData "MySocks5"
$ConfigFile = Join-Path $InstallDir "3proxy.cfg"
$ServiceName = "3proxy"

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

function New-ProxyPassword {
    $Chars = "abcdefghijkmnopqrstuvwxyz" +
             "ABCDEFGHJKLMNPQRSTUVWXYZ" +
             "23456789"

    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Bytes = New-Object byte[] 24

    try {
        $Rng.GetBytes($Bytes)
    }
    finally {
        $Rng.Dispose()
    }

    $Password = ""

    foreach ($Byte in $Bytes) {
        $Index = [int]($Byte % $Chars.Length)
        $Password += $Chars[$Index]
    }

    return $Password
}

function Send-Telegram {
    param(
        [string]$ChatId,
        [string]$Message
    )

    $Uri = "https://api.telegram.org/bot$BotToken/sendMessage"

    try {
        $Response = Invoke-RestMethod `
            -Uri $Uri `
            -Method Post `
            -Body @{
                chat_id = $ChatId
                text = $Message
            } `
            -TimeoutSec 20

        if ($Response.ok) {
            Write-Host "[OK] Sent to $ChatId"
            return $true
        }
    }
    catch {
        Write-Warning ("Telegram error for {0}: {1}" -f `
            $ChatId, $_.Exception.Message)
    }

    return $false
}

# ==========================================
# 3. CHECK INPUT
# ==========================================

Write-Host "[1/8] Checking configuration..."

if ($BotToken -eq "YOUR_BOT_TOKEN") {
    throw "Set your Telegram bot token."
}

if ($Recipients.Count -eq 0) {
    throw "Configure at least one recipient."
}

$SeenUsers = @()

foreach ($Recipient in $Recipients) {

    if ($Recipient.Username -notmatch '^[a-zA-Z0-9_]+$') {
        throw "Invalid SOCKS5 username."
    }

    if ($Recipient.ChatId -notmatch '^[0-9]+$') {
        throw "Invalid Telegram chat ID."
    }

    if ($SeenUsers -contains $Recipient.Username) {
        throw "Duplicate SOCKS5 username."
    }

    $SeenUsers += $Recipient.Username
}

# ==========================================
# 4. FIND LAN / PUBLIC IP
# ==========================================

Write-Host "[2/8] Detecting network..."

$Network = Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -and
        $_.IPv4Address -and
        $_.NetAdapter.Status -eq "Up"
    } |
    Select-Object -First 1

if (-not $Network) {
    throw "Active IPv4 connection not found."
}

$LocalIP = $Network.IPv4Address[0].IPAddress

$DetectedPublicIP = ""

try {
    $DetectedPublicIP = [string](
        Invoke-RestMethod `
            -Uri "https://api.ipify.org" `
            -TimeoutSec 15
    )
}
catch {
    Write-Warning "Public IP detection failed."
}

if ([string]::IsNullOrWhiteSpace($PublicHost)) {
    $PublicHost = $DetectedPublicIP
}

if ([string]::IsNullOrWhiteSpace($PublicHost)) {
    $PublicHost = "PUBLIC_IP_NOT_DETECTED"
}

Write-Host "LAN IPv4: $LocalIP"
Write-Host "Public IPv4: $DetectedPublicIP"
Write-Host "Proxy host: $PublicHost"

# ==========================================
# 5. DOWNLOAD OFFICIAL 3PROXY
# ==========================================

Write-Host "[3/8] Preparing 3proxy..."

New-Item -ItemType Directory `
    -Path $InstallDir -Force | Out-Null

$ExistingService = Get-Service `
    -Name $ServiceName `
    -ErrorAction SilentlyContinue

if ($ExistingService) {
    throw "3proxy service already exists. Backup or remove the old installation first."
}

$Release = Invoke-RestMethod `
    -Uri "https://api.github.com/repos/3proxy/3proxy/releases/latest" `
    -Headers @{ "User-Agent" = "PowerShell-Socks5-Setup" }

$Asset = $Release.assets |
    Where-Object {
        $_.name -match '3proxy.*x64\.zip$'
    } |
    Select-Object -First 1

if (-not $Asset) {
    throw "Windows x64 ZIP release not found."
}

$ZipPath = Join-Path $InstallDir "3proxy.zip"

Invoke-WebRequest `
    -Uri $Asset.browser_download_url `
    -OutFile $ZipPath

if ($Asset.digest -match '^sha256:([a-fA-F0-9]{64})$') {
    $Expected = $Matches[1].ToLower()
    $Actual = (Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToLower()

    if ($Expected -ne $Actual) {
        throw "Downloaded file failed SHA256 verification."
    }
}

Expand-Archive `
    -Path $ZipPath `
    -DestinationPath $InstallDir `
    -Force

Remove-Item $ZipPath -Force

$ProxyExe = Get-ChildItem `
    -Path $InstallDir `
    -Recurse `
    -Filter "3proxy.exe" `
    -File |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $ProxyExe) {
    throw "3proxy.exe not found in archive."
}

# ==========================================
# 6. GENERATE INDIVIDUAL ACCOUNTS
# ==========================================

Write-Host "[4/8] Creating accounts..."

$Accounts = @()
$Credentials = @()

foreach ($Recipient in $Recipients) {

    $Password = New-ProxyPassword

    $Accounts += [PSCustomObject]@{
        ChatId = $Recipient.ChatId
        Username = $Recipient.Username
        Password = $Password
    }

    $Credentials += (
        "{0}:CL:{1}" -f $Recipient.Username, $Password
    )
}

$UsersLine = "users " + ($Credentials -join " ")
$AllowedUsers = ($Accounts.Username -join ",")

# ==========================================
# 7. CREATE CONFIGURATION
# ==========================================

Write-Host "[5/8] Configuring proxy..."

$Config = @"
maxconn 100
nserver 1.1.1.1
nserver 8.8.8.8
nscache 65536

$UsersLine
auth strong
allow $AllowedUsers
socks -p$ProxyPort -i$LocalIP
flush
"@

Set-Content `
    -Path $ConfigFile `
    -Value $Config `
    -Encoding ASCII

# Protect configuration and credentials.
& icacls.exe $InstallDir /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" `
    "*S-1-5-32-544:(OI)(CI)F" /T | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Unable to secure installation directory."
}

# ==========================================
# 8. INSTALL WINDOWS SERVICE
# ==========================================

Write-Host "[6/8] Installing service..."

& $ProxyExe $ConfigFile --install

Start-Sleep -Seconds 3

$Service = Get-Service `
    -Name $ServiceName `
    -ErrorAction SilentlyContinue

if (-not $Service) {
    throw "3proxy service was not installed."
}

if ($Service.Status -ne "Running") {
    Start-Service -Name $ServiceName
}

Set-Service `
    -Name $ServiceName `
    -StartupType Automatic

# ==========================================
# 9. FIREWALL
# ==========================================

Write-Host "[7/8] Configuring Windows Firewall..."

$RuleName = "Custom SOCKS5 TCP $ProxyPort"

$RemoteAddresses = "Any"

if ($AllowedClientIPs.Count -gt 0) {
    $RemoteAddresses = $AllowedClientIPs
}

New-NetFirewallRule `
    -DisplayName $RuleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalAddress $LocalIP `
    -LocalPort $ProxyPort `
    -RemoteAddress $RemoteAddresses `
    -Profile Private `
    -ErrorAction Stop | Out-Null

Start-Sleep -Seconds 2

$Service = Get-Service -Name $ServiceName

if ($Service.Status -ne "Running") {
    throw "3proxy service is not running."
}

$Listening = Test-NetConnection `
    -ComputerName $LocalIP `
    -Port $ProxyPort `
    -WarningAction SilentlyContinue

if (-not $Listening.TcpTestSucceeded) {
    throw "Proxy port is not listening."
}

# ==========================================
# 10. SEND DETAILS TO TELEGRAM
# ==========================================

Write-Host "[8/8] Sending Telegram messages..."

$SentCount = 0
$FailedCount = 0

foreach ($Account in $Accounts) {

    $Message = @"
SOCKS5 PROXY READY

Computer: $env:COMPUTERNAME

Protocol: SOCKS5
Host: $PublicHost
Port: $ProxyPort

Username: $($Account.Username)
Password: $($Account.Password)

LAN address: $LocalIP
Windows service: Running

IMPORTANT:
External access requires router port forwarding.
SOCKS5 authentication is not encrypted.
"@

    $Result = Send-Telegram `
        -ChatId $Account.ChatId `
        -Message $Message

    if ($Result) {
        $SentCount++
    }
    else {
        $FailedCount++
    }

    Start-Sleep -Milliseconds 500
}

# ==========================================
# 11. SUMMARY
# ==========================================

Write-Host ""
Write-Host "========================================"
Write-Host "SOCKS5 SERVER SETUP COMPLETED"
Write-Host "========================================"
Write-Host "Local IP:      $LocalIP"
Write-Host "Public IP:     $DetectedPublicIP"
Write-Host "Proxy Host:    $PublicHost"
Write-Host "Port:          $ProxyPort"
Write-Host "Service:       $($Service.Status)"
Write-Host "Sent:          $SentCount"
Write-Host "Failed:        $FailedCount"
Write-Host "========================================"
Write-Host ""
Write-Host "NEXT STEP:"
Write-Host "Forward TCP port $ProxyPort on your router"
Write-Host "to $LocalIP port $ProxyPort."
Write-Host ""
Write-Host "Reserve the PC LAN IP in router DHCP settings."
Write-Host ""
Write-Host "Never share bot token publicly."
