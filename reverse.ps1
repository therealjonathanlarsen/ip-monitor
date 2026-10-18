
#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# =========================================
# SETTINGS
# =========================================

$BotToken = "8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk"
$ProxyPort = 1080

# Telegram recipients and SOCKS5 usernames
$Recipients = @(
    @{ ChatId = "8640543929"; Username = "user1" },
    @{ ChatId = "8362186234"; Username = "user2" },
)

$InstallDir = "$env:ProgramData\MySocks5"
$ConfigFile = "$InstallDir\3proxy.cfg"
$ServiceName = "3proxy"
$FirewallRule = "MySocks5-LAN"

# =========================================
# VALIDATION
# =========================================

if ($BotToken -eq "YOUR_BOT_TOKEN") {
    throw "Configure Telegram BotToken first."
}

if (-not $Recipients -or $Recipients.Count -eq 0) {
    throw "At least one recipient is required."
}

$Names = @()

foreach ($Recipient in $Recipients) {
    if ($Recipient.Username -notmatch '^[a-zA-Z0-9_]+$') {
        throw "Invalid username: $($Recipient.Username)"
    }

    if ($Recipient.ChatId -notmatch '^-?[0-9]+$') {
        throw "Invalid Telegram ChatId."
    }

    if ($Names -contains $Recipient.Username) {
        throw "Duplicate proxy username."
    }

    $Names += $Recipient.Username
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "An existing 3proxy service was detected. This script does not overwrite it."
}

# =========================================
# HELPERS
# =========================================

function New-SecurePassword {
    param([int]$Length = 24)

    $Alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    $Bytes = New-Object byte[] $Length

    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $Rng.GetBytes($Bytes)
    }
    finally {
        $Rng.Dispose()
    }

    return -join ($Bytes | ForEach-Object {
        $Alphabet[[int]($_ % $Alphabet.Length)]
    })
}

function Send-Telegram {
    param(
        [string]$ChatId,
        [string]$Message
    )

    $Url = "https://api.telegram.org/bot$BotToken/sendMessage"

    try {
        $Result = Invoke-RestMethod `
            -Uri $Url `
            -Method Post `
            -Body @{
                chat_id = $ChatId
                text = $Message
            } `
            -TimeoutSec 20

        if ($Result.ok) {
            Write-Host "[OK] Telegram: $ChatId"
            return $true
        }
    }
    catch {
        Write-Warning "Telegram failed for $ChatId : $($_.Exception.Message)"
    }

    return $false
}

# =========================================
# DETECT LOCAL IP
# =========================================

Write-Host "[1/7] Detecting network..."

$Interface = Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -and
        $_.IPv4Address -and
        $_.NetAdapter.Status -eq "Up"
    } |
    Select-Object -First 1

if (-not $Interface) {
    throw "No active IPv4 network interface found."
}

$LANIP = $Interface.IPv4Address[0].IPAddress

Write-Host "Local IP: $LANIP"

# =========================================
# DOWNLOAD 3PROXY
# =========================================

Write-Host "[2/7] Downloading 3proxy..."

New-Item -Path $InstallDir -ItemType Directory -Force |
    Out-Null

$Release = Invoke-RestMethod `
    -Uri "https://api.github.com/repos/3proxy/3proxy/releases/latest"

$Asset = $Release.assets |
    Where-Object {
        $_.name -match '^3proxy-[0-9.]+-x64\.zip$'
    } |
    Select-Object -First 1

if (-not $Asset) {
    throw "Windows x64 release not found."
}

$ZipPath = Join-Path $InstallDir "3proxy.zip"

Invoke-WebRequest `
    -Uri $Asset.browser_download_url `
    -OutFile $ZipPath

# Verify integrity if the release provides a SHA256 digest
if ($Asset.digest -and $Asset.digest -match '^sha256:([a-fA-F0-9]{64})$') {
    $ExpectedHash = $Matches[1].ToLowerInvariant()
    $ActualHash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($ActualHash -ne $ExpectedHash) {
        throw "3proxy download checksum mismatch."
    }
}

Expand-Archive `
    -Path $ZipPath `
    -DestinationPath $InstallDir `
    -Force

Remove-Item $ZipPath -Force

$ProxyExe = Get-ChildItem $InstallDir -Recurse -File |
    Where-Object { $_.Name -eq "3proxy.exe" } |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $ProxyExe) {
    throw "3proxy.exe not found."
}

# =========================================
# CREATE USERS
# =========================================

Write-Host "[3/7] Creating proxy accounts..."

$Accounts = @()
$UserEntries = @()

foreach ($Recipient in $Recipients) {

    $Password = New-SecurePassword

    $Accounts += [PSCustomObject]@{
        ChatId = $Recipient.ChatId
        Username = $Recipient.Username
        Password = $Password
    }

    $UserEntries += "$($Recipient.Username):CL:$Password"

    Write-Host "Created: $($Recipient.Username)"
}

$UsersLine = "users " + ($UserEntries -join " ")
$AllowedUsers = ($Accounts.Username -join ",")

# =========================================
# CREATE CONFIG
# =========================================

Write-Host "[4/7] Writing configuration..."

$Config = @"
maxconn 100
nserver 1.1.1.1
nserver 8.8.8.8
nscache 65536

$UsersLine
auth strong
allow $AllowedUsers
socks -p$ProxyPort -i$LANIP
flush
"@

Set-Content `
    -Path $ConfigFile `
    -Value $Config `
    -Encoding ASCII

# Protect credentials and installation directory
& icacls.exe $InstallDir /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" `
             "*S-1-5-32-544:(OI)(CI)F" /T | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to secure installation directory."
}

# =========================================
# WINDOWS SERVICE
# =========================================

Write-Host "[5/7] Installing service..."

& $ProxyExe $ConfigFile --install

if ($LASTEXITCODE -ne 0) {
    throw "Service installation failed."
}

Start-Sleep -Seconds 2

$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if (-not $Service) {
    throw "3proxy service not found."
}

if ($Service.Status -ne "Running") {
    Start-Service -Name $ServiceName
}

Set-Service -Name $ServiceName -StartupType Automatic

Start-Sleep -Seconds 2

$Service = Get-Service -Name $ServiceName

if ($Service.Status -ne "Running") {
    throw "Proxy service is not running."
}

# =========================================
# WINDOWS FIREWALL
# =========================================

Write-Host "[6/7] Configuring firewall..."

Get-NetFirewallRule -DisplayName $FirewallRule `
    -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule

New-NetFirewallRule `
    -DisplayName $FirewallRule `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalAddress $LANIP `
    -LocalPort $ProxyPort `
    -RemoteAddress LocalSubnet `
    -Profile Private `
    -ErrorAction Stop | Out-Null

# =========================================
# VERIFY PORT
# =========================================

$Check = Test-NetConnection `
    -ComputerName $LANIP `
    -Port $ProxyPort `
    -WarningAction SilentlyContinue

if (-not $Check.TcpTestSucceeded) {
    throw "SOCKS5 port is not accepting TCP connections."
}

# =========================================
# TELEGRAM BROADCAST
# =========================================

Write-Host "[7/7] Sending proxy details..."

$Success = 0
$Failed = 0

foreach ($Account in $Accounts) {

    $Message = @"
SOCKS5 PROXY READY

Computer: $env:COMPUTERNAME

Protocol: SOCKS5
Host: $LANIP
Port: $ProxyPort

Username: $($Account.Username)
Password: $($Account.Password)

Authentication: Enabled
Access: Local network only

Configure your SOCKS5 client with these credentials.
"@

    $Sent = Send-Telegram `
        -ChatId $Account.ChatId `
        -Message $Message

    if ($Sent) {
        $Success++
    }
    else {
        $Failed++
    }

    Start-Sleep -Milliseconds 500
}

# =========================================
# SUMMARY
# =========================================

Write-Host ""
Write-Host "======================================"
Write-Host "SOCKS5 SETUP FINISHED"
Write-Host "======================================"
Write-Host "Host: $LANIP"
Write-Host "Port: $ProxyPort"
Write-Host "Service: $ServiceName"
Write-Host "Status: $($Service.Status)"
Write-Host "Telegram sent: $Success"
Write-Host "Telegram failed: $Failed"
Write-Host "======================================"

Write-Host ""
Write-Host "Proxy accounts:"
$Accounts | Select-Object ChatId, Username |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Completed."
