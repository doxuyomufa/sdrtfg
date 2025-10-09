# mitm_manager.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- CONFIG ----------------
$WorkDir = "C:\mitm"
$PyAddon = Join-Path $WorkDir "mitm_redirect_addon.py"
$MitmPort = 8080
$LogFile = Join-Path $WorkDir "mitm_manager.log"
$MitmExeSearch = @(
    "mitmdump",
    "C:\Program Files\Python311\Scripts\mitmdump.exe", 
    "C:\Program Files (x86)\Python311\Scripts\mitmdump.exe",
    "$env:LocalAppData\Programs\Python\Python312\Scripts\mitmdump.exe",
    "$env:LocalAppData\Programs\Python\Python311\Scripts\mitmdump.exe"
)
$ForceFlag = "C:\temp\mitm_force_redirect"
$OneShotFlag = "C:\temp\mitm_reset_once"
$RedirectFile = Join-Path $WorkDir "redirect_target.txt"
# -----------------------------------------

# Установка PATH для Python
$env:PATH = "$env:LocalAppData\Programs\Python\Python312;$env:LocalAppData\Programs\Python\Python312\Scripts;$env:PATH"

function Log-Write {
    param([string]$msg, [string]$level="INFO")
    $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[{0}] {1} - {2}" -f $time, $level, $msg
    Write-Host $line
    try {
        Add-Content -Path $LogFile -Value $line -Force
    } catch {}
}

function Ensure-WorkDir {
    if (-not (Test-Path $WorkDir)) {
        New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
        Log-Write ("Created work dir: {0}" -f $WorkDir)
    }
}

function Find-Mitmdump {
    # Сначала проверяем PATH с обновленными путями Python
    foreach ($candidate in $MitmExeSearch) {
        try {
            if ($candidate -eq "mitmdump") {
                $cmd = Get-Command mitmdump -ErrorAction SilentlyContinue
                if ($cmd) {
                    Log-Write ("Found mitmdump in PATH: {0}" -f $cmd.Source)
                    return $cmd.Source
                }
            } elseif (Test-Path $candidate) {
                Log-Write ("Found mitmdump at: {0}" -f $candidate)
                return $candidate
            }
        } catch {}
    }
    
    # Если не нашли, пробуем через where
    try {
        $whereResult = where.exe mitmdump 2>$null
        if ($whereResult) {
            Log-Write ("Found mitmdump via where: {0}" -f $whereResult)
            return $whereResult
        }
    } catch {}
    
    Log-Write "mitmdump not found in any known locations" "ERROR"
    return $null
}

function Stop-ConflictingProcesses {
    Log-Write "Stopping conflicting processes on port $MitmPort..."
    
    # Останавливаем процессы Python, использующие наш порт
    Get-Process -Name python*,mitmdump,mitmproxy,mitmweb -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $procPort = (Get-NetTCPConnection -OwningProcess $_.Id -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $MitmPort })
            if ($procPort) {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Log-Write ("Killed process using port {0}: {1} (PID: {2})" -f $MitmPort, $_.ProcessName, $_.Id)
            }
        } catch {}
    }
    
    # Останавливаем любые другие процессы на нашем порту
    try {
        $portProcesses = Get-NetTCPConnection -LocalPort $MitmPort -ErrorAction SilentlyContinue
        if ($portProcesses) {
            $portProcesses | ForEach-Object {
                try {
                    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) {
                        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
                        Log-Write ("Killed process using port {0}: {1} (PID: {2})" -f $MitmPort, $proc.ProcessName, $_.OwningProcess)
                    }
                } catch {}
            }
        }
    } catch {}
    
    Start-Sleep -Seconds 1
}

function Test-PortAvailable {
    param([int]$Port = $MitmPort)
    try {
        $connection = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
        return (-not $connection)
    } catch {
        return $true
    }
}

function Ensure-PortAvailable {
    param([int]$Port = $MitmPort, [int]$MaxRetries = 3)
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        if (Test-PortAvailable -Port $Port) {
            Log-Write "Target port $Port is available"
            return $true
        }
        
        Log-Write "Port $Port is busy, attempting to free... (attempt $i/$MaxRetries)" "WARN"
        Stop-ConflictingProcesses
        
        if ($i -lt $MaxRetries) {
            Start-Sleep -Seconds 2
        }
    }
    
    Log-Write "Failed to free port $Port after $MaxRetries attempts" "ERROR"
    return $false
}

function Reset-Proxy-And-Stop-Mitmdump {
    Log-Write "Stopping mitmdump processes..."
    Get-Process -Name mitmdump,mitmproxy,mitmweb -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Log-Write ("Killed mitmdump PID: {0}" -f $_.Id)
        } catch {
            Log-Write ("Failed to kill PID {0}: {1}" -f $_.Id, $_) "WARN"
        }
    }

    # Также останавливаем конфликтующие процессы Python
    Stop-ConflictingProcesses

    try {
        netsh winhttp reset proxy | Out-Null
        Log-Write "WinHTTP proxy reset."
    } catch {
        Log-Write ("Failed winhttp reset: {0}" -f $_) "WARN"
    }

    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Force
        Log-Write "Proxy disabled in registry."
    } catch {
        Log-Write ("Failed to disable proxy in registry: {0}" -f $_) "WARN"
    }

    try {
        ipconfig /flushdns | Out-Null
        Log-Write "DNS cache flushed."
    } catch {
        Log-Write ("Failed to flush DNS: {0}" -f $_) "WARN"
    }
}

function Safe-Exit {
    Log-Write "Performing safe exit cleanup..."
    Reset-Proxy-And-Stop-Mitmdump
    Log-Write "Cleanup completed. Exiting."
    exit
}

function Ensure-MitmCA {
    $certFile = Join-Path $env:USERPROFILE ".mitmproxy\mitmproxy-ca-cert.pem"
    if (-not (Test-Path $certFile)) {
        Log-Write ("MITM CA not found at {0}. Generating..." -f $certFile)
        $mitmPath = Find-Mitmdump
        if (-not $mitmPath) {
            Log-Write "mitmdump not found; cannot auto-generate CA." "ERROR"; return $false
        }
        try {
            $proc = Start-Process -FilePath $mitmPath -ArgumentList "--set","block_global=false" -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
            Start-Sleep -Seconds 3
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Milliseconds 500
        } catch {
            Log-Write ("Transient mitmdump start failed: {0}" -f $_) "WARN"
        }
    }
    if (-not (Test-Path $certFile)) {
        Log-Write ("No CA pem found at {0}. Please run mitmdump manually." -f $certFile) "ERROR"
        return $false
    }
    try {
        Import-Certificate -FilePath $certFile -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
        Log-Write "Imported mitmproxy CA into CurrentUser\Root."
        return $true
    } catch {
        Log-Write ("Failed to import CA: {0}" -f $_) "ERROR"
        return $false
    }
}

function Set-SystemProxies {
    param([string]$proxyHost="127.0.0.1",[int]$proxyPort=$MitmPort)
    $proxy = "{0}:{1}" -f $proxyHost,$proxyPort
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name ProxyServer -Value $proxy -Force
        Set-ItemProperty -Path $regPath -Name ProxyOverride -Value "<local>" -Force

        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinInet {
    [DllImport("wininet.dll", SetLastError=true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
"@
        $INTERNET_OPTION_SETTINGS_CHANGED = 39
        $INTERNET_OPTION_REFRESH = 37
        [WinInet]::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_SETTINGS_CHANGED, [IntPtr]::Zero, 0) | Out-Null
        [WinInet]::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_REFRESH, [IntPtr]::Zero, 0) | Out-Null
        Log-Write ("Set system proxy to {0}" -f $proxy)
        return $true
    } catch {
        Log-Write ("Failed to set system proxy: {0}" -f $_) "ERROR"
        return $false
    }
}

function Clear-SystemProxies {
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0 -Type DWord -Force
        Remove-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regPath -Name ProxyOverride -ErrorAction SilentlyContinue

        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinInet {
    [DllImport("wininet.dll", SetLastError=true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
"@
        $INTERNET_OPTION_SETTINGS_CHANGED = 39
        $INTERNET_OPTION_REFRESH = 37
        [WinInet]::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_SETTINGS_CHANGED, [IntPtr]::Zero, 0) | Out-Null
        [WinInet]::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_REFRESH, [IntPtr]::Zero, 0) | Out-Null
        Log-Write "Cleared system proxies (WinINET + WinHTTP)."
        return $true
    } catch {
        Log-Write ("Failed to clear system proxies: {0}" -f $_) "WARN"
        return $false
    }
}

function Close-Browsers-Gracefully {
    param([string]$closeOption)

    if ($closeOption -eq "none") {
        Log-Write "Skipping browser close as requested."
        return
    }

    Log-Write "Closing browsers gracefully to preserve session..."

    # Сначала пытаемся закрыть через CloseMainWindow (сохраняет сессию)
    Get-Process -Name chrome,msedge,firefox -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($_.CloseMainWindow()) {
                Log-Write ("Sent close signal to {0} (PID: {1})" -f $_.ProcessName, $_.Id)
            }
        } catch {
            Log-Write ("Error sending close to {0}: {1}" -f $_.ProcessName, $_) "WARN"
        }
    }

    Start-Sleep -Seconds 3

    if ($closeOption -eq "full") {
        # Если выбрано полное закрытие, убиваем оставшиеся процессы
        Get-Process -Name chrome,msedge,firefox -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Log-Write ("Force closed {0} (PID: {1})" -f $_.ProcessName, $_.Id)
            } catch {
                Log-Write ("Failed to force close {0}: {1}" -f $_.ProcessName, $_) "WARN"
            }
        }
        Log-Write "All browsers fully closed."
    } else {
        # Если выбрано graceful, оставляем как есть
        $remaining = Get-Process -Name chrome,msedge,firefox -ErrorAction SilentlyContinue
        if ($remaining) {
            Log-Write ("Some browsers still running (user may have canceled close): {0}" -f ($remaining.ProcessName -join ", "))
        } else {
            Log-Write "All browsers closed gracefully."
        }
    }
}

function Start-Mitmdump {
    Ensure-WorkDir
    
    # Проверяем доступность порта перед запуском
    if (-not (Ensure-PortAvailable)) {
        Log-Write "Cannot start mitmdump - port $MitmPort is unavailable" "ERROR"
        return $false
    }
    
    Reset-Proxy-And-Stop-Mitmdump

    $mitmPath = Find-Mitmdump
    if (-not $mitmPath) {
        Log-Write "mitmdump not found!" "ERROR"; return $false
    }

    if (-not (Test-Path $PyAddon)) {
        Log-Write ("Python addon missing: {0}" -f $PyAddon) "ERROR"; return $false
    }

    $args = @("-p", "$MitmPort", "-s", "$PyAddon")

    Log-Write ("Starting mitmdump: {0} {1}" -f $mitmPath, ($args -join ' '))
    # ЗАПУСК В СКРЫТОМ РЕЖИМЕ - WindowStyle Hidden
    $proc = Start-Process -FilePath $mitmPath -ArgumentList $args -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru

    Start-Sleep -Seconds 2
    
    # Проверяем что процесс запустился
    if ($proc.HasExited) {
        Log-Write "mitmdump process exited immediately after start" "ERROR"
        return $false
    }
    
    Set-SystemProxies | Out-Null
    Log-Write ("mitmdump started successfully, PID: {0}" -f $proc.Id)
    return $true
}

# ---------------- REDIRECT FUNCTIONS ----------------
function Enable-ForceRedirect {
    if (-not (Test-Path (Split-Path $ForceFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $ForceFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $ForceFlag -Force | Out-Null
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Log-Write "Force redirect enabled."
    Start-Mitmdump
}

function Enable-OneShotRedirect {
    if (-not (Test-Path (Split-Path $OneShotFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $OneShotFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $OneShotFlag -Force | Out-Null
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Log-Write "One-shot redirect enabled."
    Start-Mitmdump
}

# ---------------- MAIN ----------------
Ensure-WorkDir
Log-Write "MITM Manager starting."

# Reset all
Reset-Proxy-And-Stop-Mitmdump
Clear-SystemProxies

# Ensure CA installed
Ensure-MitmCA | Out-Null

# Ask user for redirect URL
$redirectURL = Read-Host "Enter the URL to redirect clients to (include https://)"
Set-Content -Path $RedirectFile -Value $redirectURL -Force
Log-Write ("Target URL saved to {0}" -f $RedirectFile)

# Ask user about browser closing
Write-Host "`nChoose browser closing option:"
Write-Host "1) Full close (close all browser windows completely)"
Write-Host "2) Graceful close (try to close gracefully, keep if user cancels)"
Write-Host "3) Don't close browsers"
$closeChoice = Read-Host "Choose option (1-3)"

$closeOption = switch ($closeChoice) {
    "1" { "full" }
    "2" { "graceful" }
    "3" { "none" }
    default { "graceful" }
}

Close-Browsers-Gracefully -closeOption $closeOption

# Function menu
while ($true) {
    Write-Host ""
    Write-Host "--------------- MITM Redirect Manager ---------------"
    Write-Host "1) Full reset"
    Write-Host "2) Enable one-shot redirect"
    Write-Host "3) Enable force redirect"
    Write-Host "4) Disable redirects"
    Write-Host "5) Tail log"
    Write-Host "6) Check system preparation"
    Write-Host "7) Safe exit"
    $opt = Read-Host "Choose option (1-7)"

    switch ($opt) {
        "1" {
            Reset-Proxy-And-Stop-Mitmdump;
            Clear-SystemProxies | Out-Null;
            Log-Write "Full reset performed."
        }
        "2" { Enable-OneShotRedirect }
        "3" { Enable-ForceRedirect }
        "4" {
            Remove-Item -Path $ForceFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $OneShotFlag -Force -ErrorAction SilentlyContinue
            Clear-SystemProxies | Out-Null
            Reset-Proxy-And-Stop-Mitmdump
            Log-Write "Redirects disabled and proxy cleared."
        }
        "5" {
            if (Test-Path $LogFile) {
                Get-Content -Path $LogFile -Tail 200 -Wait
            } else {
                Write-Host "Log not found."
            }
        }
        "6" {
            Write-Host "System preparation check..."
            Ensure-PortAvailable | Out-Null
            Log-Write "System preparation completed"
        }
        "7" { Safe-Exit }
        default { Write-Host "Invalid choice" }
    }
}
