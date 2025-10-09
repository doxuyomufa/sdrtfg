# mitm_manager.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- CONFIG ----------------
$WorkDir     = "C:\mitm"
$PyAddon     = Join-Path $WorkDir "mitm_redirect_addon.py"
$MitmPort    = 8080
$LogFile     = Join-Path $WorkDir "mitm_manager.log"
$MitmExeSearch = @(
    "mitmdump",
    "C:\Program Files\Python311\Scripts\mitmdump.exe",
    "C:\Program Files (x86)\Python311\Scripts\mitmdump.exe"
)
$ForceFlag   = "C:\temp\mitm_force_redirect"
$OneShotFlag = "C:\temp\mitm_reset_once"
$RedirectFile = Join-Path $WorkDir "redirect_target.txt"
# -----------------------------------------

# ---------------- ENVIRONMENT SETUP ----------------
# Ensure Python 3.12 is in PATH
$pythonDir = "$env:LocalAppData\Programs\Python312"
$pythonScripts = "$pythonDir\Scripts"
if (-not ($env:PATH).Contains($pythonDir)) {
    $env:PATH = "$pythonDir;$pythonScripts;$env:PATH"
    Write-Host "[INFO] Added Python312 and Scripts to PATH."
}

function Log-Write {
    param([string]$msg, [string]$level="INFO")
    $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[{0}] {1} - {2}" -f $time, $level, $msg
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -Force } catch {}
}

function Ensure-WorkDir {
    if (-not (Test-Path $WorkDir)) {
        New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
        Log-Write ("Created work dir: {0}" -f $WorkDir)
    }
}

function Find-Mitmdump {
    foreach ($candidate in $MitmExeSearch) {
        try {
            if ($candidate -eq "mitmdump") {
                $cmd = Get-Command mitmdump -ErrorAction SilentlyContinue
                if ($cmd) { return $cmd.Source }
            } elseif (Test-Path $candidate) {
                return $candidate
            }
        } catch {}
    }
    return $null
}

function Free-Port {
    param([int]$Port)
    $used = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($used) {
        foreach ($conn in $used) {
            try {
                Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
                Log-Write ("Killed process {0} occupying port {1}" -f $conn.OwningProcess, $Port)
            } catch {
                Log-Write ("Failed to kill process {0} on port {1}: {2}" -f $conn.OwningProcess, $Port, $_) "WARN"
            }
        }
        Start-Sleep -Seconds 1
    }
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
    try {
        netsh winhttp reset proxy | Out-Null
        Log-Write "WinHTTP proxy reset."
    } catch {
        Log-Write ("Failed winhttp reset: {0}" -f $_) "WARN"
    }
}

function Ensure-MitmCA {
    $certFile = Join-Path $env:USERPROFILE ".mitmproxy\mitmproxy-ca-cert.pem"
    if (-not (Test-Path $certFile)) {
        Log-Write ("MITM CA not found at {0}. Attempting to generate..." -f $certFile)
        $mitmPath = Find-Mitmdump
        if (-not $mitmPath) { Log-Write "mitmdump not found; cannot auto-generate CA." "ERROR"; return $false }
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
        Log-Write "Imported mitmproxy CA into CurrentUser\\Root."
        return $true
    } catch {
        Log-Write ("Failed to import CA: {0}" -f $_) "ERROR"
        return $false
    }
}

function Set-WinInetProxy {
    param([string]$proxy = "127.0.0.1:8080")
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
        Log-Write ("Set WinINET proxy to {0}" -f $proxy)
        return $true
    } catch {
        Log-Write ("Failed to set WinINET proxy: {0}" -f $_) "ERROR"
        return $false
    }
}

function Clear-WinInetProxy {
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
        Log-Write "Cleared WinINET proxy"
        return $true
    } catch {
        Log-Write ("Failed to clear WinINET proxy: {0}" -f $_) "WARN"
        return $false
    }
}

function Start-Mitmdump-Visible {
    param([int]$Port = $MitmPort)
    Ensure-WorkDir
    Reset-Proxy-And-Stop-Mitmdump
    Free-Port -Port $Port   # <--- добавлено для освобождения порта

    $mitmPath = Find-Mitmdump
    if (-not $mitmPath) { Log-Write "mitmdump not found!" "ERROR"; return $false }
    if (-not (Test-Path $PyAddon)) { Log-Write ("Python addon missing: {0}" -f $PyAddon) "ERROR"; return $false }

    $args = @("-p", "$Port", "-s", "$PyAddon")
    Log-Write ("Starting mitmdump visible: {0} {1}" -f $mitmPath, ($args -join ' '))
    try {
        Start-Process -FilePath $mitmPath -ArgumentList $args -WorkingDirectory $WorkDir -WindowStyle Normal
    } catch {
        Log-Write ("Failed to start mitmdump visible: {0}" -f $_) "ERROR"
        return $false
    }

    Start-Sleep -Seconds 1
    Set-WinInetProxy -proxy ("127.0.0.1:{0}" -f $Port) | Out-Null
    return $true
}

function Enable-ForceRedirect {
    if (-not (Test-Path (Split-Path $ForceFlag))) { New-Item -ItemType Directory -Path (Split-Path $ForceFlag) -Force | Out-Null }
    New-Item -ItemType File -Path $ForceFlag -Force | Out-Null
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Log-Write "Force redirect enabled."
    Start-Mitmdump-Visible
}

function Enable-OneShotRedirect {
    if (-not (Test-Path (Split-Path $OneShotFlag))) { New-Item -ItemType Directory -Path (Split-Path $OneShotFlag) -Force | Out-Null }
    New-Item -ItemType File -Path $OneShotFlag -Force | Out-Null
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Log-Write "One-shot redirect enabled."
    Start-Mitmdump-Visible
}

function Disable-Redirects {
    Remove-Item -Path $ForceFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -Force -ErrorAction SilentlyContinue
    Clear-WinInetProxy | Out-Null
    Reset-Proxy-And-Stop-Mitmdump
    Log-Write "Redirects disabled and proxy cleared."
}

function Tail-Log {
    if (-not (Test-Path $LogFile)) { Write-Host "Log not found."; return }
    Get-Content -Path $LogFile -Tail 200 -Wait
}

# ---------------- MAIN ----------------
Ensure-WorkDir
Log-Write "MITM Redirect Manager starting."
Ensure-MitmCA | Out-Null

while ($true) {
    Write-Host ""
    Write-Host "--------------- MITM Redirect Manager ---------------"
    Write-Host "1) Full reset (stop mitmdump + reset proxy)"
    Write-Host "2) Enable one-shot redirect (single redirect then flag removed)"
    Write-Host "3) Enable force redirect (always redirect)"
    Write-Host "4) Disable redirects"
    Write-Host "5) Tail manager log"
    Write-Host "6) Start mitmdump visible (no flag changes)"
    Write-Host "7) Exit (stop mitmdump and clear proxy)"
    $opt = Read-Host "Choose option (1-7)"

    switch ($opt) {
        "1" { Reset-Proxy-And-Stop-Mitmdump; Clear-WinInetProxy | Out-Null; Log-Write "Full reset performed." }
        "2" { Enable-OneShotRedirect }
        "3" { Enable-ForceRedirect }
        "4" { Disable-Redirects }
        "5" { Tail-Log }
        "6" { Start-Mitmdump-Visible }
        "7" { Disable-Redirects; Log-Write "Exiting manager."; break }
        default { Write-Host "Invalid choice" }
    }
}
