# mitm_manager.ps1
# Fully corrected: visible mitmdump, WinINET proxy setup, mitm CA install, one-shot/force flags.
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
# -----------------------------------------

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

function Reset-Proxy-And-Stop-Mitmdump {
    Log-Write "Stopping mitmdump processes..."
    Get-Process -Name mitmdump -ErrorAction SilentlyContinue | ForEach-Object {
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

function Stop-ConflictingProcesses {
    Log-Write "Stopping conflicting processes..."
    
    # Stop Python processes that might be using our port
    Get-Process -Name python* -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $procPort = (Get-NetTCPConnection -OwningProcess $_.Id -ErrorAction SilentlyContinue).LocalPort
            if ($procPort -contains $MitmPort) {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Log-Write ("Killed Python process using port {0}: PID {1}" -f $MitmPort, $_.Id)
            }
        } catch {}
    }
    
    # Stop any process using our target port
    try {
        $portProcess = Get-NetTCPConnection -LocalPort $MitmPort -ErrorAction SilentlyContinue
        if ($portProcess) {
            $portProcess | ForEach-Object {
                try {
                    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
                    Log-Write ("Killed process using port {0}: PID {1}" -f $MitmPort, $_.OwningProcess)
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

function Ensure-MitmCA {
    # Ensure mitmproxy CA PEM exists and import to CurrentUser\Root
    $certFile = Join-Path $env:USERPROFILE ".mitmproxy\mitmproxy-ca-cert.pem"
    if (-not (Test-Path $certFile)) {
        Log-Write ("MITM CA not found at {0}. Attempting to generate by transient mitmdump start..." -f $certFile)
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
        Log-Write ("No CA pem found at {0}. Please run mitmdump manually to generate." -f $certFile) "ERROR"
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
    
    # Prepare system before starting
    if (-not (Ensure-PortAvailable -Port $Port)) {
        Log-Write "Cannot start mitmdump - port is unavailable" "ERROR"
        return $false
    }
    
    Reset-Proxy-And-Stop-Mitmdump
    Stop-ConflictingProcesses

    $mitmPath = Find-Mitmdump
    if (-not $mitmPath) { Log-Write "mitmdump not found!" "ERROR"; return $false }
    if (-not (Test-Path $PyAddon)) { Log-Write ("Python addon missing: {0}" -f $PyAddon) "ERROR"; return $false }

    $args = @("-p", "$Port", "-s", "$PyAddon")
    Log-Write ("Starting mitmdump visible: {0} {1}" -f $mitmPath, ($args -join ' '))
    try {
        # Start mitmdump directly. Start-Process will handle spaces in the exe path.
        $process = Start-Process -FilePath $mitmPath -ArgumentList $args -WorkingDirectory $WorkDir -WindowStyle Normal -PassThru
        Start-Sleep -Seconds 2
        
        # Verify mitmdump started successfully
        if ($process.HasExited) {
            Log-Write "mitmdump process exited immediately after start" "ERROR"
            return $false
        }
        
        # Wait a bit more for port to become active
        Start-Sleep -Seconds 1
        
    } catch {
        Log-Write ("Failed to start mitmdump visible: {0}" -f $_) "ERROR"
        return $false
    }

    Set-WinInetProxy -proxy ("127.0.0.1:{0}" -f $Port) | Out-Null
    Log-Write "mitmdump started successfully with proxy configured"
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
    Stop-ConflictingProcesses
    Log-Write "Redirects disabled and proxy cleared."
}

function Tail-Log {
    if (-not (Test-Path $LogFile)) { Write-Host "Log not found."; return }
    Get-Content -Path $LogFile -Tail 200 -Wait
}

# ---------------- MAIN ----------------
Ensure-WorkDir
Log-Write "MITM Redirect Manager starting."

# Ensure CA available and installed for CurrentUser
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
    Write-Host "7) Check system preparation"
    Write-Host "8) Exit (stop mitmdump and clear proxy)"
    $opt = Read-Host "Choose option (1-8)"

    switch ($opt) {
        "1" { 
            Reset-Proxy-And-Stop-Mitmdump; 
            Stop-ConflictingProcesses;
            Clear-WinInetProxy | Out-Null; 
            Log-Write "Full reset performed." 
        }
        "2" { Enable-OneShotRedirect }
        "3" { Enable-ForceRedirect }
        "4" { Disable-Redirects }
        "5" { Tail-Log }
        "6" { Start-Mitmdump-Visible }
        "7" { 
            Write-Host "System preparation check..."
            Ensure-PortAvailable | Out-Null
            Stop-ConflictingProcesses
            Log-Write "System preparation completed"
        }
        "8" { 
            Disable-Redirects; 
            Log-Write "Exiting manager."; 
            break 
        }
        default { Write-Host "Invalid choice" }
    }
}
