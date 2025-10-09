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

# ---------------- ENVIRONMENT ----------------
# Добавляем Python 3.12 в PATH
$pythonPath = "$env:LocalAppData\Programs\Python312;$env:LocalAppData\Programs\Python312\Scripts"
$env:PATH = "$pythonPath;$env:PATH"
# ----------------------------------------------

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

# ---------------- FREE PORT FUNCTION ----------------
function Free-Port {
    param([int]$Port)
    try {
        $used = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        if ($used) {
            Log-Write ("Port {0} is busy, attempting to free..." -f $Port)
            foreach ($conn in $used) {
                try {
                    $pid = $conn.OwningProcess
                    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    if ($proc) {
                        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                        Log-Write ("Killed process {0} (PID {1}) using port {2}" -f $proc.ProcessName, $pid, $Port)
                    }
                } catch {}
            }
            Start-Sleep -Seconds 1
        }
    } catch {
        Log-Write ("Failed to free port {0}: {1}" -f $Port, $_) "WARN"
    }
}
# -----------------------------------------------------

function Reset-Proxy-And-Stop-Mitmdump {
    Log-Write "Stopping mitmdump processes..."
    Get-Process -Name mitmdump,mitmproxy,mitmweb,python* -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Log-Write ("Killed {0} PID: {1}" -f $_.ProcessName, $_.Id)
        } catch {
            Log-Write ("Failed to kill PID {0}: {1}" -f $_.Id, $_) "WARN"
        }
    }

    try { netsh winhttp reset proxy | Out-Null; Log-Write "WinHTTP proxy reset." } catch { Log-Write ("Failed winhttp reset: {0}" -f $_) "WARN" }

    try { 
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Force
        Log-Write "Proxy disabled in registry."
    } catch { Log-Write ("Failed to disable proxy in registry: {0}" -f $_) "WARN" }

    try { ipconfig /flushdns | Out-Null; Log-Write "DNS cache flushed." } catch { Log-Write ("Failed to flush DNS: {0}" -f $_) "WARN" }
}

# Остальные функции (Safe-Exit, Ensure-MitmCA, Set-SystemProxies, Clear-SystemProxies, Close-Browsers-Gracefully)
# остаются без изменений, как в твоем исходном скрипте.

function Start-Mitmdump {
    Ensure-WorkDir
    Reset-Proxy-And-Stop-Mitmdump
    Free-Port -Port $MitmPort  # <-- новая проверка и освобождение порта

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

# REDIRECT FUNCTIONS и MAIN MENU остаются без изменений
