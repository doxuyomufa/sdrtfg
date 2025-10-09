param([string]$LogFile = ".\controller.log", [string]$PrevProxyFile = ".\prev_proxy.json")

function Log {
    param([string]$m)
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$t  $m" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

Log "cleanup: start"

# Save previous proxy (if not exists)
try {
    if (-not (Test-Path $PrevProxyFile)) {
        $inet = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $proxyEnable = Get-ItemProperty -Path $inet -Name ProxyEnable -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProxyEnable -ErrorAction SilentlyContinue
        $proxyServer = Get-ItemProperty -Path $inet -Name ProxyServer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProxyServer -ErrorAction SilentlyContinue
        $winhttp = (& netsh winhttp show proxy) -join "`n"
        $prev = @{ Time = (Get-Date).ToString("o"); HKCU = @{ ProxyEnable = $proxyEnable; ProxyServer = $proxyServer }; WinHTTP = $winhttp }
        $prev | ConvertTo-Json | Out-File -FilePath $PrevProxyFile -Encoding utf8
        Log "cleanup: saved prev proxy to $PrevProxyFile"
    } else {
        Log "cleanup: prev_proxy.json exists, not overwriting"
    }
} catch { Log ("cleanup: failed to save prev proxy: {0}" -f $_) }

# Try to stop mitm processes
$names = @("mitmdump","mitmproxy","mitmweb")
foreach ($n in $names) {
    try {
        $ps = Get-Process -Name $n -ErrorAction SilentlyContinue
        if ($ps) {
            foreach ($p in $ps) {
                try { Stop-Process -Id $p.Id -ErrorAction Stop; Log ("cleanup: stopped {0} (PID {1})" -f $n, $p.Id) } catch { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Log ("cleanup: force stopped {0} (PID {1})" -f $n, $p.Id) } catch { Log ("cleanup: failed to stop {0} (PID {1}): {2}" -f $n, $p.Id, $_) } }
            }
        } else { Log ("cleanup: {0} not running" -f $n) }
    } catch { Log ("cleanup: error checking {0}: {1}" -f $n, $_) }
}

# Reset winhttp proxy (do not touch HKCU saved above)
try { & netsh winhttp reset proxy | Out-Null; Log "cleanup: winhttp proxy reset" } catch { Log ("cleanup: netsh reset failed: {0}" -f $_) }

Log "cleanup: end"
