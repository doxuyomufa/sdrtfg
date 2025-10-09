param([string]$LogFile = ".\controller.log", [string]$CAPath = "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.pem")

function Log {
    param([string]$m)
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$t  $m" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

Log "cert_check_install: start"
if (-not (Test-Path $CAPath)) {
    Log ("cert_check_install: CA file not found at {0}" -f $CAPath)
    Write-Host "CA file not found at $CAPath. Run mitmproxy once or place CA file there."
    exit 0
}

try {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
    $store.Open("ReadOnly")
    $found = $store.Certificates | Where-Object { $_.Subject -match "mitmproxy" -or $_.Issuer -match "mitmproxy" }
    $store.Close()

    if ($found -and $found.Count -gt 0) {
        Log "cert_check_install: mitmproxy CA already in LocalMachine\\Root"
        Write-Host "mitmproxy CA already installed in LocalMachine\\Root"
    } else {
        Log "cert_check_install: importing CA to LocalMachine\\Root from $CAPath"
        $out = & certutil -addstore -f Root $CAPath 2>&1
        Log ("cert_check_install: certutil output: {0}" -f ($out -join "`n"))
        Write-Host "mitmproxy CA imported to LocalMachine\\Root"
    }
} catch {
    Log ("cert_check_install: error: {0}" -f $_)
    Write-Host "cert_check_install error: $_"
}
Log "cert_check_install: end"
