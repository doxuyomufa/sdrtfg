# create_autostart_task.ps1
# Запустите этот скрипт ОДИН РАЗ для создания задания в планировщике Windows

$taskName = "MITM Proxy Autostart"
$scriptPath = "C:\mitm\mitm_manager.ps1"
$workDir = "C:\mitm"

# Проверяем существование скрипта
if (-not (Test-Path $scriptPath)) {
    Write-Host "❌ Script not found: $scriptPath" -ForegroundColor Red
    Write-Host "Please make sure mitm_manager.ps1 is in C:\mitm\" -ForegroundColor Yellow
    exit 1
}

# Создаем задание в планировщике
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" -WorkingDirectory $workDir

$trigger = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
    Write-Host "✅ Scheduled task created successfully!" -ForegroundColor Green
    Write-Host "Task Name: $taskName" -ForegroundColor Cyan
    Write-Host "Script: $scriptPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📌 IMPORTANT:" -ForegroundColor Yellow
    Write-Host "   This task will start mitm_manager.ps1 at Windows startup" -ForegroundColor Yellow
    Write-Host "   The script will automatically restore your last active function" -ForegroundColor Yellow
    Write-Host "   To remove the task, run: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor Gray
} catch {
    Write-Host "❌ Failed to create scheduled task: $_" -ForegroundColor Red
}