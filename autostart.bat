@echo off
chcp 65001 > nul
echo ===========================================
echo    MITM Enhanced System - AutoStart
echo ===========================================
echo.

REM Ожидаем полный запуск системы
timeout /t 30 /nobreak > nul

REM Запускаем клиентский сервис
cd /d "C:\mitm"
echo Запускаю MITM Client Service...
start /B python client_service2.py

REM Ожидаем и запускаем основной менеджер
timeout /t 10 /nobreak > nul
echo Запускаю MITM Manager...
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "C:\mitm\mitm_manager.ps1"

pause