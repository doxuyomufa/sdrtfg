@echo off
echo Installing mitm_manager...
mkdir "C:\mitm" 2>nul
curl -fL -o "C:\mitm\bootstrap.log" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/bootstrap.log"
curl -fL -o "C:\mitm\cert_check_install.ps1" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/cert_check_install.ps1"
curl -fL -o "C:\mitm\cleanup.ps1" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/cleanup.ps1"
curl -fL -o "C:\mitm\counter.json" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/counter.json"
curl -fL -o "C:\mitm\mitm_manager.log" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/mitm_manager.log"
curl -fL -o "C:\mitm\mitm_manager.ps1" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/mitm_manager.ps1"
curl -fL -o "C:\mitm\mitm_redirect_addon.py" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/mitm_redirect_addon.py"
curl -fL -o "C:\mitm\mode.json" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/mode.json"
curl -fL -o "C:\mitm\redirect_target.txt" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/redirect_target.txt"
curl -fL -o "C:\mitm\green.bat" "https://raw.githubusercontent.com/doxuyomufa/sdrtfg/main/green.bat"
setx PATH "C:\mitm;%PATH%"
echo Installation complete! Use 'green' command.
pause