::&cls&::   Made with ❤️ by Watashi o yūwaku suru
@Echo off
chcp 65001 >nul
cd /d "%~dp0"

:: Если этот батник запущен без прав администратора, то перезапуск этого батника с запросом прав администратора.
reg query "HKU\S-1-5-19\Environment" >nul 2>&1 & cls
if "%Errorlevel%" NEQ "0" PowerShell.exe -WindowStyle Hidden -NoProfile -NoLogo -Command "Start-Process -Verb RunAS -WindowStyle Hidden -FilePath '%0'"&cls&exit

:: Удаление Zone.Identifier у главного скрипта и ярлыка, если есть эта метка.
PowerShell.exe -WindowStyle Hidden -NoProfile -NoLogo -Command "try { Unblock-File -LiteralPath '\\?\%~dp0Files\RemoveApps.ps1','\\?\%~dp0Files\RemoveApps.lnk' -ErrorAction SilentlyContinue } catch {}"

:: Запуск скрипта PS через настроенный Ярлык: параметры запуска PS, цвет и шрифты:
Start Files\RemoveApps.lnk
