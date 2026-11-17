@echo off
cd /d "%~dp0"
where py >nul 2>&1 && (py moxa_ics_password.py %*) & goto :eof
where python >nul 2>&1 && (python moxa_ics_password.py %*) & goto :eof
echo Python 3 не найден. Установите его с https://www.python.org/downloads/
echo и отметьте "Add Python to PATH".
pause
