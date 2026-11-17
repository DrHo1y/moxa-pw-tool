@echo off
chcp 65001 >nul
cd /d "%~dp0"

where py >nul 2>&1
if %ERRORLEVEL%==0 (
    set PY=py
) else (
    where python >nul 2>&1
    if %ERRORLEVEL%==0 (
        set PY=python
    ) else (
        echo Python не найден.
        echo Установите Python 3 с https://www.python.org/downloads/
        echo и отметьте "Add python.exe to PATH".
        echo.
        pause
        exit /b 1
    )
)

%PY% -c "import Crypto" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Устанавливаю pycryptodome...
    %PY% -m pip install pycryptodome
    if %ERRORLEVEL% NEQ 0 (
        echo Не удалось установить pycryptodome.
        echo Попробуйте вручную:  %PY% -m pip install pycryptodome
        echo.
        pause
        exit /b 1
    )
)

echo.
%PY% moxa_decrypt.py %*
echo.
pause
