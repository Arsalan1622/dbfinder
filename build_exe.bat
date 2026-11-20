@echo off
REM Build DBFinder.exe (Windows) — double-click this file.
REM Needs Python 3.10+ installed. Uses the "py" launcher because plain
REM "python" may hit the Microsoft Store stub instead of real Python.
REM
REM Builds TWO exes:
REM   dist\DBFinder-console.exe — console test build (errors stay visible)
REM   dist\DBFinder.exe         — windowed release build (no console)
REM Test the console build first. Ship the windowed build once the
REM primary action (Scan Now) passes on the target machine.
setlocal
cd /d "%~dp0"
echo Installing PyInstaller (one time)...
py -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo ERROR: pip failed. Is Python installed from python.org?
    pause
    exit /b 1
)
echo.
echo Building console TEST exe (DBFinder-console.exe)...
py -m PyInstaller --onefile --console --clean ^
    --name DBFinder-console ^
    dbfinder.py
if errorlevel 1 (
    echo ERROR: console build failed.
    pause
    exit /b 1
)
echo.
echo Building windowed RELEASE exe (DBFinder.exe)...
py -m PyInstaller --onefile --windowed --clean ^
    --name DBFinder ^
    dbfinder.py
if errorlevel 1 (
    echo ERROR: windowed build failed.
    pause
    exit /b 1
)
echo.
echo Done! Your apps are here:
echo   dist\DBFinder-console.exe  (test build — run this first)
echo   dist\DBFinder.exe          (release build — no console window)
echo Copy either anywhere and double-click it — no Python needed to run it.
pause
