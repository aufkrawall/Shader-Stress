@echo off
setlocal

:: ==============================================================================
:: Global Setup & Visual Studio Detection
:: ==============================================================================
echo Finding Visual Studio...

set "vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "vs_path="

:: 1. Try vswhere (Best method)
if exist "%vswhere%" (
    for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "vs_path=%%i"
    )
)

:: 2. Fallback: Check Standard Paths (Explicitly quoted to prevent syntax errors)
if not defined vs_path (
    for %%P in (
        "%ProgramFiles%\Microsoft Visual Studio\2022\Community"
        "%ProgramFiles%\Microsoft Visual Studio\2022\Professional"
        "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise"
        "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community"
        "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional"
        "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise"
        "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community"
    ) do (
        if exist "%%~P\VC\Auxiliary\Build\vcvars64.bat" (
            set "vs_path=%%~P"
            goto :FoundVS
        )
    )
)

:FoundVS
if not defined vs_path (
    echo.
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo ERROR: Could not locate Visual Studio installation.
    echo Please run this script from a 'x64 Native Tools Command Prompt'.
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    pause
    exit /b 1
)

echo Found Visual Studio at: "%vs_path%"
echo.

:: ==============================================================================
:: Execution
:: ==============================================================================

:: 1. Build Standard Windows (x64)
call :BuildX64
if %errorlevel% neq 0 goto :Fail

:: 2. Build Windows ARM64
call :BuildARM64
if %errorlevel% neq 0 goto :Fail

echo.
echo ============================
echo    ALL BUILDS COMPLETE
echo ============================
pause
exit /b 0

:Fail
echo.
echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!
echo    BUILD SEQUENCE FAILED
echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!
pause
exit /b 1


:: ==============================================================================
:: Subroutine: Build x64 (Intel/AMD)
:: ==============================================================================
:BuildX64
setlocal
echo ----------------------------------------
echo Building Target: Windows x64
echo ----------------------------------------

:: Create Output Directory
if not exist "shaderstress_windows_x86" mkdir "shaderstress_windows_x86"

:: Setup Environment (x64 Native)
call "%vs_path%\VC\Auxiliary\Build\vcvars64.bat" >nul
if %errorlevel% neq 0 (
    echo Failed to load vcvars64.bat
    exit /b 1
)

:: Compile Resources
rc /nologo resource.rc

:: Compile Exe
cl /nologo /std:c++20 /O2 /EHsc /DUNICODE /D_UNICODE ShaderStress.cpp ^
    /Fe"shaderstress_windows_x86\ShaderStress.exe" ^
    /link /SUBSYSTEM:WINDOWS resource.res user32.lib gdi32.lib ole32.lib dwmapi.lib urlmon.lib wintrust.lib crypt32.lib shcore.lib shell32.lib

if %errorlevel% neq 0 (
    echo Build x64 FAILED
    endlocal
    exit /b 1
)

:: Clean up intermediates (Keep only .exe)
del *.obj *.res >nul 2>&1

echo Success: shaderstress_windows_x86\ShaderStress.exe
echo.
endlocal
exit /b 0


:: ==============================================================================
:: Subroutine: Build ARM64
:: ==============================================================================
:BuildARM64
setlocal
echo ----------------------------------------
echo Building Target: Windows ARM64
echo ----------------------------------------

:: Create Output Directory
if not exist "shaderstress_windows_arm64" mkdir "shaderstress_windows_arm64"

:: Setup Environment (Cross Compile x64_arm64)
if exist "%vs_path%\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" (
    call "%vs_path%\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" >nul
) else (
    echo.
    echo ERROR: 'vcvarsamd64_arm64.bat' not found.
    echo You must install "MSVC ... ARM64 build tools" via VS Installer.
    exit /b 1
)

:: Compile Resources (Must re-compile resource for clean state)
rc /nologo resource.rc

:: Compile Exe (ARM64 Specific Flags)
cl /nologo /std:c++20 /O2 /Ot /EHsc /DUNICODE /D_UNICODE ShaderStress.cpp ^
    /Fe"shaderstress_windows_arm64\ShaderStress.exe" ^
    /link /SUBSYSTEM:WINDOWS /MACHINE:ARM64 resource.res user32.lib gdi32.lib ole32.lib dwmapi.lib urlmon.lib wintrust.lib crypt32.lib shcore.lib shell32.lib

if %errorlevel% neq 0 (
    echo Build ARM64 FAILED
    endlocal
    exit /b 1
)

:: Clean up intermediates (Keep only .exe)
del *.obj *.res >nul 2>&1

echo Success: shaderstress_windows_arm64\ShaderStress.exe
echo.
endlocal
exit /b 0
