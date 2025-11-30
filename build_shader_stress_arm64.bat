@echo off
setlocal

echo Searching for Visual Studio ARM64 Build Tools...

:: --- Visual Studio Detection (Prioritize ARM64 Cross Tools) ---
set "vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%vswhere%" (
    :: Look for the ARM64 build component explicitly
    for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.ARM64 -property installationPath`) do (
        set "vs_path=%%i"
    )
)

:: Try to find the x64_arm64 cross-compiler (Host: x64, Target: ARM64)
if defined vs_path (
    if exist "%vs_path%\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" (
        echo Found Visual Studio at: %vs_path%
        echo Setting up Environment: vcvarsamd64_arm64.bat
        call "%vs_path%\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"
        goto :build
    )
)

:: Fallback: Check standard paths
:: We use explicit quoted strings here to prevent "C:\Program" whitespace errors
for %%P in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_arm64.bat"
) do (
    if exist %%P (
        echo Found VS environment at: %%P
        call %%P >nul
        goto :build
    )
)

echo.
echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
echo ERROR: Could not locate 'vcvarsamd64_arm64.bat'
echo You must install the "MSVC ... ARM64 build tools" via VS Installer.
echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
pause
exit /b 1

:build
echo.
echo ----------------------------------------
echo Compiling Resources...
echo ----------------------------------------
rc /nologo resource.rc

echo.
echo ----------------------------------------
echo Compiling ShaderStress.cpp (ARM64 Target)...
echo ----------------------------------------

:: Compiler Flags:
:: /O2      : Maximize Speed
:: /Ot      : Favor Fast Code
:: /EHsc    : Standard C++ Exception Handling
:: /D_ARM64_WIN_ : Explicitly define if not set (optional, usually automatic)
:: Linker:
:: /MACHINE:ARM64 : Crucial for targeting ARM64

cl /nologo /std:c++20 /O2 /Ot /EHsc /DUNICODE /D_UNICODE ShaderStress.cpp ^
    /link /SUBSYSTEM:WINDOWS /MACHINE:ARM64 /OUT:ShaderStress.exe resource.res user32.lib gdi32.lib ole32.lib dwmapi.lib urlmon.lib wintrust.lib crypt32.lib shcore.lib shell32.lib

if %errorlevel% neq 0 (
    echo.
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo       BUILD FAILED
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!
) else (
    echo.
    echo ============================
    echo       BUILD SUCCESS
    echo    Target: Windows ARM64
    echo ============================
)

echo.
pause
endlocal