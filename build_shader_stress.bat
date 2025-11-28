@echo off
setlocal

:: --- Visual Studio Detection ---
set "vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%vswhere%" (
    for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "vs_path=%%i"
    )
)

if defined vs_path (
    if exist "%vs_path%\VC\Auxiliary\Build\vcvars64.bat" (
        echo Found Visual Studio at: %vs_path%
        call "%vs_path%\VC\Auxiliary\Build\vcvars64.bat"
        goto :build
    )
)

:: Method 2: Check Standard Paths (Fallback)
set "search_paths=^
 %ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat;^
 %ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat;^
 %ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat;^
 %ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat;^
 %ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat;^
 %ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat;^
 %ProgramFiles%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat;^
 %ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

if not defined VCINSTALLDIR (
    for %%P in (%search_paths%) do (
        if exist "%%P" (
            echo Found VS environment at: %%P
            call "%%P" >nul
            goto :build
        )
    )
    echo Could not locate vcvars64.bat automatically. 
    echo Please run this script from a 'x64 Native Tools Command Prompt'.
    pause
    exit /b 1
)

:build
echo.
echo ----------------------------------------
echo Compiling Resources...
echo ----------------------------------------
rc /nologo resource.rc

echo.
echo ----------------------------------------
echo Compiling ShaderStress.cpp...
echo ----------------------------------------

:: Link shell32.lib and resource.res
cl /nologo /std:c++20 /O2 /EHsc /DUNICODE /D_UNICODE ShaderStress.cpp ^
    /link /SUBSYSTEM:WINDOWS /OUT:ShaderStress.exe resource.res user32.lib gdi32.lib ole32.lib dwmapi.lib urlmon.lib wintrust.lib crypt32.lib shcore.lib shell32.lib

if %errorlevel% neq 0 (
    echo.
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo       BUILD FAILED
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!
) else (
    echo.
    echo ============================
    echo       BUILD SUCCESS
    echo ============================
)

echo.
pause
endlocal