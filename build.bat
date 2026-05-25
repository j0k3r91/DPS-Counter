@echo off
:: build.bat — Compile DPS Counter en x86 Release
:: Nécessite : Visual Studio (MSVC), CMake, DirectX SDK June 2010

setlocal enabledelayedexpansion

echo ========================================
echo  DPS Counter -- Build x86 Release
echo ========================================

:: ---- Vérifier DXSDK_DIR -----------------------------------------------
if "%DXSDK_DIR%"=="" (
    echo [ERREUR] La variable d'environnement DXSDK_DIR n'est pas définie.
    echo          Installez le DirectX SDK ^(June 2010^) et relancez.
    pause & exit /b 1
)
echo [OK] DXSDK_DIR = %DXSDK_DIR%

:: ---- Vérifier CMake ---------------------------------------------------
where cmake >nul 2>nul
if errorlevel 1 (
    echo [ERREUR] cmake introuvable dans le PATH.
    pause & exit /b 1
)

:: ---- Initialiser l'environnement MSVC x86 si nécessaire ---------------
if "%VCINSTALLDIR%"=="" (
    echo Recherche de vcvars32.bat ...
    :: essayer VS 2022, 2019, 2017
    for %%V in (
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat"
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars32.bat"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
        "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars32.bat"
    ) do (
        if exist %%V (
            echo Chargement: %%V
            call %%V
            goto :vcfound
        )
    )
    echo [ERREUR] vcvars32.bat introuvable. Installez Visual Studio.
    pause & exit /b 1
    :vcfound
)

:: ---- Dossier de build -------------------------------------------------
set BUILD_DIR=%~dp0build_x86

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

:: ---- CMake configure --------------------------------------------------
echo.
echo [1/2] Configuration CMake...
cmake .. -G "NMake Makefiles" -A "" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_GENERATOR_PLATFORM="" ^
    -DDXSDK_DIR="%DXSDK_DIR%"
if errorlevel 1 (
    echo [ERREUR] cmake configure a échoué.
    cd /d "%~dp0"
    pause & exit /b 1
)

:: ---- CMake build -------------------------------------------------------
echo.
echo [2/2] Compilation...
cmake --build . --config Release
if errorlevel 1 (
    echo [ERREUR] La compilation a échoué.
    cd /d "%~dp0"
    pause & exit /b 1
)

cd /d "%~dp0"

echo.
echo ========================================
echo  Build terminé avec succès !
echo  Binaires dans : %BUILD_DIR%\
echo    - dpscounter.dll
echo    - DPSCounter.exe
echo ========================================
pause
