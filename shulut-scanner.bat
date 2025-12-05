@echo off
REM ============================================================================
REM SHULUT 2.0 DETECTION & REMEDIATION TOOL - Windows
REM Professional Scanner para Windows (10, 11, Server 2019+)
REM ============================================================================

setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
cls

REM Color codes (using PowerShell for colors)
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "CYAN=[96m"
set "NC=[0m"

set "SCRIPT_DIR=%~dp0"
set "TIMESTAMP=%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "SCAN_REPORT=%TEMP%\shulut_scan_%TIMESTAMP%.log"
set "INFECTED_REPORT=%TEMP%\shulut_infected_%TIMESTAMP%.txt"
set "REMEDIATION_LOG=%TEMP%\shulut_remediation_%TIMESTAMP%.log"

REM ============================================================================
REM UTILITY FUNCTIONS
REM ============================================================================

:print_header
    cls
    echo.
    echo ============================================================================
    echo %~1
    echo ============================================================================
    echo.
    exit /b 0

:print_success
    echo [OK] %~1
    exit /b 0

:print_error
    echo [ERROR] %~1
    exit /b 1

:print_warning
    echo [WARNING] %~1
    exit /b 0

:print_info
    echo [INFO] %~1
    exit /b 0

:log_message
    for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set "mydate=%%c-%%a-%%b")
    for /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set "mytime=%%a:%%b")
    echo [!mydate! !mytime!] %~1 >> "%SCAN_REPORT%"
    exit /b 0

REM ============================================================================
REM REQUIREMENTS CHECK
REM ============================================================================

:check_requirements
    echo.
    echo Verificando Requisitos...
    echo.
    
    REM Verificar Node.js
    where node >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Node.js no está instalado
        echo Descargue desde: https://nodejs.org
        exit /b 1
    ) else (
        for /f "tokens=*" %%a in ('node --version') do (
            echo [OK] Node.js %%a encontrado
        )
    )
    
    REM Verificar npm
    where npm >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] npm no está instalado
        exit /b 1
    ) else (
        for /f "tokens=*" %%a in ('npm --version') do (
            echo [OK] npm %%a encontrado
        )
    )
    
    REM Verificar PowerShell
    where powershell >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] PowerShell no encontrado (algunas funciones limitadas)
    ) else (
        echo [OK] PowerShell encontrado
    )
    
    exit /b 0

REM ============================================================================
REM DETECTION FUNCTIONS
REM ============================================================================

:find_npm_projects
    setlocal enabledelayedexpansion
    set "search_path=%~1"
    if "!search_path!"=="" set "search_path=."
    
    echo.
    echo Buscando proyectos npm en: !search_path!
    echo.
    
    setlocal enabledelayedexpansion
    for /r "!search_path!" %%f in (package.json) do (
        echo %%~dpf
    )
    endlocal
    exit /b 0

:scan_package_json
    setlocal enabledelayedexpansion
    set "pkg_file=%~1"
    set "project_dir=%~dp1"
    
    if not exist "!pkg_file!" exit /b 0
    
    REM Buscar indicadores de malware en package.json
    findstr /i "setupban van-environment" "!pkg_file!" >nul 2>&1
    if not errorlevel 1 (
        echo Malware dependency detected: !project_dir!
        echo !project_dir! >> "%INFECTED_REPORT%"
        endlocal
        exit /b 1
    )
    
    REM Verificar scripts preinstall sospechosos
    findstr /i "preinstall" "!pkg_file!" >nul 2>&1
    if not errorlevel 1 (
        (for /f "delims=" %%a in ('findstr /i "preinstall" "!pkg_file!"') do (
            echo %%a | findstr /i "setupban ban-" >nul
            if not errorlevel 1 (
                echo Suspicious preinstall script: !project_dir!
                echo !project_dir! >> "%INFECTED_REPORT%"
                endlocal
                exit /b 1
            )
        ))
    )
    
    endlocal
    exit /b 0

:scan_node_modules
    setlocal enabledelayedexpansion
    set "project_dir=%~1"
    set "node_modules=!project_dir!\node_modules"
    
    if not exist "!node_modules!" (
        endlocal
        exit /b 0
    )
    
    echo [INFO] Escaneando node_modules: !project_dir!
    
    REM Buscar archivos IOC conocidos
    if exist "!node_modules!\van-environment.js" (
        echo Malware file found: van-environment.js
        endlocal
        exit /b 1
    )
    
    if exist "!node_modules!\setupban.js" (
        echo Malware file found: setupban.js
        endlocal
        exit /b 1
    )
    
    REM Buscar paquetes maliciosos
    if exist "!node_modules!\shulut" (
        echo Malicious package found: shulut
        endlocal
        exit /b 1
    )
    
    if exist "!node_modules!\van-environment" (
        echo Malicious package found: van-environment
        endlocal
        exit /b 1
    )
    
    endlocal
    exit /b 0

:scan_credentials_exposure
    setlocal enabledelayedexpansion
    set "project_dir=%~1"
    
    REM Verificar archivos sensibles
    if exist "!project_dir!\.env" (
        findstr /i "API_KEY SECRET TOKEN PASSWORD" "!project_dir!\.env" >nul 2>&1
        if not errorlevel 1 (
            echo Exposed credentials detected: .env
            endlocal
            exit /b 1
        )
    )
    
    if exist "!project_dir!\.npmrc" (
        echo Sensitive file found: .npmrc
        endlocal
        exit /b 1
    )
    
    endlocal
    exit /b 0

REM ============================================================================
REM REMEDIATION FUNCTIONS
REM ============================================================================

:remediate_project
    setlocal enabledelayedexpansion
    set "project_dir=%~1"
    
    echo.
    echo ============================================================================
    echo Remediando: !project_dir!
    echo ============================================================================
    echo.
    
    echo [INFO] Creando backup...
    for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set "date_stamp=%%c-%%a-%%b")
    for /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set "time_stamp=%%a-%%b")
    set "backup_dir=!project_dir!\.backup_!date_stamp!_!time_stamp!"
    
    if not exist "!backup_dir!" mkdir "!backup_dir!"
    copy "!project_dir!\package.json" "!backup_dir!\" >nul 2>&1
    copy "!project_dir!\package-lock.json" "!backup_dir!\" >nul 2>&1
    
    echo [INFO] Eliminando archivos maliciosos...
    del /s /q "!project_dir!\van-environment.js" >nul 2>&1
    del /s /q "!project_dir!\setupban.js" >nul 2>&1
    
    echo [INFO] Eliminando node_modules...
    if exist "!project_dir!\node_modules" (
        rmdir /s /q "!project_dir!\node_modules" >nul 2>&1
    )
    
    echo [INFO] Limpiando npm cache...
    call npm cache clean --force >nul 2>&1
    
    echo [INFO] Eliminando paquetes maliciosos...
    cd /d "!project_dir!" || exit /b 1
    
    for %%p in (shulut shai-hulut van-environment setupban node-setupban ban) do (
        call npm uninstall --save %%p >nul 2>&1
    )
    
    echo [INFO] Reinstalando dependencias...
    call npm install
    
    echo [OK] Remediación completada
    endlocal
    exit /b 0

REM ============================================================================
REM FULL SCAN WORKFLOW
REM ============================================================================

:perform_full_scan
    setlocal enabledelayedexpansion
    set "search_path=%~1"
    if "!search_path!"=="" set "search_path=."
    
    echo.
    echo ============================================================================
    echo ESCANEO COMPLETO DE PROYECTOS
    echo ============================================================================
    echo.
    echo Ruta de búsqueda: !search_path!
    echo Reporte: "%SCAN_REPORT%"
    echo.
    
    set /a scanned_count=0
    set /a infected_count=0
    
    REM Buscar todos los package.json
    for /r "!search_path!" %%f in (package.json) do (
        set /a scanned_count+=1
        set "pkg_file=%%f"
        set "project_dir=%%~dpf"
        
        cls
        echo [!scanned_count!] Escaneando: !project_dir!
        
        call :scan_package_json "!pkg_file!"
        if errorlevel 1 (
            set /a infected_count+=1
            echo [INFECTADO] !project_dir!
            call :log_message "INFECTED: !project_dir!"
        ) else (
            call :scan_node_modules "!project_dir!"
            if errorlevel 1 (
                set /a infected_count+=1
                echo [INFECTADO] !project_dir!
                call :log_message "INFECTED: !project_dir!"
            ) else (
                echo [LIMPIO] !project_dir!
                call :log_message "CLEAN: !project_dir!"
            )
        )
    )
    
    echo.
    echo ============================================================================
    echo RESUMEN DEL ESCANEO
    echo ============================================================================
    echo Proyectos escaneados: !scanned_count!
    echo Proyectos infectados: !infected_count!
    echo Proyectos limpios: !scanned_count - infected_count!
    echo.
    
    endlocal
    exit /b 0

REM ============================================================================
REM MAIN MENU
REM ============================================================================

:show_menu
    echo.
    echo ============================================================================
    echo         SHULUT 2.0 SCANNER ^& REMEDIATOR - Windows
    echo ============================================================================
    echo.
    echo 1 - Escanear proyectos en directorio actual
    echo 2 - Escanear directorio específico
    echo 3 - Remediar proyecto infectado
    echo 4 - Escaneo completo + Remediación automática
    echo 5 - Ver reportes anteriores
    echo 6 - Limpiar archivos temporales
    echo 0 - Salir
    echo.
    set /p choice="Seleccione opción: "
    exit /b 0

:main
    call :check_requirements
    if errorlevel 1 exit /b 1
    
    :menu_loop
    call :show_menu
    
    if "!choice!"=="1" (
        call :perform_full_scan .
        pause
        goto menu_loop
    )
    
    if "!choice!"=="2" (
        set /p search_dir="Ingrese ruta de directorio: "
        if exist "!search_dir!" (
            call :perform_full_scan "!search_dir!"
        ) else (
            echo Directorio no existe: !search_dir!
        )
        pause
        goto menu_loop
    )
    
    if "!choice!"=="3" (
        set /p project_dir="Ingrese ruta del proyecto: "
        if exist "!project_dir!" (
            call :remediate_project "!project_dir!"
        ) else (
            echo Directorio no existe: !project_dir!
        )
        pause
        goto menu_loop
    )
    
    if "!choice!"=="4" (
        set /p search_dir="Ingrese ruta de directorio: "
        if exist "!search_dir!" (
            call :perform_full_scan "!search_dir!"
            REM TODO: Auto-remediate infected projects
        )
        pause
        goto menu_loop
    )
    
    if "!choice!"=="5" (
        echo Reportes disponibles:
        dir "%TEMP%\shulut_*" /b 2>nul || echo No hay reportes previos
        pause
        goto menu_loop
    )
    
    if "!choice!"=="6" (
        del /q "%TEMP%\shulut_*" 2>nul
        echo Archivos temporales eliminados
        pause
        goto menu_loop
    )
    
    if "!choice!"=="0" (
        exit /b 0
    )
    
    echo Opción inválida
    pause
    goto menu_loop

REM ============================================================================
REM EXECUTION
REM ============================================================================

call :main %*
endlocal
