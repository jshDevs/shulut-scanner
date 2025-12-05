#!/bin/bash

################################################################################
# SHULUT 2.0 DETECTION & REMEDIATION TOOL
# Professional Scanner para Linux (Rocky, CentOS, Ubuntu, Debian)
# Detecta y limpia infecciones por malware Shulut 2.0
################################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Log files
SCAN_REPORT="/tmp/shulut_scan_$(date +%s).log"
INFECTED_REPORT="/tmp/shulut_infected_$(date +%s).txt"
REMEDIATION_LOG="/tmp/shulut_remediation_$(date +%s).log"

################################################################################
# UTILITY FUNCTIONS
################################################################################

print_header() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}============================================${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$SCAN_REPORT"
}

################################################################################
# DETECTION FUNCTIONS
################################################################################

check_requirements() {
    print_header "Verificando Requisitos"
    
    local required_tools=("grep" "find" "sed" "jq" "npm" "node")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        else
            print_success "$tool encontrado"
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_warning "Herramientas faltantes: ${missing_tools[*]}"
        print_info "Instale con: sudo apt-get install -y ${missing_tools[*]}"
        return 1
    fi
    
    return 0
}

get_npm_projects() {
    local search_path="${1:-.}"
    local max_depth="${2:-5}"
    
    print_info "Buscando proyectos npm en: $search_path"
    find "$search_path" -maxdepth "$max_depth" -name "package.json" -type f 2>/dev/null | while read -r pkg_file; do
        echo "$(dirname "$pkg_file")"
    done
}

scan_package_json() {
    local pkg_file="$1"
    local project_dir="$(dirname "$pkg_file")"
    local findings=()
    
    # Indicador 1: Verificar scripts preinstall sospechosos
    if grep -q "preinstall" "$pkg_file" 2>/dev/null; then
        local preinstall_cmd=$(grep "preinstall" "$pkg_file" | head -1)
        
        if echo "$preinstall_cmd" | grep -qE "(setupban|van-environment|node-|exec|curl|wget)"; then
            findings+=("PREINSTALL_SUSPICIOUS: $preinstall_cmd")
        fi
    fi
    
    # Indicador 2: Dependencias van-environment o setupban
    if grep -qE '"van-environment"|"setupban"|"ban"' "$pkg_file" 2>/dev/null; then
        findings+=("MALWARE_DEPENDENCY_DETECTED")
    fi
    
    # Indicador 3: Versiones modificadas recientemente
    local mod_time=$(stat -f%m "$pkg_file" 2>/dev/null || stat -c%Y "$pkg_file" 2>/dev/null)
    local current_time=$(date +%s)
    local days_modified=$(( (current_time - mod_time) / 86400 ))
    
    if [ "$days_modified" -lt 7 ]; then
        findings+=("RECENT_MODIFICATION: ${days_modified} días")
    fi
    
    # Indicador 4: Caracteres sospechosos en scripts
    if grep -q $'\\x00' "$pkg_file" 2>/dev/null; then
        findings+=("BINARY_CONTENT_DETECTED")
    fi
    
    if [ ${#findings[@]} -gt 0 ]; then
        echo "$project_dir"
        for finding in "${findings[@]}"; do
            echo "  → $finding"
        done
        echo "${findings[@]}" >> "$INFECTED_REPORT"
        return 1
    fi
    
    return 0
}

scan_node_modules() {
    local project_dir="$1"
    local node_modules="$project_dir/node_modules"
    local findings=()
    
    if [ ! -d "$node_modules" ]; then
        return 0
    fi
    
    print_info "Escaneando node_modules: $project_dir"
    
    # Buscar archivos IOC conocidos
    if find "$node_modules" -name "van-environment.js" -o -name "setupban.js" 2>/dev/null | grep -q .; then
        findings+=("MALWARE_FILES_FOUND")
    fi
    
    # Buscar paquetes maliciosos conocidos
    local malicious_packages=(
        "shulut"
        "shai-hulut"
        "van-environment"
        "setupban"
        "node-setupban"
    )
    
    for pkg in "${malicious_packages[@]}"; do
        if [ -d "$node_modules/$pkg" ]; then
            findings+=("MALICIOUS_PACKAGE: $pkg")
        fi
    done
    
    # Buscar scripts ejecutables sospechosos
    local suspicious_scripts=$(find "$node_modules/.bin" -type f -exec grep -l "eval\|exec\|child_process.*exec" {} \; 2>/dev/null | wc -l)
    
    if [ "$suspicious_scripts" -gt 0 ]; then
        findings+=("SUSPICIOUS_SCRIPTS: $suspicious_scripts scripts")
    fi
    
    if [ ${#findings[@]} -gt 0 ]; then
        echo "$project_dir"
        for finding in "${findings[@]}"; do
            echo "  → $finding"
        done
        return 1
    fi
    
    return 0
}

scan_github_credentials() {
    local project_dir="$1"
    local findings=()
    
    # Verificar archivos sensibles expuestos
    local sensitive_files=(
        ".env"
        ".env.local"
        ".git/config"
        "~/.ssh/config"
        "~/.aws/credentials"
        ".npmrc"
    )
    
    for file in "${sensitive_files[@]}"; do
        local expanded_file=$(eval echo "$file")
        if [ -f "$project_dir/$expanded_file" ]; then
            # Verificar si contiene credenciales
            if grep -qE "API_KEY|SECRET|TOKEN|PASSWORD" "$project_dir/$expanded_file" 2>/dev/null; then
                findings+=("EXPOSED_CREDENTIALS: $file")
            fi
        fi
    done
    
    if [ ${#findings[@]} -gt 0 ]; then
        return 1
    fi
    
    return 0
}

scan_git_history() {
    local project_dir="$1"
    
    if [ ! -d "$project_dir/.git" ]; then
        return 0
    fi
    
    print_info "Verificando historial Git: $project_dir"
    
    # Buscar commits sospechosos recientes
    cd "$project_dir" || return 1
    
    local recent_commits=$(git log --since="7 days ago" --oneline 2>/dev/null | grep -c "." || true)
    
    if [ "$recent_commits" -gt 10 ]; then
        print_warning "Múltiples commits recientes detectados: $recent_commits"
    fi
    
    cd - > /dev/null || return 1
    return 0
}

scan_environment_variables() {
    print_info "Verificando variables de entorno"
    
    local suspicious_vars=$(env | grep -E "NODE_|NPM_|BAN_|SETUP" | grep -v "PATH\|HOME\|USER\|SHELL" || true)
    
    if [ -n "$suspicious_vars" ]; then
        echo "$suspicious_vars" | while read -r var; do
            print_warning "Variable sospechosa: $var"
        done
        return 1
    fi
    
    return 0
}

scan_package_lock() {
    local pkg_lock="$1"
    local findings=()
    
    if [ ! -f "$pkg_lock" ]; then
        return 0
    fi
    
    print_info "Verificando package-lock.json"
    
    # Buscar referencias a paquetes maliciosos
    if grep -qE '"shulut"|"shai-hulut"|"van-environment"|"setupban"' "$pkg_lock"; then
        findings+=("MALICIOUS_PACKAGE_REF")
    fi
    
    # Verificar integridad (checksums)
    if ! jq empty "$pkg_lock" 2>/dev/null; then
        findings+=("CORRUPTED_LOCK_FILE")
    fi
    
    if [ ${#findings[@]} -gt 0 ]; then
        return 1
    fi
    
    return 0
}

################################################################################
# REMEDIATION FUNCTIONS
################################################################################

remediate_project() {
    local project_dir="$1"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') Iniciando remediación: $project_dir" >> "$REMEDIATION_LOG"
    
    print_header "Remediando: $project_dir"
    
    # Backup original
    print_info "Creando backup..."
    tar -czf "$project_dir/.backup_$(date +%s).tar.gz" \
        "$project_dir/package.json" \
        "$project_dir/package-lock.json" 2>/dev/null || true
    
    # 1. Eliminar archivos maliciosos conocidos
    print_info "Eliminando archivos maliciosos..."
    find "$project_dir" -name "van-environment.js" -delete 2>/dev/null || true
    find "$project_dir" -name "setupban.js" -delete 2>/dev/null || true
    find "$project_dir" -name "*shulut*" -delete 2>/dev/null || true
    
    # 2. Limpiar node_modules
    if [ -d "$project_dir/node_modules" ]; then
        print_info "Eliminando node_modules contaminados..."
        rm -rf "$project_dir/node_modules" 2>/dev/null || true
        echo "node_modules eliminados" >> "$REMEDIATION_LOG"
    fi
    
    # 3. Limpiar npm cache
    print_info "Limpiando cache de npm..."
    npm cache clean --force 2>/dev/null || true
    
    # 4. Remover paquetes maliciosos del package.json
    if [ -f "$project_dir/package.json" ]; then
        print_info "Limpiando package.json..."
        
        # Remover dependencias maliciosas
        npm uninstall --save \
            shulut shai-hulut van-environment setupban node-setupban ban 2>/dev/null || true
        
        # Remover scripts preinstall sospechosos
        if grep -q '"preinstall"' "$project_dir/package.json"; then
            node -e "
                const fs = require('fs');
                const pkg = JSON.parse(fs.readFileSync('$project_dir/package.json', 'utf8'));
                if (pkg.scripts && pkg.scripts.preinstall) {
                    if (pkg.scripts.preinstall.includes('setupban') || 
                        pkg.scripts.preinstall.includes('van-environment')) {
                        delete pkg.scripts.preinstall;
                    }
                }
                fs.writeFileSync('$project_dir/package.json', JSON.stringify(pkg, null, 2));
            " 2>/dev/null || true
        fi
    fi
    
    # 5. Reinstalar dependencias limpias
    print_info "Reinstalando dependencias..."
    cd "$project_dir" || return 1
    npm install 2>&1 | tee -a "$REMEDIATION_LOG"
    cd - > /dev/null || return 1
    
    # 6. Verificar instalación
    if [ -d "$project_dir/node_modules" ]; then
        print_success "Remediación completada: $project_dir"
    else
        print_error "Remediación falló: $project_dir"
        return 1
    fi
}

################################################################################
# MAIN SCANNING WORKFLOW
################################################################################

perform_full_scan() {
    local search_path="${1:-.}"
    local infected_count=0
    local scanned_count=0
    
    print_header "ESCANEO COMPLETO DE PROYECTOS"
    print_info "Ruta de búsqueda: $search_path"
    print_info "Reporte: $SCAN_REPORT"
    
    # Get all npm projects
    mapfile -t projects < <(get_npm_projects "$search_path" 5)
    
    if [ ${#projects[@]} -eq 0 ]; then
        print_warning "No se encontraron proyectos npm"
        return 0
    fi
    
    print_info "Proyectos encontrados: ${#projects[@]}"
    echo ""
    
    for project_dir in "${projects[@]}"; do
        scanned_count=$((scanned_count + 1))
        pkg_file="$project_dir/package.json"
        
        echo -n "[$scanned_count/${#projects[@]}] Escaneando: $project_dir ... "
        
        local issues_found=0
        
        # Ejecutar scans
        if ! scan_package_json "$pkg_file" 2>/dev/null; then
            issues_found=$((issues_found + 1))
        fi
        
        if ! scan_node_modules "$project_dir" 2>/dev/null; then
            issues_found=$((issues_found + 1))
        fi
        
        if ! scan_package_lock "$project_dir/package-lock.json" 2>/dev/null; then
            issues_found=$((issues_found + 1))
        fi
        
        if [ "$issues_found" -gt 0 ]; then
            echo -e "${RED}INFECTADO${NC}"
            infected_count=$((infected_count + 1))
            log_message "INFECTED: $project_dir - Issues: $issues_found"
        else
            echo -e "${GREEN}LIMPIO${NC}"
            log_message "CLEAN: $project_dir"
        fi
    done
    
    echo ""
    print_header "RESUMEN DEL ESCANEO"
    print_info "Total proyectos escaneados: $scanned_count"
    print_info "Proyectos infectados: $infected_count"
    print_info "Proyectos limpios: $((scanned_count - infected_count))"
    
    return "$infected_count"
}

################################################################################
# INTERACTIVE MENU
################################################################################

show_menu() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}  SHULUT 2.0 SCANNER & REMEDIATOR${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo "1) Escanear proyectos en directorio actual"
    echo "2) Escanear directorio específico"
    echo "3) Remediar proyectos infectados"
    echo "4) Escaneo completo + Remediación automática"
    echo "5) Mostrar reportes anteriores"
    echo "6) Limpiar archivos temporales"
    echo "0) Salir"
    echo ""
}

main() {
    print_header "INICIANDO SHULUT 2.0 DETECTOR"
    print_info "Versión: 1.0"
    print_info "Fecha: $(date)"
    
    if ! check_requirements; then
        print_error "No se cumplen los requisitos"
        exit 1
    fi
    
    while true; do
        show_menu
        read -p "Seleccione opción: " choice
        
        case "$choice" in
            1)
                perform_full_scan "."
                ;;
            2)
                read -p "Ingrese ruta de directorio: " scan_dir
                if [ -d "$scan_dir" ]; then
                    perform_full_scan "$scan_dir"
                else
                    print_error "Directorio no existe: $scan_dir"
                fi
                ;;
            3)
                read -p "Ingrese ruta del proyecto: " project_dir
                if [ -d "$project_dir" ]; then
                    remediate_project "$project_dir"
                else
                    print_error "Directorio no existe: $project_dir"
                fi
                ;;
            4)
                read -p "Ingrese ruta de directorio: " scan_dir
                if [ -d "$scan_dir" ]; then
                    perform_full_scan "$scan_dir"
                    # Auto-remediate all found infected projects
                    if [ -f "$INFECTED_REPORT" ]; then
                        grep "^/" "$INFECTED_REPORT" | sort -u | while read -r project; do
                            remediate_project "$project"
                        done
                    fi
                fi
                ;;
            5)
                ls -lh /tmp/shulut_* 2>/dev/null || print_warning "No hay reportes previos"
                ;;
            6)
                rm -f /tmp/shulut_*
                print_success "Archivos temporales eliminados"
                ;;
            0)
                print_info "Saliendo..."
                exit 0
                ;;
            *)
                print_error "Opción inválida"
                ;;
        esac
    done
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
