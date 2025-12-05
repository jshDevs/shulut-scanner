# SHULUT 2.0 Threat Analysis & Remediation Guide

## 📋 Tabla de Contenidos
1. [Análisis de Amenaza](#análisis-de-amenaza)
2. [Indicadores Técnicos](#indicadores-técnicos)
3. [Guía de Remediación](#guía-de-remediación)
4. [Prevención](#prevención)

---

## 🔍 Análisis de Amenaza

### Resumen Ejecutivo

**Shulut 2.0** es un gusano de malware que infecta paquetes npm y Maven, se autorreplica y exfiltra credenciales de desarrolladores.

| Aspecto | Detalles |
|---------|----------|
| **Nombre** | Shulut 2.0 (Evolución de Shai-Hulut) |
| **Año de inicio** | Septiembre 2025 |
| **Versión actual** | 2.0 (Noviembre 2025) |
| **Ecosistemas afectados** | npm (800+ paquetes), Maven (cientos) |
| **Descargas semanales** | 20+ millones (paquetes infectados) |
| **Empresas confirmadas** | CrowdStrike, PostHog, Babel, Postman |

### Cadena de Ataque

```
1. INFECCIÓN INICIAL
   └─ Paquete npm legítimo es comprometido
      └─ Atacante añade script preinstall malicioso

2. INSTALACIÓN
   └─ npm install ejecuta preinstall script
      └─ Se instala malware (van-environment.js, setupban.js)

3. EXTRACCIÓN DE CREDENCIALES
   └─ Busca archivos sensibles:
      ├─ ~/.ssh/config
      ├─ ~/.aws/credentials
      ├─ .env / .env.local
      ├─ .git/config
      ├─ .npmrc
      └─ variables de entorno

4. OFUSCACIÓN
   └─ Codifica los credenciales
   └─ Genera paquete malicioso

5. EXFILTRACIÓN
   └─ Crea repositorio público en GitHub
   └─ Publica todas las credenciales

6. PROPAGACIÓN
   └─ Si el desarrollador tiene paquetes npm publicados
      └─ Se comprometieron automáticamente
      └─ Se auto-replican a otros 800+ paquetes

7. EJECUCIÓN REMOTA
   └─ El malware puede ejecutar código remoto
   └─ Usa credenciales de la víctima
```

### Severidad

**CRÍTICA** ⚠️⚠️⚠️

#### Por qué es tan grave:

1. **Acceso sin permisos**: npm solo valida preinstall en scripts, no solicita confirmación
2. **Efecto cadena**: Un solo desarrollador comprometido = todos sus paquetes infectados
3. **Escala masiva**: 800+ paquetes × 20M descargas/semana = exposición global
4. **Credenciales expuestas**: API keys, tokens Git, credenciales AWS públicamente visibles
5. **Supresión imposible**: GitHub no puede eliminar todos los repos a tiempo
6. **Salto de ecosistemas**: npm → Maven → posiblemente otros

---

## 🎯 Indicadores Técnicos (IOCs)

### 1. Archivos Indicadores

```bash
# Buscar estos archivos en tu sistema
van-environment.js
setupban.js
node_modules/.bin/setupban
node_modules/.bin/van-environment
```

### 2. Patrones en package.json

```json
{
  "scripts": {
    "preinstall": "node setupban.js",
    "preinstall": "npx ban",
    "preinstall": "npm run van-environment"
  },
  "dependencies": {
    "van-environment": "^1.0.0",
    "setupban": "^1.0.0",
    "shai-hulut": "^2.0.0"
  }
}
```

### 3. Paquetes Maliciosos Conocidos

```
shulut
shai-hulut
van-environment
setupban
node-setupban
ban-install
ban (cuando tiene preinstall malicioso)
```

### 4. Comportamiento en Runtime

- ✋ Instalación de `ban` (Bun runtime) como decoy
- 🔍 Búsqueda recursiva de archivos `.env`, `.npmrc`, `.git`
- 📤 Intento de conexión a hosts remoto
- 🔐 Lectura de `~/.ssh`, `~/.aws`
- 💾 Creación de repositorios GitHub automáticos

### 5. Historial Git Sospechoso

```bash
# Commits automatizados en última semana
git log --since="7 days ago" --oneline

# Si ves >10 commits de origen desconocido = sospechoso
# Si ves cambios en package.json que no hiciste = INFECTADO
```

---

## 🛡️ Guía de Remediación

### Paso 1: Detección

#### Opción A: Script Bash (Linux/macOS)

```bash
chmod +x shulut-scanner.sh
./shulut-scanner.sh

# Opciones:
# 1 - Escanear directorio actual
# 2 - Escanear directorio específico
# 3 - Remediar proyecto
# 4 - Escaneo + Remediación automática
```

#### Opción B: Script Batch (Windows)

```cmd
shulut-scanner.bat

# Menú interactivo:
# 1 - Escanear directorio actual
# 2 - Escanear directorio específico
# 3 - Remediar proyecto
# 0 - Salir
```

#### Opción C: Python (Multiplataforma)

```bash
chmod +x shulut_detector.py
python3 shulut_detector.py /ruta/a/proyectos --scan
python3 shulut_detector.py /ruta/a/proyectos --remediate
python3 shulut_detector.py /ruta/a/proyectos --report reporte.json
```

### Paso 2: Verificación Manual

Si no tienes las herramientas automatizadas:

```bash
# 1. Verificar package.json
cat package.json | grep -E "setupban|van-environment|preinstall"

# 2. Buscar archivos maliciosos
find . -name "van-environment.js" -o -name "setupban.js"

# 3. Verificar node_modules
ls node_modules | grep -E "shulut|van-environment|setupban"

# 4. Revisar scripts recientes
git log --since="7 days ago" --name-status

# 5. Buscar credenciales expuestas
git log -p -S "API_KEY" --since="7 days ago"
```

### Paso 3: Remediación Manual

**⚠️ IMPORTANTE: Rotación de Credenciales**

Antes de remediar, asume que tus credenciales están comprometidas:

```bash
# 1. CAMBIAR INMEDIATAMENTE:
# ✓ Tokens de GitHub
# ✓ Credenciales AWS
# ✓ API Keys
# ✓ SSH Keys
# ✓ Credenciales npm (.npmrc)
# ✓ Contraseñas de bases de datos
# ✓ Tokens de servicios (Sentry, NewRelic, etc)

# 2. REVOCAR EN GITHUB:
# - Settings → Developer settings → Personal access tokens → Delete
# - Settings → SSH and GPG keys → Delete
# - Security → Review security events

# 3. REVOCAR EN AWS:
# - https://console.aws.amazon.com/iam/
# - Users → Security credentials → Delete old keys
# - Create new access keys
```

**Remediación del Proyecto:**

```bash
# 1. Hacer backup
tar -czf proyecto_backup_$(date +%s).tar.gz .
git tag backup-$(date +%Y%m%d_%H%M%S)

# 2. Limpiar node_modules
rm -rf node_modules
rm -rf .npm
npm cache clean --force

# 3. Remover paquetes maliciosos del package.json
npm uninstall shulut shai-hulut van-environment setupban node-setupban ban

# 4. Eliminar preinstall sospechosos
# Editar package.json manualmente y remover:
{
  "scripts": {
    "preinstall": "..." // ELIMINAR SI CONTIENE setupban, van-environment
  }
}

# 5. Reinstalar dependencias
npm install

# 6. Verificar
npm audit
npm list

# 7. Hacer push de cambios limpios
git add package.json package-lock.json
git commit -m "fix: remove malware packages (Shulut 2.0)"
git push
```

### Paso 4: Verificación Post-Remediación

```bash
# Verificar que no hay archivos maliciosos
find . -name "van-environment.js"
find . -name "setupban.js"

# Verificar package.json limpio
cat package.json | grep -i "shulut\|van-environment\|setupban" && echo "❌ AÚN INFECTADO" || echo "✓ LIMPIO"

# Verificar git limpio
git log --all -p -S "API_KEY" --since="7 days ago"

# Audit npm
npm audit
```

---

## 🔐 Prevención

### 1. Usar pnpm en lugar de npm

**pnpm NO ejecuta preinstall scripts automáticamente sin confirmación**

```bash
# Instalar pnpm
npm install -g pnpm

# Usar pnpm en proyectos
pnpm install

# Con pnpm tienes más seguridad:
# ✓ Solicita confirmación para scripts preinstall
# ✓ Mejor aislamiento de dependencias
# ✓ Menos vulnerable a supply chain attacks
```

### 2. Revisar package-lock.json

```bash
# Mantener bajo control de versión
git add package-lock.json
git commit -m "lock dependencies"

# Verificar cambios no autorizados en lockfile
git diff package-lock.json
```

### 3. Auditoría Regular

```bash
# Ejecutar auditoría npm
npm audit

# Ejecutar Snyk (más exhaustivo)
npm install -g snyk
snyk test

# Ejecutar sonarqube/dependencycheck
docker run --rm -v $(pwd):/source owasp/dependency-check:latest \
  --project "MyProject" \
  --scan /source
```

### 4. Monitoreo de Dependencias

```bash
# Verificar cambios en dependencias
npm outdated

# Usar npm ci en CI/CD (en lugar de npm install)
# en .github/workflows/build.yml
npm ci  # Respeta package-lock.json

# Verificar checksums
npm verify
```

### 5. Configuración de Seguridad

```bash
# En ~/.npmrc global
audit-level=moderate  # O "high" o "critical"
ignore-scripts=false   # O true si quieres más seguridad

# Usar .npmrc específico por proyecto
cat > .npmrc << 'EOF'
audit-level=critical
ignore-scripts=false
fund=false
EOF

git add .npmrc
```

### 6. Git Hooks para Prevención

```bash
# .git/hooks/pre-commit
#!/bin/bash
# Verificar que no se cometan credenciales

if git diff --cached | grep -E "API_KEY|SECRET|TOKEN|PASSWORD"; then
    echo "❌ No se pueden commitear credenciales"
    exit 1
fi

chmod +x .git/hooks/pre-commit
```

### 7. Secretos Management

```bash
# Usar variables de entorno, nunca guardar en código
export API_KEY="tu_key"
export SECRET_TOKEN="tu_token"

# O usar .env (NUNCA versionar)
echo ".env" >> .gitignore

# O usar herramientas profesionales:
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault
# - 1Password Teams
```

---

## 📊 Tabla de Comparación de Herramientas

| Herramienta | Windows | Linux | macOS | Características |
|-------------|---------|-------|-------|-----------------|
| `shulut-scanner.sh` | ❌ (WSL) | ✅ | ✅ | Bash, detalle manual |
| `shulut-scanner.bat` | ✅ | ❌ | ❌ | Batch, interfaz simple |
| `shulut_detector.py` | ✅ | ✅ | ✅ | Python, análisis profundo |
| `npm audit` | ✅ | ✅ | ✅ | Built-in, básico |
| `snyk test` | ✅ | ✅ | ✅ | Online, exhaustivo |

---

## 🚨 Checklist de Respuesta a Incidente

- [ ] **Confirmación**: Verificar infección con herramientas
- [ ] **Contención**: Aislar sistemas afectados de la red
- [ ] **Rotación de credenciales**: Cambiar todos los tokens y keys
- [ ] **Remediación**: Ejecutar scripts de limpieza
- [ ] **Verificación**: Confirmar que está limpio
- [ ] **Notificación**: Informar a usuarios si es necesario
- [ ] **Post-mortem**: Analizar cómo entró el malware
- [ ] **Mejoras**: Implementar preventivas (pnpm, auditoría, git hooks)

---

## 📚 Referencias

- **midudev**: https://www.youtube.com/watch?v=dn5tt2W8tlE
- **npm Security**: https://docs.npmjs.com/packages-and-modules/security
- **OWASP Supply Chain**: https://owasp.org/www-community/attacks/Supply_Chain_Attack
- **pnpm Security**: https://pnpm.io/security

---

**Última actualización**: Diciembre 4, 2025
**Estado de amenaza**: ACTIVA - Monitoreo continuo requerido
