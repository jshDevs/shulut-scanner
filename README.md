# 🛡️ SHULUT Scanner

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)
![Node](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)

**Professional SHULUT 2.0 Detection & Remediation Suite**

Protege tus proyectos Node.js contra el malware SHULUT 2.0 con escaneo automatizado, detección avanzada y remediación completa.

[🚀 Inicio Rápido](#-inicio-rápido) • [📖 Documentación](#-uso) • [🔍 Análisis de Amenaza](THREAT_ANALYSIS.md) • [🤝 Contribuir](CONTRIBUTING.md)

</div>

---

## 📋 Tabla de Contenidos

- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Características](#-características)
- [Requisitos](#-requisitos)
- [Inicio Rápido](#-inicio-rápido)
- [Uso](#-uso)
- [Indicadores de Compromiso](#-indicadores-de-compromiso-iocs)
- [Remediación](#-Remediación)
- [Integración CI/CD](#-integración-cicd)
- [Roadmap](#-Roadmap)
- [Contribución](#-contribución)
- [Licencia](#-licencia)

---

## 🎯 Resumen Ejecutivo

**SHULUT 2.0** es un malware de cadena de suministro activo que ha infectado **800+ paquetes npm** con más de **20 millones de descargas semanales**. Este malware:

- ✅ **Roba credenciales** (.env, .npmrc, AWS, GitHub)
- ✅ **Se autorreplica** a través de scripts preinstall
- ✅ **Exfiltra datos** públicamente a GitHub
- ✅ **Afecta empresas** como CrowdStrike, PostHog, Babel

**SHULUT Scanner** proporciona:
- ✅ Detección multi-vector de malware
- ✅ Análisis profundo de node_modules
- ✅ Remediación automatizada
- ✅ Protección de credenciales
- ✅ Escaneo de Git history

---

## ✨ Características

### 🔍 **Detección Avanzada**
- Análisis de firmas maliciosas conocidas
- Detección de comportamientos sospechosos
- Escaneo de scripts preinstall
- Verificación de integridad de paquetes

### 🧹 **Remediación Automática**
- Eliminación de archivos infectados
- Sanitización de package.json
- Reinstalación de dependencias limpias
- Backup automático antes de cambios

### 🔐 **Protección de Credenciales**
- Detección de exposición de .env
- Análisis de .npmrc y tokens
- Verificación de AWS credentials
- Escaneo de GitHub tokens

### 📊 **Reportes Detallados**
- Logs completos de escaneo
- Reportes en JSON
- Estadísticas de infección
- Recomendaciones de seguridad

---

## 📦 Requisitos

### Linux / macOS
```bash
- Bash 4.0+
- Node.js 14+ (opcional)
- npm 6+ (opcional)
- git (para análisis de history)
```

### Windows
```cmd
- Windows 10/11 o Windows Server
- Node.js 14+ (opcional)
- npm 6+ (opcional)
- git (para análisis de history)
```

### Python (Herramienta Avanzada)
```bash
- Python 3.7+
- Sin dependencias externas (usa stdlib)
```

---

## 🚀 Inicio Rápido

### Linux / macOS

```bash
# 1. Clonar repositorio
git clone https://github.com/jshDevs/shulut-scanner.git
cd shulut-scanner

# 2. Dar permisos de ejecución
chmod +x shulut-scanner.sh

# 3. Ejecutar escaneo
./shulut-scanner.sh /ruta/a/tu/proyecto
```

### Windows

```cmd
REM 1. Clonar repositorio
git clone https://github.com/jshDevs/shulut-scanner.git
cd shulut-scanner

REM 2. Ejecutar escaneo
shulut-scanner.bat C:\ruta\a\tu\proyecto
```

### Python (Multiplataforma)

```bash
# 1. Clonar repositorio
git clone https://github.com/jshDevs/shulut-scanner.git
cd shulut-scanner

# 2. Ejecutar detector
python shulut_detector.py /ruta/a/tu/proyecto

# Con opciones avanzadas
python shulut_detector.py /ruta/proyecto --remediate --verbose --output report.json
```

---

## 📖 Uso

### Escaneo Básico

```bash
# Bash (Linux/macOS)
./shulut-scanner.sh /mi/proyecto

# Batch (Windows)
shulut-scanner.bat C:\mi\proyecto

# Python (Todos)
python shulut_detector.py /mi/proyecto
```

### Opciones Avanzadas (Python)

```bash
# Remediación automática
python shulut_detector.py /proyecto --remediate

# Modo verbose con reporte JSON
python shulut_detector.py /proyecto --verbose --output scan_report.json

# Solo escanear sin remediar
python shulut_detector.py /proyecto --no-remediate

# Ayuda completa
python shulut_detector.py --help
```

### Menú Interactivo (Bash)

```bash
./shulut-scanner.sh

# Opciones:
# 1) Escaneo completo
# 2) Escaneo rápido
# 3) Análisis de credenciales
# 4) Verificación de Git history
# 5) Remediación
```

---

## 🔍 Indicadores de Compromiso (IOCs)

### Archivos Maliciosos
```
- van-environment.js
- setupban.js
- node_modules/.cache/**/*.js (sospechoso)
- preinstall.js (eval/exec)
```

### Paquetes Comprometidos (Parcial)
```
- @amplication/* (varios)
- @crowdstrike/* (9 paquetes)
- @posthog/plugin-contrib
- babel-plugin-*
- @postman/pm-*
```

### Comportamientos Sospechosos
```javascript
// Ejecución remota
eval(Buffer.from(...))
exec('curl http://...')
child_process.spawn(...)

// Exfiltración
fs.readFile('.env')
fs.readFile('.npmrc')
process.env.AWS_*
```

---

## 🛠️ Remediación

### Proceso Automático

El scanner ejecuta automáticamente:

1. **Backup**: Crea respaldo con timestamp
2. **Detección**: Identifica archivos y paquetes infectados
3. **Eliminación**: Remueve malware detectado
4. **Sanitización**: Limpia package.json de scripts maliciosos
5. **Reinstalación**: Instala dependencias limpias
6. **Verificación**: Valida la remediación
7. **Reporte**: Genera log detallado

### Proceso Manual

Si prefieres control manual:

```bash
# 1. Backup
cp -r /proyecto /proyecto_backup_$(date +%Y%m%d_%H%M%S)

# 2. Eliminar node_modules
rm -rf /proyecto/node_modules

# 3. Limpiar package-lock
rm /proyecto/package-lock.json

# 4. Reinstalar
cd /proyecto
npm cache clean --force
npm install

# 5. Verificar
npm audit
```

### Rotación de Credenciales

**CRÍTICO**: Si el scanner detecta credenciales expuestas:

1. **Inmediatamente rotar**:
   - Tokens de GitHub
   - Claves AWS/Azure/GCP
   - Tokens npm
   - API keys

2. **Verificar accesos no autorizados**:
   - GitHub audit log
   - AWS CloudTrail
   - npm publish history

3. **Implementar secretos seguros**:
   - Usar variables de entorno
   - Implementar vault (HashiCorp, AWS Secrets Manager)
   - Nunca commitear credenciales

---

## 🔄 Integración CI/CD

### GitHub Actions

```yaml
name: SHULUT Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SHULUT Scanner
        run: |
          chmod +x shulut-scanner.sh
          ./shulut-scanner.sh .
          
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: shulut-report
          path: shulut_scan_*.log
```

### GitLab CI

```yaml
shulut-scan:
  stage: security
  image: node:18
  script:
    - chmod +x shulut-scanner.sh
    - ./shulut-scanner.sh .
  artifacts:
    paths:
      - shulut_scan_*.log
    expire_in: 1 week
```

### Jenkins

```groovy
stage('SHULUT Scan') {
    steps {
        sh 'chmod +x shulut-scanner.sh'
        sh './shulut-scanner.sh ${WORKSPACE}'
        archiveArtifacts artifacts: 'shulut_scan_*.log'
    }
}
```

---

## 🗺️ Roadmap

### v1.1.0 (Q1 2026)
- [ ] Soporte para Python/pip packages
- [ ] Integración con npm audit
- [ ] Dashboard web interactivo
- [ ] API REST para integración

### v1.2.0 (Q2 2026)
- [ ] Soporte para Maven (Java)
- [ ] Machine learning para detección
- [ ] Análisis de tráfico de red
- [ ] Plugin para VS Code

### v2.0.0 (Q3 2026)
- [ ] Soporte multi-lenguaje completo
- [ ] Servicio cloud managed
- [ ] Mobile app para alertas
- [ ] Integración con SIEM

---

## 🤝 Contribución

¡Contribuciones son bienvenidas! Por favor lee [CONTRIBUTING.md](CONTRIBUTING.md) para detalles.

### Cómo Contribuir

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Reportar Bugs

Usa [GitHub Issues](https://github.com/jshDevs/shulut-scanner/issues) con:
- Descripción detallada
- Pasos para reproducir
- Logs relevantes
- Sistema operativo y versión

---

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver [LICENSE](LICENSE) para detalles.

---

## 🙏 Agradecimientos

- Equipo de seguridad de npm
- Comunidad de ciberseguridad
- Investigadores que reportaron SHULUT 2.0
- Todos los contribuidores

---

## 📞 Contacto

- **GitHub**: [@jshDevs](https://github.com/jshDevs)
- **Issues**: [GitHub Issues](https://github.com/jshDevs/shulut-scanner/issues)
- **Documentación**: [Wiki](https://github.com/jshDevs/shulut-scanner/wiki)

---

<div align="center">

**⚠️ ADVERTENCIA ⚠️**

Este scanner detecta amenazas conocidas hasta la fecha. 
**Siempre mantén tus dependencias actualizadas** y sigue las mejores prácticas de seguridad.

**🛡️ ¡Protege tu código, protege tu negocio! 🛡️**

</div>
