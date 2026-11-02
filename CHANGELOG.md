# Registro de Cambios — SECMASTER-OpenMonster

Todos los cambios notables en este proyecto están documentados en este archivo.
El formato sigue las pautas de Keep a Changelog y se adhiere a la licencia GPL-3.0.

---

## [1.0.0] - 2026-11-01

### Fase 1: Auditoría Integral y Fundación de la Plataforma
- Auditoría estricta del repositorio original `secMONSTER` (`REPOSITORY_AUDIT.md`), identificando dependencias fantasma y causas de falsos positivos.
- Establecimiento de licencias: `LICENSE` (GPL-3.0), `SECURITY.md`, `CONTRIBUTING.md`.
- Migración inicial de base de datos relacional `001_initial_schema.sql` (activos, alcances, escaneos, hallazgos, bitácora y plugins).
- Esqueleto de aplicación de escritorio Tauri 2 con backend en Rust.
- Interfaz gráfica React 18, TypeScript, Tailwind CSS y Lucide Icons con tema oscuro profesional y 16 módulos de menú.

### Fase 2: Control de Alcance, Exclusiones y Gobernanza Ética
- Migración `002_phase2_scope_enhancements.sql` con soporte para sesiones de auditoría con firma ejecutiva y listas de exclusión de rutas.
- Modales interactivos de gestión de exclusiones por activo y registro de sesiones de auditoría en la interfaz gráfica.
- Validación obligatoria de autorización antes de permitir escaneos activos; modo pasivo por defecto.
- Batería de pruebas unitarias para verificación de cumplimiento de alcance.

### Fase 3: Motor de Análisis No Destructivo y Verificación Diferencial
- Desacoplamiento del script monolítico original hacia un motor modular en Python 3.12+ con arquitectura de eventos JSON Lines en tiempo real.
- **SSTI Diferencial:** Eliminación del falso positivo por regex `49` mediante cálculo aleatorio dinámico $N_1 \times N_2$.
- **XSS Diferencial:** Sustitución de regexes estáticas por inyección de canarios aleatorios y comprobación de reflejo no codificado en el DOM.
- **SQLi Diferencial:** Verificación por divergencia booleana y detección de errores de base de datos.
- **Open Redirect:** Auditoría de cabeceras 3xx `Location`.
- **Cabeceras de Seguridad:** Auditoría de CSP, HSTS, X-Frame-Options y X-Content-Type-Options.
- Integración de subprocesos asíncronos en Rust con captura en streaming y botón de parada de emergencia inmediata (`SIGTERM`).

### Fase 4: Deduplicación Criptográfica, Remediaciones e Informes Profesionales
- Migración `003_vulnerability_dedup_and_remediation.sql` con huella criptográfica SHA-256 por vector y tabla de trazabilidad `vulnerability_history`.
- Ciclo de vida de vulnerabilidades (`open`, `remediated`, `false_positive`) con justificación técnica y firma de auditor.
- Pestaña de **Comparativa de Remediación (Differential Trend)**: clasificación en nuevos, mitigados y recurrentes (`occurrences > 1`).
- Generador de informes multi-formato: PDF/A4 para impresión, HTML independiente y autocontenido, JSON estructurado y CSV.

### Fase 5: Gestor de Plugins, IA Local Aislada (Ollama) y Diagnósticos
- Runtime de plugins desacoplado con manifiestos JSON, cálculo de sumas de integridad SHA-256 y restricción estricta de permisos.
- Plugins auditados integrados: `cors_scanner` y `ssl_tls_scanner`.
- Integración con Ollama local (`127.0.0.1:11434`) en modo estrictamente air-gapped para explicación de hallazgos, priorización y revisión defensiva de código.
- Consola de autodiagnóstico del sistema (`PRAGMA integrity_check`, módulos de escáneres, entorno Python 3.14 y garantía de cero telemetría externa).

### Fase 6: Hardening de Seguridad, Empaquetado y Verificación Final
- Endurecimiento de Content Security Policy (CSP) en la ventana webview.
- Eliminación de capacidades innecesarias de shell desde el frontend (`shell:allow-execute` revocado; todo comando se orquesta exclusivamente desde el backend de Rust con mínimos privilegios).
- Empaquetado para Linux (AppImage y Debian).
- Documentación completa de operación en `USER_GUIDE.md`.

---

## [1.1.0] - 2026-11-01

### Módulo Reconnaissance & Intelligence Engine (Fases A a J)
- **Fase A (Auditoría Técnica y Arquitectura):** Inspección forense de las capacidades de reconocimiento del proyecto original secMONSTER. Diagnóstico de dependencias y diseño desacoplado en 5 sub-motores.
- **Fase B (Contratos de Datos y Esquema Relacional):** Migración SQLite `004_reconnaissance_engine.sql` (`recon_scans`, `recon_subdomains`, `recon_dns_records`, `recon_technologies`, `recon_http_fingerprints`), estructuras Rust y orquestador central con control de límites de alcance (*scope enforcement*).
- **Fase C (Passive Reconnaissance Engine):** Integración de Certificate Transparency (`crt.sh`), OSINT público (`HackerTarget`) y adaptadores para `subfinder` y `amass`. Normalización RFC 1123, eliminación de comodines y etiquetado de activos legados/entornos (`risk:potentially_forgotten`).
- **Fase D (DNS Intelligence Engine):** Resolución multirregistro (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `PTR`), verificación criptográfica de `DNSSEC`, consultas inversas PTR y detección heurística de vectores de **Subdomain Takeover** (clasificados estrictamente como hallazgos sujetos a validación sin acciones de reclamo).
- **Fase E (HTTP & TLS Header Intelligence Engine):** Diagnóstico de transporte seguro y certificados X.509 (versión TLS, algoritmo de cifrado, emisor CA y días restantes hasta expiración con alerta si $<30$ días). Auditoría de cabeceras de seguridad (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`) y evaluación de atributos de cookies (`Secure`, `HttpOnly`, `SameSite`).
- **Fase F (Technology Fingerprinting Engine):** Base de firmas extensible `technologies.json` compatible con Wappalyzer. Detección multifactorial en 5 dimensiones (cabeceras, cookies de sesión, etiquetas `<meta>`, scripts cargados y DOM) con calibración de certeza (`Confirmed`, `Probable`, `Suspected`).
- **Fase G (Intelligence Correlation Engine):** Construcción de grafo topológico de superficie de ataque, clusterización por infraestructura compartida (*IP clustering*) y auditoría diferencial histórica (*diffing* entre escaneos).
- **Fase H (Interfaz de Usuario y Visualización):** Panel gráfico profesional en React, Tailwind CSS y Lucide Icons con 6 pestañas interactivas, métricas KPI en tiempo real, barra de progreso por streaming (`recon-event`), terminal colapsable de eventos y exportación directa a JSON y CSV.
- **Fase I (Integración con la Suite):** Enlace directo para promover subdominios descubiertos al catálogo de activos en *Asset Discovery*, deduplicación e inserción automática de hallazgos de cabeceras/TLS en *Vulnerability Management* y generación de bitácoras de auditoría inmutables.
- **Fase J (Hardening, Pruebas y Despliegue):** 44 pruebas unitarias herméticas en Python (100% aprobadas), 7 pruebas en Rust (100% aprobadas), compilación de paquete de escritorio de lanzamiento (*release binary*) y publicación del código fuente en GitHub.
