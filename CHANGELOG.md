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
