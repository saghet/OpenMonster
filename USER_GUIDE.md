# SECMASTER-OpenMonster — Manual de Operación y Guía del Usuario

Plataforma Profesional de Ciberseguridad, Ethical Hacking y Evaluación de Vulnerabilidades para Linux.

> **Aviso Legal y Ético:** SECMASTER-OpenMonster está diseñado exclusivamente para auditorías autorizadas, pruebas de intrusión bajo alcance contractual y análisis defensivo de seguridad. El escaneo no autorizado de sistemas ajenos está estrictamente penado por la legislación vigente.

---

## 1. Requisitos del Sistema

- **Sistema Operativo:** Linux (Ubuntu 22.04+, Debian 12+, Fedora 38+, Arch Linux o derivados).
- **Entorno de Escritorio:** Servidor X11 o Wayland con soporte WebKit2GTK (`libwebkit2gtk-4.1` o `libwebkit2gtk-4.0`).
- **Runtime de Análisis:** Python 3.12 o superior con biblioteca estándar y `requests`.
- **Base de Datos:** SQLite 3 integrado (sin necesidad de configurar servidores de base de datos externos).
- **Asistente de IA Opcional:** [Ollama](https://ollama.ai) ejecutándose localmente (`http://127.0.0.1:11434`).

---

## 2. Arquitectura de Seguridad y Límites de Alcance

### A. Autorización Obligatoria de Activos
Antes de que cualquier escáner activo pueda enviar paquetes o sondas de inyección, el activo debe estar registrado y formalmente autorizado:
1. Ve al módulo **Asset Discovery**.
2. Haz clic en **Registrar Activo** e ingresa la URL o dominio objetivo (ej. `https://staging.corp-portal.local`).
3. El activo se creará en estado **No Autorizado** (bloqueo por defecto).
4. El operador debe presionar **Autorizar Alcance** y firmar con su identidad de auditor.

### B. Listas de Exclusión de Rutas
Para evitar efectos no deseados durante auditorías (por ejemplo, llamadas a endpoints de eliminación de cuentas `/admin/delete` o cierre prematuro de sesión `/auth/logout`), puedes definir exclusiones:
1. En el activo deseado, abre **Exclusiones de Alcance**.
2. Agrega las rutas o patrones prohibidos. El motor cancelará automáticamente cualquier prueba dirigida a esas rutas.

### C. Botón de Parada de Emergencia (Emergency Stop)
En la barra superior de la interfaz, el botón **Parada de Emergencia** envía una señal inmediata `SIGTERM` al subproceso del motor de escaneo en ejecución, cancelando instantáneamente la operación y liberando los descriptores de red.

---

## 3. Motor de Análisis y Verificación Diferencial

A diferencia de herramientas heurísticas que generan falsos positivos masivos mediante expresiones regulares estáticas (como ocurría en versiones previas no auditadas):

- **Server-Side Template Injection (SSTI):** Realiza multiplicación dinámica de dos números aleatorios $N_1 \times N_2$ en tiempo real (ej. `{{4829*3102}}`). Solo si el producto exacto `14979558` es calculado y renderizado por el motor del servidor se confirma la vulnerabilidad.
- **Cross-Site Scripting (XSS):** Emplea un token canario único aleatorio (ej. `sec_xss_948210`). Analiza si el valor exacto es reflejado sin codificación en el DOM de la respuesta.
- **SQL Injection (SQLi):** Compara el cuerpo de la respuesta con sondas booleanas inversas (`' OR '1'='1` vs `' AND '1'='2`), calculando el diferencial de longitud y detectando anomalías en la estructura del documento.
- **Open Redirect:** Verifica que el encabezado `Location` de respuestas de redirección 3xx coincida con el objetivo externo de prueba.
- **Cabeceras de Transporte & Seguridad:** Audita la presencia y configuración defensiva de `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` y `X-Content-Type-Options`.

---

## 4. Gestión Inteligente de Vulnerabilidades

### A. Deduplicación por Huella Criptográfica (SHA-256)
Cada vulnerabilidad genera una huella única:
$$\text{Fingerprint} = \text{SHA256}(\text{asset\_id} \parallel \text{attack\_type} \parallel \text{vector} \parallel \text{title})$$
Si un vector se detecta nuevamente en auditorías posteriores, no se crean filas duplicadas; se incrementa el contador de recurrencias (`occurrences`) y se actualiza la evidencia técnica más reciente.

### B. Ciclo de Vida y Transición de Estados
Desde el módulo **Vulnerability Management**, selecciona cualquier hallazgo:
- **Marcar Remediado:** Permite al auditor documentar el parche o cambio aplicado junto con su firma.
- **Falso Positivo:** Exige justificación técnica documentada.
- **Reabrir Hallazgo:** Vuelve a activar un vector si se detecta una regresión.
- **Trazabilidad Inmutable:** Cada cambio se guarda de forma permanente en la tabla `vulnerability_history` y en `audit_logs`.

### C. Matriz Diferencial de Remediación (Differential Trend)
En la pestaña **Comparativa de Remediación**, puedes comparar el estado de seguridad de un activo entre escaneos:
- **Nuevos Hallazgos:** Vulnerabilidades detectadas por primera vez.
- **Hallazgos Remediados:** Vectores mitigados exitosamente.
- **Hallazgos Recurrentes:** Problemas no resueltos que persisten tras múltiples evaluaciones.

---

## 5. Generación de Informes Profesionales

Desde el módulo **Reports**:
- **PDF:** Vista previa lista para impresión y exportación en formato A4 con reglas CSS `@media print`.
- **HTML Autónomo:** Exporta un archivo `.html` autocontenido, navegable en cualquier dispositivo sin conexión y sin dependencias externas.
- **JSON Estructurado:** Exportación machine-readable con metadatos completos, versiones de herramientas y evidencias JSON.
- **CSV:** Formato tabular para importación directa en hojas de cálculo y sistemas SIEM.

---

## 6. Sistema de Plugins

El módulo **Plugin Manager** permite extender la plataforma con nuevas capacidades de auditoría:
- Cada plugin reside en su propio directorio con un archivo `manifest.json`.
- **Verificación de Integridad:** Se comprueba la suma de comprobación SHA-256 del archivo `plugin.py`.
- **Aislamiento de Privilegios:** Se aplican listas blancas de permisos (`network:http_probe`, `network:tls_probe`). Está estrictamente prohibido solicitar acceso a shell arbitrario o root.
- **Plugins incluidos:**
  - `cors_scanner`: Auditoría de políticas Cross-Origin Resource Sharing.
  - `ssl_tls_scanner`: Verificación de certificados X.509 y negociación TLS.

---

## 7. Asistente de IA Local (Ollama)

En el módulo **AI Security & Assistant**:
- Conexión local transparente a `http://127.0.0.1:11434`.
- **Aislamiento Total (Air-Gapped):** Ningún dato sensible, código, IP o credencial sale de la máquina local.
- **Capacidades:**
  1. *Explicación Técnica:* Desglose del impacto de cualquier hallazgo con código defensivo para desarrolladores.
  2. *Priorización:* Ordenamiento de la matriz de remediación por criticidad de negocio.
  3. *Auditoría de Código:* Análisis estático de fragmentos vulnerables y sugerencia de refactorización segura.
- **Modo sin IA:** Si Ollama no está instalado o se encuentra apagado, la plataforma continúa funcionando al 100% de manera autónoma.

---

## 8. Diagnóstico del Sistema y Política de Telemetría

En el módulo **Settings**:
- **Integridad de Base de Datos:** Comprobación `PRAGMA integrity_check` en tiempo real.
- **Estado de Módulos:** Verificación de disponibilidad de los 5 motores principales.
- **Política de Telemetría Externa:** **DESACTIVADA POR DEFECTO (0 endpoints remotos)**. Todos los registros y diagnósticos se almacenan localmente.

---

## 9. Atribución y Licencia

SECMASTER-OpenMonster es software libre distribuido bajo los términos de la **GNU General Public License v3.0 (GPL-3.0)**.
Inspirado y derivado de las capacidades verificadas del repositorio upstream `secMONSTER` por Sylhety Hackvenger, transformado en una plataforma modular, profesional y desacoplada para Linux.
