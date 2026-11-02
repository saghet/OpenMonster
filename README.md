# 🛡️ SECMASTER-OpenMonster

> **Enterprise-Grade Desktop Cybersecurity Platform for Linux**  
> *Derived from and expanding on the verified foundation of secMONSTER with modern Rust/Tauri 2, React, and an Isolated Async Python Engine.*

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](#)
[![Stack](https://img.shields.io/badge/Stack-Tauri%202%20%7C%20Rust%20%7C%20React%20%7C%20Python-green.svg)](#)

---

## 🌟 Overview

**SECMASTER-OpenMonster** is a modular, high-performance desktop platform designed for ethical hacking, Red Team operations, and vulnerability management. It transforms raw security payloads into an enterprise application featuring:

- **Desktop Core:** Tauri 2 + Rust for process orchestration, resource isolation, safe IPC, and audit logging.
- **Frontend Experience:** Modern React 18, TypeScript, Tailwind CSS, Lucide Icons, and Recharts.
- **Reconnaissance & Intelligence Engine:** Modular attack surface discovery suite (Passive OSINT, Certificate Transparency, multi-record DNS resolution, DNSSEC, takeover detection, X.509/TLS cryptography, and Wappalyzer-compatible multi-factor technology fingerprinting).
- **Security Engine:** Python 3.12+ modular engine with strict differential verification (eliminating upstream false positives like naive regex matching).
- **Persistent Storage:** SQLite with versioned schema migrations (001-004) and audit history.
- **Scope & Safety Architecture:** Strict target whitelisting, passive-by-default scanning, rate limiting, and instantaneous cancellation.

---

## 📁 Repository Architecture

```text
sec-master/
├── frontend/             # React 18 + TypeScript + Vite + Tailwind CSS
├── src-tauri/            # Tauri 2 + Rust orchestration & secure IPC
├── engine/               # Python 3.12+ Modular Security Scanner
│   ├── core/             # Engine orchestration, cancellation & events
│   ├── recon/            # Reconnaissance & Intelligence Engine
│   │   ├── passive.py    # CT logs (crt.sh), OSINT & tool adapters (subfinder, amass)
│   │   ├── dns_engine.py # RFC DNS resolver (A, MX, NS, CNAME, DNSSEC, PTR, takeover)
│   │   ├── http_engine.py# HTTP headers, cookie security, TLS X.509 cert analysis
│   │   ├── fingerprint.py# Multi-factor technology fingerprinting (Wappalyzer)
│   │   ├── correlation.py# Attack surface topology, clustering & historical diffing
│   │   └── signatures/   # Extensible technology signatures JSON database
│   ├── scanners/         # Web, API, Auth, and Protocol scanners
│   ├── plugins/          # Extensible plugin system
│   ├── validators/       # Scope enforcement & target validation
│   └── reporting/        # JSON, CSV, HTML & Executive report generation
├── database/             # SQLite migrations, audit logs & vulnerability repository
├── tests/                # Unit, integration, and security verification tests
├── docs/                 # Architecture & API specifications
├── REPOSITORY_AUDIT.md   # Initial forensic audit of upstream secMONSTER
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Linux (x86_64)
- Rust 1.80+ and Cargo
- Bun or Node.js
- Python 3.12+

### Running the Application in Development
```bash
# Install frontend dependencies
cd frontend && bun install && cd ..

# Launch Desktop App via Tauri
bunx @tauri-apps/cli dev
```

---

## 📜 Attribution & License

SECMASTER-OpenMonster is licensed under the **GNU General Public License v3.0**.  
Portions of security signatures, payloads, and guidance methodologies are derived from [secMONSTER](https://github.com/sylhetyhackvenger/secMONSTER) by SYLHETYHACKVENGER THE-ERROR808.
