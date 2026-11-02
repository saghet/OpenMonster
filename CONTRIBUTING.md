# Contributing to SECMASTER-OpenMonster

Thank you for contributing to SECMASTER-OpenMonster. We welcome modular scanner plugins, UI enhancements, database optimisations, and false-positive reduction algorithms.

## Principles
1. **Verifiable Capabilities Only:** Never introduce phantom features, mock CVEs, or synthetic detection banners. If a feature or protocol is not tested against actual RFC specifications or mock servers, mark it as experimental.
2. **Deterministic Verification:** Avoid naive regex matches that look for simple numbers or standard HTTP strings (`<script>`, `49`, `admin`). Use differential analysis and payload reflection verification.
3. **Strict Licensing:** All contributions must comply with GNU General Public License v3.0 (GPL-3.0).
4. **Clean Code & Tests:** All pull requests must include unit and integration tests under `tests/`.
