# Security Policy & Operational Safety

## 1. Responsible Disclosure
If you discover a security vulnerability within SECMASTER-OpenMonster itself (UI, backend orchestration, privilege handling, IPC or sandbox), please report it responsibly to the security team rather than opening a public issue.

## 2. Mandatory Authorization & Scope Enforcement
SECMASTER-OpenMonster is designed strictly for authorized penetration testing, vulnerability management, and defensive security auditing.

1. **Explicit Scope Required:** Before any active scanner module can execute, target assets (FQDNs, IP ranges, URLs) must be explicitly registered and confirmed in the Scope Manager.
2. **Strict Blacklisting:** The engine enforces hardcoded exclusion filters preventing inadvertent scanning of critical cloud metadata addresses, broadcast networks, and sensitive domains unless specifically validated with override authorizations.
3. **Passive Mode by Default:** All new targets begin in Passive Reconnaissance mode. Active injection or fuzzing requires deliberate authorization flags.
4. **Immediate Emergency Stop:** An asynchronous cancellation pipeline is wired directly into the Rust backend, ensuring that scans can be immediately terminated on demand.

## 3. Sandboxing & Privilege Model
- The application executes with standard user privileges.
- Under no circumstances does the engine demand or automatically invoke `sudo` or `root` permissions.
- Engine sub-processes execute in ephemeral working environments with restricted environment variables and resource timeouts.
