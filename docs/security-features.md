# Security Features – Zero-Trust Design

OP-MODEL-SENTRY follows strict zero-trust principles:

- Never executes pickle code (uses only pickletools.dis)
- No network calls unless explicitly configured
- All parsing is read-only
- Custom rules are loaded via safe YAML parsing
- Risk scoring is deterministic and auditable
- Output can be exported to SIEM (JSON format)

Designed for air-gapped and high-security environments.