# ShaderStress llm-wiki Index

| Page | Purpose | Last Verified | Stale Risk |
|------|---------|---------------|------------|
| [overview.md](overview.md) | Architecture, source map, modes, build, tests, invariants | 2026-10-04 | Low |
| [verification.md](verification.md) | Error detection: paired jobs, golden values, RAM/IO/decompress checks, attribution | 2026-10-03 | Low |
| [opt-audit.md](opt-audit.md) | Power/heat design: kernel structure, build flags, rejected approaches | 2026-10-04 | Medium (P011 measured; targets unmet) |
| [power-optimization.md](power-optimization.md) | Power targets, benchmark job-mix / compiler-sim-only 8+15 s windows, bounded A/B rules and tooling | 2026-10-04 | Medium (historical steady-mode rankings unverified) |
| [power-ledger.md](power-ledger.md) | Power experiments, historical benchmark baseline, protocol audit and recheck priorities | 2026-10-04 | Medium (P026–P028 benchmark-window results; targets unmet) |
| [debug-tools.md](debug-tools.md) | Debuggers, symbols, crash reports, sanitizer builds, known-good commands | 2026-10-03 | Medium (toolchain paths) |
| [debug-tools-security-audit.md](debug-tools-security-audit.md) | Security/binary-analysis tool inventory + project risk notes | 2026-10-03 | Medium |
| [secret-leak-prevention.md](secret-leak-prevention.md) | Mandatory pre/post-commit secret checks, gitleaks commands, sensitive artifacts | 2026-10-03 | Low |
| [changelog-guidelines.md](changelog-guidelines.md) | How to maintain `CHANGELOG.md` / release notes | 2026-10-03 | Low |
| [log/recent.md](log/recent.md) | Recent changes (newest first) | 2026-10-04 | Low |
| [log/archive/](log/archive/) | Archived log entries and the pre-3.6 optimization history | 2026-10-03 | Historical |
