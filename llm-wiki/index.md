# ShaderStress llm-wiki Index

| Page | Purpose | Last Verified | Stale Risk |
|------|---------|---------------|------------|
| [overview.md](overview.md) | Architecture, source map, modes, build, tests, invariants | 2026-10-04 | Low |
| [verification.md](verification.md) | Error detection: paired jobs, golden values, RAM/IO/decompress checks, attribution | 2026-10-03 | Low |
| [opt-audit.md](opt-audit.md) | Power/heat design: kernel structure, build flags, traffic-rate model, rejected approaches | 2026-10-06 | Medium (realistic target unmet inside pin; general tuning only) |
| [power-optimization.md](power-optimization.md) | Current targets, no architecture-specific tuning/builds, compiler-sim-only benchmark windows and A/B rules | 2026-10-06 | Low |
| [power-ledger.md](power-ledger.md) | Power experiments, provisional rankings, current targets and general tuning rechecks | 2026-10-06 | Medium (P044–P050; realistic 3.5–8.5 W short of band) |
| [debug-tools.md](debug-tools.md) | Debuggers, symbols, crash reports, sanitizer builds, known-good commands | 2026-10-03 | Medium (toolchain paths) |
| [debug-tools-security-audit.md](debug-tools-security-audit.md) | Security/binary-analysis tool inventory + project risk notes | 2026-10-03 | Medium |
| [secret-leak-prevention.md](secret-leak-prevention.md) | Mandatory pre/post-commit secret checks, gitleaks commands, sensitive artifacts | 2026-10-03 | Low |
| [changelog-guidelines.md](changelog-guidelines.md) | How to maintain `CHANGELOG.md` / release notes | 2026-10-03 | Low |
| [log/recent.md](log/recent.md) | Recent changes (newest first) | 2026-10-04 | Low |
| [log/archive/](log/archive/) | Archived log entries and the pre-3.6 optimization history | 2026-10-03 | Historical |
