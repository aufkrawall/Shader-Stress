# Agent Instructions

## Critical workflow

- Windows-first project: prefer PowerShell 7.6, Windows-native paths, and installed project tools unless there is a clear reason to move away from them!
- After code changes, always run `python build.py` to rebuild all targets!
- Confirm the changed behavior or artifact when practical; do not infer success from exit status alone.
- Keep large logs, generated output, traces, dumps, and minified files out of working context unless needed; inspect targeted ranges or summaries and retain full output only as evidence.
- Always git commit after code changes!
- Before committing, run ALL tests and ensure they pass: `python tests/run_tests.py --stress --sanitize`!
- Sanitizer builds catch UB and memory errors before they reach release.
- Before committing, review the diff and verification results and follow the commit-message convention below.
- Commit completed code changes with plain git commands only: `git status`, `git add -A`, review `git status --short` and `git diff --cached --stat` for unintended or sensitive files, run the staged secret check, `git commit -m "<message>"`, then run the post-commit check from `llm-wiki/secret-leak-prevention.md`!
- Every agent-created commit must pass the mandatory pre-commit and post-commit secret-leak checks in `llm-wiki/secret-leak-prevention.md`; never push a commit that has not passed the post-commit check.
- Do not push to cloud unless explicitly requested, generally just commit locally!
- Maintain the root `CHANGELOG.md` using `llm-wiki/changelog-guidelines.md`: record changelog-worthy task-owned changes in the `## Unreleased` section before committing.
- Always consult `llm-wiki/` for code, bug, build, test, config, debugging, or behavior work!
- Keep `llm-wiki/` linted / quality-checked and updated when durable project knowledge changes!
- Always update `llm-wiki/` after code changes!
- Mistrust code, code annotations and llm-wiki! Each of them might be stale or outdated! Come to your own conclusion and act based on that!
- When fixing a bug or implementing a feature, generally always add new regression test units, or adjust existing ones!
- When fixing a bug or implementing a feature, generally always increase or improve debug logging to make bug diagnosis easier!

## Commit messages

- One summary line (imperative or noun phrase, <= ~100 characters) naming the user-visible effect; optional blank line plus `-` bullet body for details and the tests that were run.
- No absolute user paths, user names, secrets, or raw log excerpts in messages; keep the pseudonymous `ShaderStress Developer` identity.

## Changelog and release notes

- Describe the observable issue, behavior change, compatibility effect, or capability first; keep internal implementation detail secondary.
- Prefer concise bold lead-in anchors and the changelog categories (New, Improved, Fixed, Changed, Removed, Security) so entries remain highly scannable.
- Keep GitHub release notes aligned with the changelog section of the same release.
- Do not claim power/heat improvements without stating how they were established (measured watts on a named CPU, `--perf-stats` throughput) or marking them as expected/unmeasured.

## Secret leak prevention

- Treat secret safety as a commit gate, not an optional security-audit task.
- Before committing, inspect staged/untracked task-owned files, the staged patch, and the planned commit message; run the local secret scanner (see `llm-wiki/secret-leak-prevention.md`) when available.
- After committing, inspect the exact created commit including patch and metadata, and run commit/history secret scanning when available.
- If scanners are unavailable, perform the documented manual fallback; scanner absence never means the check may be skipped.
- Stop before push on any suspected leak. Remove/redact it, rewrite affected local commits as appropriate, and rotate/revoke real credentials according to project policy.
- Never reproduce full discovered secrets in logs, reports, changelogs, issues, PRs, or commit messages.

## Engineering rules

- Prefer root-cause fixes over workarounds; do not hide, ignore, weaken, or paper over failures!
- Perform thorough thinking about actual root causes of crashes and other issues for proper fixes!
- If the result after thorough thinking is that proper fixes require bigger changes, they generally should be implemented!
- Do not just mitigate fallout, take the hard route of proper and solid root cause fixes!
- Do not use sleeps, wait tables, polling delays, or timing bandaids as crash/race fixes!
- Do not introduce nor accept racy, timing-sensitive, or fragile behavior!
- Preserve intended features, compatibility guarantees, performance characteristics (power draw and heat are the product), and public contracts unless the requested change intentionally alters them.
- Keep behavioral diffs focused; do not mix unrelated formatting, generated churn, cleanup, or opportunistic refactors when they can be separated.
- Keep source files roughly 600-800 lines maximum; split up files when needed!
- Keep the repository layout: sources under `src/<area>/` (core, workloads, engine, app, launcher), headers included as `"<area>/<file>.h"` (`-Isrc`), scripts in `scripts/`, docs in `docs/`, resources in `resources/`, toolchains in git-ignored `toolchains/`; nothing new in the repo root unless it is a top-level project file.
- Treat dumps, logs, media, captures, credentials, private keys, tokens, symbols, and user data as sensitive!
- Do not commit secrets, dumps, logs, captures, private-symbol PDBs, large generated artifacts, user names or private user data!

## Non-negotiable project constraints

- Do not disable features to avoid fixing bugs!
- Regression unit tests, smoke tests etc. must not run the actual stresstest workloads, we do not want our program to cause heat and system load during development! The only exception are the bounded `--stress` smoke runs in `tests/run_tests.py` (seconds, <= 2 worker threads, 64 MiB RAM test, 16 MiB I/O file); never add full-thread or long-running stress to tests.
- `RunRealisticCompilerSim_V3` (`src/workloads/WorkloadRealistic.cpp`) is user-pinned by a source-hash test: change it only for correctness (e.g. UB) and only when the golden checksum proves bit-identical output. Since 2026-10-07 the default `scalar-sim` is the V5 model (`WorkloadRealisticV5*.cpp`); V3 runs only in the `x64-zig-v3-simv3` comparison build.
- "Continue power draw optimization" (or any power/heat tuning of workloads, compilers or flags): follow `llm-wiki/power-optimization.md` and record every experiment, one change each, in `llm-wiki/power-ledger.md`.
- Power measurements for the current goal must use the GUI-equivalent benchmark job mix with only compiler-sim/compute threads (all 16 on the reference CPU), zero decompression workers, RAM and I/O disabled. Select `--mode benchmark` and the intended ISA explicitly; use bounded `--power-window 23` runs (8 s warm-up + 15 s measurement), never longer workloads or steady-mode proxies. Individual runs longer than 8+15 s are a waste of time (user instruction 2026-10-06). Session procedure (user instruction 2026-10-07): a conclusive comparison is 5 paired runs per binary, decided by the paired 95% CI (no single-run or fixed-watt-tolerance verdicts), and one session compares at most a baseline plus 2 candidates (<= 345 s planned load, enforced by `power_measure.py`; `--allow-long-session` only when the user asks). Never run 20-minute probe batches: split comparisons into small sessions. Runs with more than 10% foreign CPU during the window are rejected and repeated automatically. Recheck promising or close historical short-only results; large-loss variants may be deprioritized, not relabeled as benchmark-tested. Preserve the normal GUI benchmark's 180 s scoring contract; power windows produce no benchmark score/hash.
- Every compute result must stay bit-reproducible (strict IEEE FP, no `-ffast-math`, kernels behind one non-inlined dispatcher): the redundant cross-core verification depends on it.

## Build, diagnostics, and tests

Regression coverage and diagnosability are first-class deliverables, not optional polish.

- On Windows, run every CLI mode (`--self-test`, `--repro`, `--perf-stats`, power runs) through `ShaderStress.com`, never `ShaderStress.exe` with arguments: the GUI binary pops a blocking message box on the user's desktop.
- Fix pre-existing, as well as newly introduced LSP errors/warnings along they way!
- We are paranoid about having sufficient regression tests, better too many than too few!
- For every bug fix or behavioral correction, explicitly assess both regression coverage and diagnostics even when existing tests pass. Strongly prefer a focused automated regression test that fails before the fix and passes after it.
- Add focused regression tests where possible, especially tests that would have failed before the fix!
- Unit tests live in the binary (`--self-test`, `src/app/SelfTest.cpp`) and in `tests/run_tests.py`; extend them rather than adding ad-hoc scripts.
- If additional regression coverage or diagnostics are deliberately not added for a non-trivial behavioral change, state the reason.
- Do not add sleeps or timing assumptions to tests!
- Check whether touched/new code has sufficient unit coverage, and add new test units accordingly!

## Debugging and logging

- We are paranoid about having sufficient debug logging!
- Add additional debug logging when it helps diagnose issue root causes, state transitions, failure modes, unexpected runtime conditions, or future regressions! Keep diagnostics non-secret and low-overhead.
- Ensure builds preserve useful debug symbols etc. so crash dumps contain actionable information!
- Inspect relevant dumps, logs, traces, symbols, and produced artifacts when they can establish the reported failure or its root cause.
- Prefer project-documented debugger and symbol-path guidance (`llm-wiki/debug-tools.md`).
- When `tools/discover-debug-tools.ps1` and `debug-tool-manifest.json` exist on Windows, use the manifest as machine-specific path evidence instead of duplicating SDK/MSVC discovery logic. Do not commit the manifest.
- Verify tool availability before relying on documented paths. Treat hardcoded paths as examples unless the repository declares them mandatory.
- Do not mutate global debugger flags, registry/system settings, binaries, symbols, drivers (PawnIO scripts!), or persistent environment state unless explicitly requested and justified.

## `llm-wiki/` workflow

- `llm-wiki/` is canonical LLM-maintained derived memory, not the sole source of truth.
- For substantial work, start with `llm-wiki/index.md`, read only relevant topic pages, then read `llm-wiki/log/recent.md` for active/stale-risk areas.
- Read archives only when historical context is needed or explicitly linked.
- For trivial localized edits, skip broad wiki loading unless the area is unfamiliar or stale-risk is likely.
- If `llm-wiki/` is missing during substantial work, create `index.md`, `overview.md`, and `log/recent.md` by inspecting repo structure, build/test entry points, config, docs, and workflows.
- Mistrust wiki claims until verified against code (but mistrust code too!), tests, build scripts, config, or observed behavior.
- Prefer updating existing pages over creating new ones; create new pages only for reusable topics.
- Keep topic pages focused on current best understanding; put chronology, partial investigations, and temporary notes in `llm-wiki/log/recent.md`.
- Mark uncertainty explicitly as open question, stale-risk, or unverified claim.
- Do not dump raw logs or long command output unless it establishes durable knowledge.
- Update the wiki when durable knowledge changes: architecture, behavior, build/test/package/deploy/debug workflows, bugs/root causes, invariants, conventions, rejected approaches, follow-ups, or code style.
- Do not update the wiki for trivial edits with no future-useful context.
- `llm-wiki/debug-tools.md` contains additional available debug commands and tool paths; `llm-wiki/debug-tools-security-audit.md` is the security/binary-analysis inventory.
- `llm-wiki/index.md` is a compact routing table with page link, purpose, last verified date, and stale-risk.
- Durable topic pages should include summary, source anchors, invariants, diagnostics/failure modes, open questions/stale-risk, and last verified details.
- `llm-wiki/log/recent.md` is newest-first rolling memory; archive older entries (`llm-wiki/log/archive/`) when it gets too long.
- After both wiki updates and code changes, perform a semantic quality check for contradictions, stale claims, duplicates, orphan pages, broken links, missing source anchors, and merge/delete/archive candidates.
