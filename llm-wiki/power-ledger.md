# Power Experiment Ledger

Last verified: 2026-10-03. Stale-risk: low for the rules, **no agent measurement recorded yet**.

Durable record of every power experiment (procedure and decision rules:
[power-optimization.md](power-optimization.md)). Rules: one entry per experiment ID, one
change per experiment, newest entry first, measured numbers are never edited afterwards
(append a correction), negative and inconclusive results are recorded too. Evidence paths
point into the git-ignored `audit/` tree (local only); the entry itself must be enough to
understand and reproduce the change.

## Reference system

- Ryzen 7 5700X (Zen 3, 8C/16T), PBO limits open, max 90 C (Tjmax), Windows 11.
- Sensors (LHM 0.9.6, verified idle 2026-10-03): `Package` power, `Cores (Average
  Effective)` clock, `Core (Tctl/Tdie)`, `Core (SVI2 TFN)` voltage.
- UAC: `ConsentPromptBehaviorAdmin=0` → elevation is granted silently.
- Unknown, record when learned: cooler, fan profile, ambient, Windows power plan, BIOS/AGESA.

## Targets and current best (benchmark mode, all 16 threads)

"Best measured" rows come from `--mode benchmark` runs only (short-mode watts are for A/B).

| Workload | `--isa` | Target | Best measured | Eff MHz | Build / commit | Experiment |
|---|---|---|---|---|---|---|
| Realistic compiler sim | `scalar-sim` | >= ~115 W | not measured | - | - | - |
| Scalar synthetic (SSE2) | `scalar` | >= ~135 W | not measured | - | - | - |
| AVX2 synthetic | `avx2` | >= ~140-145 W | not measured (user: ~122 W before the 2026-10-03 SLP fix; build and tool unrecorded) | - | - | - |

## Hypothesis backlog

Status: `open`, `running`, `accepted`, `rejected`, `inconclusive`, `retry` (worth
re-testing after a baseline change). Take the next free ID for new ideas.

| ID | Type | Hypothesis (one change) | ISAs | Status |
|---|---|---|---|---|
| P000 | method | Validate the short protocol once: one `--mode benchmark` session of the current build, then inspect the per-second `Power sample` trace (transient after start: is 8 s warmup enough?) and compare the 9-23 s mean with the benchmark window; later check that short and benchmark A/B deltas agree for the first accepted change | all | open |
| P001 | compiler | Establish the first measured baseline and the best toolchain: `x64-llvm-v3` (baseline) vs `x64-zig-v3` vs `x64-msvc-v3`, same commit | all | open |
| P002 | flag | Quantify the SLP fix: `x64-llvm-v3-slp` (old kernel codegen, ymm spills) vs `x64-llvm-v3` | scalar, avx2 | open |
| P003 | knob | Smaller buffer / more rounds: two SMT threads x 512 KiB overflow the 512 KiB L2; start with 128 KiB x 4 rounds (`--sweep`) | scalar, avx2 | open |
| P004 | kernel | Zen 3 FADD pipes idle in the AVX2 kernel: butterflies issue only MUL/FMA (FP0/FP1), so FP2/FP3 sit idle; add independent norm-preserving add/sub work on live data (verify pipe mapping first) | avx2 (scalar shares the body) | open |
| P005 | kernel | Integer network: the g0..g7 chains are serial across blocks (multiply+rotate latency, one 64-bit DIV); restructure for more independent GPR work, keep DIV + verification | scalar, avx2 | open |
| P006 | flag | `-mtune=znver3` (`win-v3-znver3`) — mostly codegen of the realistic sim | all | open |
| P007 | flag | `-funroll-loops` / LTO / strict aliasing one at a time (`win-v3-nounroll`, `-nolto`, `-strictalias`) for the realistic sim | scalar-sim | open |
| P008 | flag | PGO (`build.py --pgo-gen/--pgo-use`) for the realistic sim; needs a bounded profiling run design (no long full-load profiling) | scalar-sim | open |

## Entries

Newest first. Copy the template.

```
### P0NN — <slug> (<status>)
- Date: YYYY-MM-DD. Type: kernel | knob | compiler | flag | scheduling.
- Change (exactly one): <what, where; key lines or patch path>.
- Baseline: <snapshot label> (GitHead <sha>, clean?) — measured on top of <previous accepted ID>.
- Candidate(s): <snapshot label(s)>.
- Conditions: background load <x>%, ambient/fans/power plan if known, anything unusual.
- Command: python scripts/power_measure.py --label ... --exe ... [--mode short|benchmark] [--isas ...] [--repeats ...]
- Result: <paste summary.md table>
- Verdict: <accepted | rejected | inconclusive> — <reason per decision rules; thermal limit?>.
- Side effects: jobs/s <delta> (benchmark score), golden checksums <unchanged | re-recorded>,
  codegen audit, --perf-stats cycles/block.
- Evidence: audit/power-measurements/session-... (local). Commit: <sha or "ledger only">.
- Follow-ups: <new hypotheses, retry conditions>.
```

(No measured entries yet. Tooling for effective clock/temperature/Vcore capture, UAC
self-elevation, snapshots and paired A/B summaries landed 2026-10-03.)
