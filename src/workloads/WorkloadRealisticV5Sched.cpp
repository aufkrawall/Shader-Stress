// WorkloadRealisticV5Sched.cpp - Realistic V5 register demand and machine
// scheduler (ACO's live_var_analysis demand and schedule_program in spirit).
//
// Register demand: a backward walk per block over the live set (seeded from
// the block's live-out bitset) yields, for every instruction, the SGPR / VGPR
// dwords live across it, its definitions included. The program maximum gives
// the occupancy (GFX9 waves per SIMD from the VGPR and SGPR budgets).
//
// Scheduler: scalar loads (SMEM) and vector memory loads (VMEM) move up their
// block, past independent instructions, so their latency overlaps other work
// and loads of one kind form clauses. A move stops at the definition of an
// operand, a store / export / branch, a load of the same kind (clause order),
// an exec write (VMEM runs under exec), the window / move budget, or when the
// longer live range would raise the demand above what the current occupancy
// allows (never trade waves for latency). Windows and budgets shrink with
// occupancy like ACO's SMEM_WINDOW_SIZE / VMEM_WINDOW_SIZE. Moves rotate the
// instruction pointers in place and update the demand of the crossed range.
#include "workloads/WorkloadRealisticV5Mach.h"
#include <algorithm>

namespace simv5 {
namespace {
inline bool TestB(const uint64_t *s, uint32_t k) { return (s[k >> 6] >> (k & 63)) & 1; }
inline uint32_t Pack(uint32_t s, uint32_t v) { return s | v << 16; }

// GFX9, wave64: 256 VGPRs per lane in granules of 4, 800 SGPRs per SIMD in
// granules of 16 (+6 for vcc / flat_scratch / xnack), at most 10 waves.
uint32_t WavesFor(uint32_t sgprs, uint32_t vgprs) {
  const uint32_t v = std::max(4u, (vgprs + 3) & ~3u), s = std::max(16u, (sgprs + 6 + 15) & ~15u);
  return std::max(1u, std::min({10u, 256u / v, 800u / s}));
}
// Scheduling targets keep headroom below the register files (the allocator's
// single intervals are coarser than the exact demand).
uint32_t VgprLimit(uint32_t waves) { return std::min(kVgprs - 8, (256u / waves) & ~3u); }
uint32_t SgprLimit(uint32_t waves) { return std::min(kSgprAlloc - 9, ((800u / waves) & ~15u) - 6); }

enum LoadKind : uint8_t { kNoLoad, kSmem, kVmem };
inline LoadKind KindOf(const MInst &mi) {
  if (MHas(mi.op, kMStore) || mi.ndefs == 0 || !IsTempOp(mi.defs[0])) return kNoLoad;
  if (MHas(mi.op, kMLgkm)) return kSmem;
  if (MHas(mi.op, kMVmem)) return kVmem;
  return kNoLoad;
}

// Can load `c` (kind k) move above instruction p?
bool Independent(const MInst &p, const MInst &c, LoadKind k) {
  if (p.op == m_p_phi || p.op == m_p_startpgm || p.op == m_p_parallelcopy) return false;
  if (MHas(p.op, kMStore | kMBranch)) return false;                // memory order, control flow
  if (k == kSmem ? MHas(p.op, kMLgkm) : MHas(p.op, kMVmem)) return false; // clause order
  for (uint32_t d = 0; d < 2; ++d) {
    const uint32_t o = p.defs[d];
    if (o == kONone) continue;
    if ((o & kOKind) == kOFixed) {
      if (k == kVmem && (o & 0x3FF) == kRegExec) return false; // the load runs under exec
      for (uint32_t j = 0; j < c.nops; ++j)
        if (c.ops[j] == o) return false;
      continue;
    }
    if (!IsTempOp(o)) continue;
    for (uint32_t j = 0; j < c.nops; ++j)
      if (IsTempOp(c.ops[j]) && TempOf(c.ops[j]) == TempOf(o)) return false; // operand defined here
  }
  return true;
}
} // namespace

void ComputeRegisterDemand(Fn &f, Mach &m) {
  MachineLiveness(f, m);
  const uint32_t n = (uint32_t)m.code.size(), words = m.liveWords;
  m.demand.resize(n);
  uint64_t *live = m.live.data();
  uint32_t maxS = 0, maxV = 0;
  auto add = [&](uint32_t t, uint32_t &s, uint32_t &v, int sign) {
    const MTemp &x = m.temps[t];
    (x.cls == kSgpr ? s : v) += (uint32_t)(sign * (int)x.size);
  };
  for (uint32_t b = 0; b < m.blocks.size(); ++b) {
    const MBlock &mb = m.blocks[b];
    const uint64_t *out = &m.liveOut[(size_t)b * words];
    std::copy(out, out + words, live);
    uint32_t s = 0, v = 0;
    for (uint32_t w = 0; w < words; ++w)
      for (uint64_t bits = live[w]; bits; bits &= bits - 1) add(w * 64 + (uint32_t)std::countr_zero(bits), s, v, 1);
    for (uint32_t i = mb.end; i-- > mb.start;) {
      const MInst &mi = m.code[i];
      uint32_t atS = s, atV = v; // live after i, plus definitions nobody reads
      for (uint32_t d = 0; d < mi.ndefs; ++d) {
        if (!IsTempOp(mi.defs[d])) continue;
        const uint32_t t = TempOf(mi.defs[d]);
        if (TestB(live, t)) {
          live[t >> 6] &= ~(1ull << (t & 63));
          add(t, s, v, -1);
        } else {
          add(t, atS, atV, 1);
        }
      }
      if (mi.op != m_p_phi) // phi operands are live out of the predecessors
        for (uint32_t k = 0; k < mi.nops; ++k) {
          if (!IsTempOp(mi.ops[k])) continue;
          const uint32_t t = TempOf(mi.ops[k]);
          if (TestB(live, t)) continue;
          live[t >> 6] |= 1ull << (t & 63); // killed here
          add(t, s, v, 1);
        }
      const uint32_t ds = std::max(atS, s), dv = std::max(atV, v);
      m.demand[i] = Pack(ds, dv);
      maxS = std::max(maxS, ds);
      maxV = std::max(maxV, dv);
    }
  }
  m.demandS = maxS;
  m.demandV = maxV;
  m.waves = WavesFor(maxS, maxV);
  f.st.demandSgprPeak = std::max<uint64_t>(f.st.demandSgprPeak, maxS);
  f.st.demandVgprPeak = std::max<uint64_t>(f.st.demandVgprPeak, maxV);
  f.st.wavesSum += m.waves;
}

void ScheduleMachine(Fn &f, Mach &m) {
  const uint32_t waves = m.waves;
  const uint32_t limS = SgprLimit(waves), limV = VgprLimit(waves); // over-limit shaders get no moves there
  // Window / move budgets from the occupancy, clamped to 4..8 waves as ACO
  // does for GFX9 (more waves hide latency themselves, fewer need no less).
  const uint32_t w = std::clamp(waves, 4u, 8u);
  const uint32_t smemWindow = 350 - w * 35, vmemWindow = 1024 - w * 64;
  const uint32_t smemMoves = 64 - w * 4, vmemMoves = 256 - w * 16;
  MInst **code = m.code.data();
  uint32_t *dem = m.demand.data();
  for (const MBlock &mb : m.blocks) {
    uint32_t first = mb.start;
    while (first < mb.term && (code[first]->op == m_p_phi || code[first]->op == m_p_startpgm)) ++first;
    for (uint32_t i = first; i < mb.term; ++i) {
      const MInst &c = *code[i];
      const LoadKind kind = KindOf(c);
      if (kind == kNoLoad) continue;
      const MTemp &dt = m.temps[TempOf(c.defs[0])];
      const uint32_t addS = dt.cls == kSgpr ? dt.size : 0, addV = dt.cls == kVgpr ? dt.size : 0;
      const uint32_t window = kind == kSmem ? smemWindow : vmemWindow;
      const uint32_t budget = kind == kSmem ? smemMoves : vmemMoves;
      uint32_t k = i, scanned = 0;
      while (k > first && scanned < window && i - k < budget) {
        const MInst &p = *code[k - 1];
        ++scanned;
        if (!Independent(p, c, kind)) break;
        const uint32_t d = dem[k - 1];
        if ((d & 0xFFFF) + addS > limS || (d >> 16) + addV > limV) break; // would cost occupancy
        --k;
      }
      f.st.mschedScanned += scanned;
      if (k == i) continue;
      // Rotate [k, i] so the load lands at k; the crossed range now also
      // holds its result.
      MInst *x = code[i];
      const uint32_t add = Pack(addS, addV), atK = dem[k];
      for (uint32_t j = i; j > k; --j) {
        code[j] = code[j - 1];
        dem[j] = dem[j - 1] + add;
      }
      code[k] = x;
      dem[k] = atK + add;
      f.st.mschedMoved++;
      f.st.mschedDistance += i - k;
    }
  }
  // Definitions moved: renumber (live intervals start at the definition).
  for (uint32_t i = 0; i < m.code.size(); ++i) {
    const MInst &mi = *code[i];
    for (uint32_t d = 0; d < mi.ndefs; ++d)
      if (IsTempOp(mi.defs[d])) m.temps[TempOf(mi.defs[d])].def = i;
  }
}
} // namespace simv5

// Scheduler on hand-built code: SMEM hoisting to the block start, VMEM
// stopping at an operand definition and at an exec write, the occupancy limit
// blocking a move, definitions renumbered. Returns failed-check bits.
uint32_t RunRealisticCompilerSimV5SchedTest() {
  using namespace simv5;
  uint32_t fail = 0;
  for (int variant = 0; variant < 2; ++variant) {
    Mach m;
    Fn f;
    auto temp = [&](uint8_t cls, uint8_t size) {
      MTemp t{};
      t.def = kNone;
      t.hint = t.fixed = kNone;
      t.phys = kPhysSpill;
      t.cls = cls;
      t.size = size;
      m.temps.push_back(t);
      return (uint32_t)m.temps.size() - 1;
    };
    auto inst = [&](uint32_t op, uint32_t def, uint32_t a = kONone, uint32_t b = kONone) {
      MInst mi;
      std::memset(&mi, 0, sizeof(mi));
      mi.op = (uint16_t)op;
      mi.defs[0] = def;
      mi.defs[1] = kONone;
      mi.ndefs = def != kONone;
      mi.ops[0] = a;
      mi.ops[1] = b;
      mi.ops[2] = mi.ops[3] = kONone;
      mi.nops = (uint8_t)(b != kONone ? 2 : a != kONone ? 1 : 0);
      mi.node = mi.aux = kNone;
      if (IsTempOp(def)) m.temps[TempOf(def)].def = (uint32_t)m.code.size();
      m.code.push_back(mi);
    };
    const uint32_t t0 = temp(kSgpr, 2), t1 = temp(kVgpr, 1), t2 = temp(kVgpr, 1), t3 = temp(kSgpr, 4);
    const uint32_t t4 = temp(kVgpr, 1), t5 = temp(kVgpr, 1), t6 = temp(kVgpr, 1), t7 = temp(kVgpr, 1);
    const uint32_t t8 = temp(kVgpr, 1);
    inst(m_p_startpgm, OTemp(t0));                          // 0
    inst(m_v_mov_b32, OTemp(t1), kOInline | 129);           // 1
    inst(m_v_add_u32, OTemp(t2), OTemp(t1), OTemp(t1));     // 2
    inst(m_s_load_dwordx4, OTemp(t3), OTemp(t0));           // 3 -> 1
    inst(m_v_add_u32, OTemp(t4), OTemp(t2), OTemp(t2));     // 4
    inst(m_v_mov_b32, OTemp(t6), kOInline | 130);           // 5
    inst(m_buffer_load_dword, OTemp(t5), OTemp(t1), OTemp(t3)); // 6 -> 3 (stops at t1's definition)
    inst(m_s_mov_b64, kOFixed | kRegExec, OTemp(t0));       // 7 exec write
    inst(m_v_mov_b32, OTemp(t7), kOInline | 131);           // 8
    inst(m_buffer_load_dword, OTemp(t8), OTemp(t1), OTemp(t3)); // 9 -> 8 (stops at the exec write)
    inst(m_exp, kONone, OTemp(t5), OTemp(t8));              // 10
    inst(m_s_endpgm, kONone);                               // 11
    MBlock b{};
    b.ir = 0;
    b.start = 0;
    b.term = 11;
    b.end = 12;
    b.succ[0] = b.succ[1] = kNone;
    b.flipOf = kNone;
    m.blocks.push_back(b);
    ComputeRegisterDemand(f, m);
    if (m.waves != 10 || m.demandS != 6 || m.demandV < 3) fail |= 1;
    if (variant == 1) m.demand[2] = Pack(SgprLimit(m.waves), 0); // SGPR budget full at the v_add
    ScheduleMachine(f, m);
    static constexpr uint16_t kExpect[2][12] = {
        {m_p_startpgm, m_s_load_dwordx4, m_v_mov_b32, m_buffer_load_dword, m_v_add_u32, m_v_add_u32,
         m_v_mov_b32, m_s_mov_b64, m_buffer_load_dword, m_v_mov_b32, m_exp, m_s_endpgm},
        {m_p_startpgm, m_v_mov_b32, m_v_add_u32, m_s_load_dwordx4, m_buffer_load_dword, m_v_add_u32,
         m_v_mov_b32, m_s_mov_b64, m_buffer_load_dword, m_v_mov_b32, m_exp, m_s_endpgm}};
    for (uint32_t i = 0; i < 12; ++i)
      if (m.code[i].op != kExpect[variant][i]) fail |= 2u << (variant * 4);
    if (m.temps[t3].def != (variant ? 3u : 1u) || m.temps[t8].def != 8) fail |= 4u << (variant * 4);
    if (ValidateMachine(f, m) != 0) fail |= 8u << (variant * 4);
  }
  return fail;
}
