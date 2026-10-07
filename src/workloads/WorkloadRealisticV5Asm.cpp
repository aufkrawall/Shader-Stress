// WorkloadRealisticV5Asm.cpp - Realistic V5 wait-count insertion and binary
// encoding (ACO insert_waitcnt and assembler in spirit).
//  - s_waitcnt: per register, the outstanding vector-memory loads (vmcnt,
//    in-order counter: how many newer loads may still be pending), scalar
//    memory results (lgkmcnt, out of order: wait for zero) and exports that
//    still read a register (expcnt). Block states join over predecessors and
//    iterate to a fixed point for loops; the last sweep emits the waits.
//  - Assembler: real GFX9 formats (SOP1/SOP2/SOPC/SOPK/SOPP, SMEM, VOP1/VOP2/
//    VOPC/VOP3, VINTRP, MUBUF, MIMG, EXP), VOP2/VOPC promoted to VOP3 when the
//    operands require it, literal dwords, branch offsets from block layout,
//    one encoder per opcode; the shader binary is hashed (cache key).
#include "workloads/WorkloadRealisticV5Mach.h"
#include <array>

namespace simv5 {
namespace {
constexpr uint32_t kSlots = 128 + kVgprs; // SGPR codes 0..127, VGPRs
constexpr uint32_t kMaskWords = kSlots / 64;
constexpr uint8_t kNoWait = 0xFF;
enum Counter { kVm, kLgkm, kExp, kCounters };
// Pending events per counter: a bitmask of registers with an outstanding
// result (or export source) and, per register, how many newer events of the
// same counter may still be outstanding when it completes (vmcnt / expcnt are
// in order; lgkmcnt is out of order, so waits for it go to zero).
struct WaitState {
  uint64_t mask[kCounters][kMaskWords];
  uint8_t val[kCounters][kSlots];
  uint8_t out[kCounters];
  uint8_t valid;
};
inline uint32_t Slot(uint32_t code) { return code < 128 ? code : code >= kRegVgpr ? 128 + (code - kRegVgpr) : kNone; }
inline uint32_t DefSize(const MInst &mi, uint32_t d, const Mach &m) {
  return IsTempOp(mi.defs[d]) ? m.temps[TempOf(mi.defs[d])].size : (MHas(mi.op, kM64) ? 2 : 1);
}
inline uint32_t OpSize(const MInst &mi, uint32_t k, const Mach &m) {
  if (!IsTempOp(mi.ops[k])) return 1;
  const MTemp &t = m.temps[TempOf(mi.ops[k])];
  return SubOf(mi.ops[k]) ? 1 : t.size;
}
template <class F> inline void ForBits(const uint64_t *mask, F &&f) {
  for (uint32_t w = 0; w < kMaskWords; ++w)
    for (uint64_t b = mask[w]; b; b &= b - 1) f(w * 64 + (uint32_t)std::countr_zero(b));
}
inline bool Has(const uint64_t *mask, uint32_t r) { return (mask[r >> 6] >> (r & 63)) & 1; }

class Waitcnt {
public:
  Waitcnt(Fn &f, Mach &m) : f_(f), m_(m) {}
  void Run();

private:
  static void Reset(WaitState &s) {
    std::memset(s.mask, 0, sizeof(s.mask));
    std::memset(s.out, 0, sizeof(s.out));
    s.valid = 0;
  }
  static void Copy(WaitState &d, const WaitState &s) { // pending entries only
    std::memcpy(d.mask, s.mask, sizeof(s.mask));
    std::memcpy(d.out, s.out, sizeof(s.out));
    d.valid = s.valid;
    for (uint32_t c = 0; c < kCounters; ++c) ForBits(s.mask[c], [&](uint32_t r) { d.val[c][r] = s.val[c][r]; });
  }
  static bool Same(const WaitState &a, const WaitState &b) {
    if (a.valid != b.valid || std::memcmp(a.mask, b.mask, sizeof(a.mask)) || std::memcmp(a.out, b.out, sizeof(a.out)))
      return false;
    bool same = true;
    for (uint32_t c = 0; c < kCounters; ++c) ForBits(a.mask[c], [&](uint32_t r) { same &= a.val[c][r] == b.val[c][r]; });
    return same;
  }
  static void Join(WaitState &s, const WaitState &p) {
    if (!p.valid) return;
    for (uint32_t c = 0; c < kCounters; ++c) {
      ForBits(p.mask[c], [&](uint32_t r) {
        if (Has(s.mask[c], r)) s.val[c][r] = std::min(s.val[c][r], p.val[c][r]);
        else {
          s.mask[c][r >> 6] |= 1ull << (r & 63);
          s.val[c][r] = p.val[c][r];
        }
      });
      s.out[c] = std::max(s.out[c], p.out[c]);
    }
  }
  static void Issue(WaitState &s, uint32_t c, uint8_t cap) { // a newer event of counter c
    ForBits(s.mask[c], [&](uint32_t r) {
      if (s.val[c][r] < cap) s.val[c][r]++;
    });
    s.out[c] = (uint8_t)std::min<uint32_t>(cap + 1u, s.out[c] + 1u);
  }
  static void Pend(WaitState &s, uint32_t c, uint32_t code, uint32_t size) {
    for (uint32_t k = 0; k < size; ++k) {
      const uint32_t r = Slot(code + k);
      if (r == kNone) return;
      s.mask[c][r >> 6] |= 1ull << (r & 63);
      s.val[c][r] = 0;
    }
  }
  void Block(uint32_t b, WaitState &s, bool emit);
  Fn &f_;
  Mach &m_;
  uint32_t term_ = 0;
};

void Waitcnt::Block(uint32_t b, WaitState &s, bool emit) {
  const MBlock &mb = m_.blocks[b];
  for (uint32_t i = mb.start; i < mb.end; ++i) {
    const MInst &mi = m_.code[i];
    uint8_t need[kCounters] = {kNoWait, kNoWait, kNoWait};
    auto check = [&](uint32_t code, uint32_t size, bool def) {
      for (uint32_t k = 0; k < size; ++k) {
        const uint32_t r = Slot(code + k);
        if (r == kNone) return;
        if (Has(s.mask[kVm], r)) need[kVm] = std::min(need[kVm], s.val[kVm][r]);
        if (Has(s.mask[kLgkm], r)) need[kLgkm] = 0;
        if (def && Has(s.mask[kExp], r)) need[kExp] = std::min(need[kExp], s.val[kExp][r]);
      }
    };
    if (emit && i == mb.term) term_ = (uint32_t)m_.tmp.size();
    for (uint32_t k = 0; k < 4; ++k)
      if (mi.ops[k] != kONone) check(mi.pop[k], OpSize(mi, k, m_), false);
    for (uint32_t d = 0; d < 2; ++d)
      if (mi.defs[d] != kONone) check(mi.pdef[d], DefSize(mi, d, m_), true);
    if (need[kVm] != kNoWait || need[kLgkm] != kNoWait || need[kExp] != kNoWait) {
      if (emit) {
        MInst w;
        std::memset(&w, 0, sizeof(w));
        w.op = m_s_waitcnt;
        w.defs[0] = w.defs[1] = kONone;
        for (uint32_t &o : w.ops) o = kONone;
        w.node = w.aux = kNone;
        w.block = b;
        const uint32_t v = need[kVm] == kNoWait ? 63 : need[kVm], e = need[kExp] == kNoWait ? 7 : need[kExp];
        const uint32_t l = need[kLgkm] == kNoWait ? 15 : need[kLgkm];
        w.imm = (uint16_t)((v & 15) | e << 4 | l << 8 | (v >> 4) << 14);
        m_.tmp.push_back(w);
        f_.st.waitcnts++;
      }
      for (uint32_t c = 0; c < kCounters; ++c) { // events older than the allowed count completed
        if (need[c] == kNoWait) continue;
        ForBits(s.mask[c], [&](uint32_t r) {
          if (s.val[c][r] >= need[c]) s.mask[c][r >> 6] &= ~(1ull << (r & 63));
        });
        s.out[c] = std::min(s.out[c], need[c]);
      }
    }
    if (emit) m_.tmp.push_back(mi);
    const uint16_t fl = kMOpInfo[mi.op].flags;
    if (fl & kMVmem) {
      Issue(s, kVm, 62);
      if (!(fl & kMStore)) Pend(s, kVm, mi.pdef[0], DefSize(mi, 0, m_));
    } else if (fl & kMLgkm) {
      Pend(s, kLgkm, mi.pdef[0], DefSize(mi, 0, m_));
      s.out[kLgkm] = (uint8_t)std::min(15, s.out[kLgkm] + 1);
    } else if (fl & kMExpCnt) {
      Issue(s, kExp, 6);
      for (uint32_t k = 0; k < 4; ++k)
        if (mi.ops[k] != kONone) Pend(s, kExp, mi.pop[k], 1);
    }
  }
}

void Waitcnt::Run() {
  const uint32_t nb = (uint32_t)m_.blocks.size();
  m_.waitState.resize((size_t)nb * sizeof(WaitState));
  WaitState *out = reinterpret_cast<WaitState *>(m_.waitState.data());
  for (uint32_t b = 0; b < nb; ++b) out[b].valid = 0;
  WaitState s;
  auto entry = [&](uint32_t b) {
    Reset(s);
    for (uint32_t p = 0; p < m_.blocks[b].npred; ++p) Join(s, out[m_.blocks[b].pred[p]]);
    s.valid = 1;
  };
  for (bool changed = true; changed;) { // fixed point over loops
    changed = false;
    f_.st.waitIters++;
    for (uint32_t b = 0; b < nb; ++b) {
      entry(b);
      Block(b, s, false);
      if (!Same(out[b], s)) {
        Copy(out[b], s);
        changed = true;
      }
    }
  }
  m_.tmp.clear();
  for (uint32_t b = 0; b < nb; ++b) {
    MBlock &mb = m_.blocks[b];
    const uint32_t start = (uint32_t)m_.tmp.size();
    entry(b);
    term_ = kNone;
    Block(b, s, true);
    mb.start = start;
    mb.end = (uint32_t)m_.tmp.size();
    mb.term = term_ == kNone ? mb.end : term_;
  }
  m_.code.swap(m_.tmp);
}

// --- Assembler ---------------------------------------------------------------
struct Ctx {
  const Mach &m;
  uint32_t pc; // dword offset of the instruction
};
inline bool UsesVop3(const MInst &mi) {
  const uint32_t fmt = kMOpInfo[mi.op].fmt;
  if (fmt == kFVop3 || mi.mods) return true;
  if (fmt == kFVop2) {
    if (mi.op == m_v_cndmask_b32) return mi.pop[3] != kRegVcc || mi.pop[1] < kRegVgpr;
    return mi.ops[1] != kONone && mi.pop[1] < kRegVgpr;
  }
  if (fmt == kFVopc) return mi.pdef[0] != kRegVcc || mi.pop[1] < kRegVgpr;
  return false;
}
inline bool HasLiteral(const MInst &mi) {
  for (uint32_t k = 0; k < 4; ++k)
    if (mi.pop[k] == 255 && mi.ops[k] != kONone) return true;
  return false;
}
inline uint32_t Words(const MInst &mi) {
  const uint32_t fmt = kMOpInfo[mi.op].fmt;
  if (fmt == kFPseudo) return 0;
  const bool wide = fmt == kFSmem || fmt == kFMubuf || fmt == kFMimg || fmt == kFExp ||
                    ((fmt == kFVop2 || fmt == kFVop1 || fmt == kFVopc || fmt == kFVop3) && UsesVop3(mi));
  return (wide ? 2 : 1) + (HasLiteral(mi) ? 1 : 0);
}

template <uint32_t Op> NOINLINE uint32_t *Encode(const MInst &mi, uint32_t *out, const Ctx &c) {
  constexpr MOpInfo info = kMOpInfo[Op];
  constexpr uint32_t code = info.code;
  const uint32_t d = mi.pdef[0], s0 = mi.pop[0], s1 = mi.pop[1], s2 = mi.pop[2];
  if constexpr (info.fmt == kFSop2) {
    *out++ = 0x80000000u | code << 23 | (d & 0x7F) << 16 | (s1 & 0xFF) << 8 | (s0 & 0xFF);
  } else if constexpr (info.fmt == kFSopk) {
    *out++ = 0xB0000000u | code << 23 | (d & 0x7F) << 16 | mi.imm;
  } else if constexpr (info.fmt == kFSop1) {
    *out++ = 0xBE800000u | (d & 0x7F) << 16 | code << 8 | (s0 & 0xFF);
  } else if constexpr (info.fmt == kFSopc) {
    *out++ = 0xBF000000u | code << 16 | (s1 & 0xFF) << 8 | (s0 & 0xFF);
  } else if constexpr (info.fmt == kFSopp) {
    uint32_t simm = mi.imm;
    if constexpr ((info.flags & kMBranch) != 0) simm = (c.m.blocks[mi.aux].offset - (c.pc + 1)) & 0xFFFF;
    *out++ = 0xBF800000u | code << 16 | simm;
  } else if constexpr (info.fmt == kFSmem) {
    const bool imm = (mi.flags & kMfOffset) && mi.ops[1] == kONone;
    *out++ = 0xC0000000u | code << 18 | (imm ? 1u << 17 : 0u) | (d & 0x7F) << 6 | ((s0 >> 1) & 0x3F);
    *out++ = imm ? mi.imm : s1 & 0xFF;
  } else if constexpr (info.fmt == kFVop2 || info.fmt == kFVop1 || info.fmt == kFVopc || info.fmt == kFVop3) {
    if (UsesVop3(mi)) {
      uint32_t op3 = code;
      if constexpr (info.fmt == kFVop2) op3 = 0x100 + code;
      else if constexpr (info.fmt == kFVop1) op3 = 0x140 + code;
      const uint32_t src2 = Op == m_v_cndmask_b32 ? mi.pop[3] : s2;
      *out++ = 0xD0000000u | (op3 & 0x3FF) << 16 | (mi.mods & 0x40 ? 1u << 15 : 0u) | ((mi.mods >> 3) & 7) << 8 | (d & 0xFF);
      *out++ = (uint32_t)(mi.mods & 7) << 29 | (src2 & 0x1FF) << 18 | (s1 & 0x1FF) << 9 | (s0 & 0x1FF);
    } else if constexpr (info.fmt == kFVop2) {
      *out++ = code << 25 | ((d - kRegVgpr) & 0xFF) << 17 | ((s1 - kRegVgpr) & 0xFF) << 9 | (s0 & 0x1FF);
    } else if constexpr (info.fmt == kFVop1) {
      *out++ = 0x7E000000u | (d & 0xFF) << 17 | code << 9 | (s0 & 0x1FF);
    } else {
      *out++ = 0x7C000000u | code << 17 | ((s1 - kRegVgpr) & 0xFF) << 9 | (s0 & 0x1FF);
    }
  } else if constexpr (info.fmt == kFVintrp) {
    const uint32_t src = s0; // i (p1) or j (p2) barycentric
    *out++ = 0xD4000000u | ((d - kRegVgpr) & 0xFF) << 18 | code << 16 | (mi.imm >> 2 & 0x3F) << 10 |
             (mi.imm & 3) << 8 | ((src - kRegVgpr) & 0xFF);
  } else if constexpr (info.fmt == kFMubuf) {
    const bool store = (info.flags & kMStore) != 0;
    const uint32_t vdata = store ? s0 : d, vaddr = store ? s1 : s0, rsrc = store ? s2 : s1;
    *out++ = 0xE0000000u | code << 18 | (mi.flags & kMfOffen ? 1u << 12 : 0u) | (mi.imm & 0xFFF);
    *out++ = 128u << 24 | ((rsrc >> 2) & 0x1F) << 16 | ((vdata - kRegVgpr) & 0xFF) << 8 | ((vaddr - kRegVgpr) & 0xFF);
  } else if constexpr (info.fmt == kFMimg) {
    *out++ = 0xF0000000u | code << 18 | (mi.imm & 0xF) << 8;
    *out++ = ((s2 >> 2) & 0x1F) << 21 | ((s1 >> 2) & 0x1F) << 16 | ((d - kRegVgpr) & 0xFF) << 8 | ((s0 - kRegVgpr) & 0xFF);
  } else if constexpr (info.fmt == kFExp) {
    *out++ = 0xC4000000u | (mi.flags & kMfVm ? 1u << 12 : 0u) | (mi.flags & kMfDone ? 1u << 11 : 0u) | (mi.imm & 0xF);
    uint32_t v = 0;
    for (uint32_t k = 0; k < 4; ++k) v |= (mi.ops[k] != kONone ? (mi.pop[k] - kRegVgpr) & 0xFF : 0u) << (8 * k);
    *out++ = v;
  } else {
    return out; // pseudo instructions are gone after lowering
  }
  if (HasLiteral(mi)) *out++ = mi.literal;
  return out;
}

using EncodeFn = uint32_t *(*)(const MInst &, uint32_t *, const Ctx &);
template <uint32_t... I>
constexpr std::array<EncodeFn, sizeof...(I)> EncodeTable(std::integer_sequence<uint32_t, I...>) {
  return {{&Encode<I>...}};
}
constexpr auto kEncode = EncodeTable(std::make_integer_sequence<uint32_t, kMOpCount>{});
} // namespace

void InsertWaitcnt(Fn &f, Mach &m) {
  Waitcnt w(f, m);
  w.Run();
}

uint64_t AssembleAndHash(Fn &f, Mach &m) {
  uint32_t pc = 4; // program header: resource descriptor
  for (MBlock &mb : m.blocks) {
    mb.offset = pc;
    for (uint32_t i = mb.start; i < mb.end; ++i) pc += Words(m.code[i]);
  }
  m.bytes.resize((size_t)pc * 4 + 16);
  uint32_t *buf = reinterpret_cast<uint32_t *>(m.bytes.data()), *out = buf;
  // SPI_SHADER_PGM_RSRC1/2-like header: register counts, shader statistics.
  *out++ = ((m.vgprs + 3) / 4) | ((m.sgprs + 7) / 8) << 6 | 0xC0u << 12;
  *out++ = (uint32_t)m.code.size() | f.info.stores << 20;
  *out++ = f.info.phis | f.info.divergent << 16;
  *out++ = (uint32_t)f.info.inputsRead ^ (uint32_t)(f.info.inputsRead >> 32);
  for (const MBlock &mb : m.blocks) {
    for (uint32_t i = mb.start; i < mb.end; ++i) {
      const Ctx c{m, (uint32_t)(out - buf)};
      out = kEncode[m.code[i].op](m.code[i], out, c);
    }
  }
  const size_t words = (size_t)(out - buf);
  f.st.emittedBytes += words * 4;
  f.st.sgprPeak = std::max<uint64_t>(f.st.sgprPeak, m.sgprs);
  f.st.vgprPeak = std::max<uint64_t>(f.st.vgprPeak, m.vgprs);
  uint64_t h = 0x243F6A8885A308D3ull ^ words;
  for (size_t k = 0; k + 1 < words; k += 2)
    h = Rotl64(h ^ ((uint64_t)buf[k] | (uint64_t)buf[k + 1] << 32), 29) * 0x9E3779B97F4A7C15ull;
  if (words & 1) h = (h ^ buf[words - 1]) * 0x100000001b3ull;
  return h;
}
} // namespace simv5

// Self-test of the machine back end on hand-built code (no workload run):
// returns a bit per failed check.
uint32_t RunRealisticCompilerSimV5MachineTest() {
  using namespace simv5;
  Mach m;
  Fn f;
  f.info = {};
  auto inst = [&](uint32_t op, uint32_t d, uint32_t s0, uint32_t s1) {
    MInst mi;
    std::memset(&mi, 0, sizeof(mi));
    mi.op = (uint16_t)op;
    mi.defs[0] = d == kNone ? kONone : kOFixed | d;
    mi.defs[1] = kONone;
    mi.ops[0] = s0 == kNone ? kONone : kOFixed | s0;
    mi.ops[1] = s1 == kNone ? kONone : kOFixed | s1;
    mi.ops[2] = mi.ops[3] = kONone;
    mi.ndefs = d != kNone;
    mi.nops = (uint8_t)((s0 != kNone) + (s1 != kNone));
    mi.pdef[0] = (uint16_t)(d == kNone ? 0 : d);
    mi.pop[0] = (uint16_t)(s0 == kNone ? 0 : s0);
    mi.pop[1] = (uint16_t)(s1 == kNone ? 0 : s1);
    mi.node = mi.aux = kNone;
    m.code.push_back(mi);
  };
  const uint32_t v = kRegVgpr;
  inst(m_buffer_load_dword, v + 1, v + 4, 8);    // v1 <- load (vaddr v4, rsrc s[8:11])
  inst(m_v_add_f32, v + 6, v + 2, v + 3);         // VOP2: 0x020C0702 (no wait: v1 untouched)
  inst(m_v_add_f32, v + 5, v + 1, v + 3);         // reads v1: needs vmcnt(0)
  m.code.back().mods = 1;                         // neg src0 -> VOP3
  inst(m_s_endpgm, kNone, kNone, kNone);
  MBlock b{};
  b.ir = 0;
  b.start = 0;
  b.term = 3;
  b.end = 4;
  b.succ[0] = b.succ[1] = kNone;
  m.blocks.push_back(b);
  m.temps.clear();
  uint32_t fail = 0;
  InsertWaitcnt(f, m);
  if (m.code.size() != 5 || m.code[2].op != m_s_waitcnt || m.code[2].imm != 0xF70) fail |= 1;
  AssembleAndHash(f, m);
  const uint32_t *w = reinterpret_cast<const uint32_t *>(m.bytes.data()) + 4; // after the header
  if (w[0] != 0xE0500000u || w[2] != 0x020C0702u) fail |= 2;                 // MUBUF, VOP2
  if (w[3] != 0xBF8C0F70u) fail |= 4;                                         // s_waitcnt vmcnt(0)
  if (w[4] != 0xD1010005u || w[5] != (1u << 29 | 0x103u << 9 | 0x101u)) fail |= 8; // VOP3 v_add_f32 -v1
  if (w[6] != 0xBF810000u) fail |= 16;                                        // s_endpgm
  return fail;
}
