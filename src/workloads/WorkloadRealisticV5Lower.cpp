// WorkloadRealisticV5Lower.cpp - Realistic V5 lowering, as in Mesa drivers:
// nir_shader_instructions_pass-style passes, each a full walk of every block's
// instruction list with a filter and a real rewrite. Early (before the
// optimization loop): I/O to interpolation / exports, resource handles to
// descriptor loads, constant-buffer and SSBO addressing, fsub(-0, x) to fneg,
// division by constants (magic numbers), fdiv to rcp. Late: offset folding,
// ffma fusion, load vectorization, sinking, comparison motion, source
// modifiers. Then divergence analysis and gather_info; ValidateIr checks the
// IR invariants in diagnostic runs.
#include "workloads/WorkloadRealisticV5.h"
#ifdef SIMV5_VALIDATE_TRACE
#include <cstdio>
#include <vector>
#define SIMV5_TRACE(...) std::fprintf(stderr, __VA_ARGS__)
#else
#define SIMV5_TRACE(...) ((void)0)
#endif

namespace simv5 {
namespace {
// Source modifiers in Node::imm of float ALU instructions (ACO-style).
constexpr uint32_t kModNeg = 1, kModAbs = 8; // << operand slot

template <class Body> inline void ForEachInst(Fn &f, Body &&body) {
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    for (uint32_t i = f.blocks[b].head; i != kNone;) {
      const uint32_t next = f.nodes[i].next; // body may rewrite or move the node
      if (IsInst(f.nodes[i])) body(i, f.nodes[i]);
      i = next;
    }
  }
}
inline bool IsC(const Fn &f, uint32_t v) { return v != kNone && IsConst(f.nodes[v]); }
inline uint32_t CU(const Fn &f, uint32_t v) { return (uint32_t)f.nodes[v].val; }
inline uint32_t C32(Fn &f, uint32_t v) { return GetConst(f, kI32, v); }

// In-place opcode change keeping the operands (lowering to driver intrinsics).
inline void Relabel(Fn &f, Node &n, uint32_t op) {
  n.op = (n.op & ~kOpMask) | op;
  f.st.lowered++;
}
// New instruction placed before `before` (kNone when out of node slots).
uint32_t Emit(Fn &f, uint32_t before, uint32_t op, uint32_t type, uint32_t a, uint32_t b = kNone, uint32_t c = kNone) {
  const uint32_t i = NewNode(f, op, type, a, b, c);
  if (i != kNone) InsertBefore(f, i, before);
  return i;
}
inline void RewriteOperands(Fn &f, uint32_t i, uint32_t op, uint32_t a, uint32_t b, uint32_t c, uint32_t imm) {
  DropOperands(f, i);
  Node &n = f.nodes[i];
  n.op = (n.op & ~kOpMask) | op;
  n.a = a;
  n.b = b;
  n.c = c;
  n.imm = imm;
  for (uint32_t k = 0; k < Arity(op); ++k) AddUse(f, i, k, Operand(n, k));
  f.st.lowered++;
}

// nir_lower_io + descriptor lowering: inputs become interpolation, outputs
// exports, resource handles descriptor-table loads, texture ops image ops.
void LowerIoAndResources(Fn &f) {
  ForEachInst(f, [&](uint32_t, Node &n) {
    switch (OpOf(n)) {
    case kLoadInput: Relabel(f, n, kInterp); break;
    case kStoreOutput: Relabel(f, n, kExport); break;
    case kCreateHandle: Relabel(f, n, kDescLoad); break;
    case kSample: Relabel(f, n, kImageSample); break;
    case kTextureLoad: Relabel(f, n, kImageLoad); break;
    default: break;
    }
  });
}

// Constant buffers: extractvalue(cbufferLoadLegacy(h, reg), c) -> load_ubo(h,
// reg * 16 + c * 4); the legacy aggregate load dies.
void LowerConstantBuffers(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    if (OpOf(n) != kExtract) return;
    const Node &agg = f.nodes[n.a];
    if (!IsInst(agg) || OpOf(agg) != kCBufferLoad) return;
    const uint32_t h = agg.a, reg = agg.b, comp = n.imm * 4;
    uint32_t off;
    if (IsC(f, reg)) off = C32(f, CU(f, reg) * 16 + comp);
    else off = Emit(f, i, kIMad, kI32, reg, C32(f, 16), C32(f, comp));
    if (off == kNone) return;
    RewriteOperands(f, i, kLoadUbo, h, off, kNone, 0);
  });
}

// SSBOs: buffer element index -> byte address (16-byte elements).
void LowerBuffers(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    const uint32_t op = OpOf(n);
    if (op != kBufferLoad && op != kBufferStore) return;
    const uint32_t addr = Emit(f, i, kShl, kI32, n.b, C32(f, 4));
    if (addr == kNone) return;
    RewriteOperands(f, i, op == kBufferLoad ? kLoadSsbo : kStoreSsbo, n.a, addr, n.c, 0);
  });
}

// DXC negates with fsub(-0.0, x).
void LowerFsubToFneg(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    if (OpOf(n) != kFSub || !IsC(f, n.a) || (CU(f, n.a) & 0x7FFFFFFFu) != 0) return;
    RewriteOperands(f, i, kFNeg, n.b, kNone, kNone, 0);
  });
}

// nir_opt_idiv_const: unsigned division / remainder by a constant via a
// multiply-high with a Granlund-Montgomery magic number:
// q = (t + ((x - t) >> 1)) >> (l - 1), t = umulhi(x, m), m = 2^32 (2^l - d) / d + 1.
void LowerDivByConst(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    const uint32_t op = OpOf(n);
    if ((op != kUDiv && op != kURem) || !IsC(f, n.b)) return;
    const uint32_t d = CU(f, n.b), x = n.a;
    if (d < 2 || !(d & (d - 1))) return; // 0, 1 and powers of two: algebraic rules
    const uint32_t l = 32 - (uint32_t)std::countl_zero(d - 1);
    const uint32_t m = (uint32_t)((((uint64_t)1 << 32) * (((uint64_t)1 << l) - d)) / d + 1);
    const uint32_t t = Emit(f, i, kUMulHi, kI32, x, C32(f, m));
    const uint32_t diff = t == kNone ? kNone : Emit(f, i, kISub, kI32, x, t);
    const uint32_t half = diff == kNone ? kNone : Emit(f, i, kLShr, kI32, diff, C32(f, 1));
    const uint32_t sum = half == kNone ? kNone : Emit(f, i, kIAdd, kI32, t, half);
    if (sum == kNone) return;
    if (op == kUDiv) {
      RewriteOperands(f, i, kLShr, sum, C32(f, l - 1), kNone, 0);
      return;
    }
    const uint32_t q = Emit(f, i, kLShr, kI32, sum, C32(f, l - 1));
    const uint32_t qd = q == kNone ? kNone : Emit(f, i, kIMul, kI32, q, n.b);
    if (qd != kNone) RewriteOperands(f, i, kISub, x, qd, kNone, 0);
  });
}

// No hardware divide: x / y -> x * rcp(y); exact power-of-two divisors
// become a multiply by the exact reciprocal.
void LowerFdiv(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    if (OpOf(n) != kFDiv) return;
    if (IsC(f, n.b)) {
      const uint32_t bits = CU(f, n.b), e = (bits >> 23) & 0xFF;
      if ((bits & 0x7FFFFFu) == 0 && e > 1 && e < 253) { // exact reciprocal
        const uint32_t r = GetConst(f, kF32, (bits & 0x80000000u) | ((254 - e) << 23));
        if (r != kNone) RewriteOperands(f, i, kFMul, n.a, r, kNone, 0);
        return;
      }
    }
    const uint32_t r = Emit(f, i, kRcp, kF32, n.b);
    if (r != kNone) RewriteOperands(f, i, kFMul, n.a, r, kNone, 0);
  });
}

// nir_opt_offsets: constant address adds fold into the immediate offset.
void OptOffsets(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    const uint32_t op = OpOf(n);
    if (op != kLoadUbo && op != kLoadSsbo && op != kStoreSsbo) return;
    const Node &addr = f.nodes[n.b];
    if (!IsInst(addr) || OpOf(addr) != kIAdd || !IsC(f, addr.b) || n.imm + CU(f, addr.b) >= 4096) return;
    n.imm += CU(f, addr.b);
    SetOperand(f, i, 1, addr.a);
    f.st.lowered++;
  });
}

// nir_opt_algebraic late: fadd(fmul(a, b), c) -> ffma when the product has no
// other use.
void FuseFfma(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    if (OpOf(n) != kFAdd) return;
    for (uint32_t k = 0; k < 2; ++k) {
      const uint32_t m = Operand(n, k);
      const Node &mul = f.nodes[m];
      if (!IsInst(mul) || OpOf(mul) != kFMul || mul.numUses != 1 || mul.imm) continue;
      const uint32_t other = Operand(n, 1 - k), a = mul.a, b = mul.b;
      RewriteOperands(f, i, kFMad, a, b, other, 0);
      return;
    }
  });
}

// nir_opt_load_store_vectorize: scalar UBO loads of one 16-byte row with
// constant offsets merge into one vec4 load plus component extracts.
void VectorizeLoads(Fn &f) {
  struct Row {
    uint32_t handle, base, first, wide;
  };
  Row rows[16];
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    uint32_t nrows = 0;
    for (uint32_t i = f.blocks[b].head, next; i != kNone; i = next) {
      next = f.nodes[i].next;
      const Node &n = f.nodes[i];
      if (!IsInst(n) || OpOf(n) != kLoadUbo || !IsC(f, n.b)) continue;
      const uint32_t off = CU(f, n.b) + n.imm, base = off & ~15u;
      uint32_t r = 0;
      while (r < nrows && (rows[r].handle != n.a || rows[r].base != base)) ++r;
      if (r == nrows) { // first load of this row: remember it, vectorize on the second
        if (nrows == 16) nrows = 0;
        rows[nrows++] = {n.a, base, i, kNone};
        continue;
      }
      if (rows[r].wide == kNone) { // the vec4 load replaces the row's first load too
        const uint32_t first = rows[r].first, base4 = C32(f, base);
        const uint32_t w = base4 == kNone ? kNone : Emit(f, first, kLoadUboX4, kResRetF32, n.a, base4);
        if (w == kNone) continue;
        rows[r].wide = w;
        const Node &fl = f.nodes[first];
        RewriteOperands(f, first, kExtract, w, kNone, kNone, ((CU(f, fl.b) + fl.imm) & 15) / 4);
      }
      RewriteOperands(f, i, kExtract, rows[r].wide, kNone, kNone, (off & 15) / 4);
    }
  }
}

// nir_opt_sink: cheap loads move down to just before their first user when
// every user is in the same block (shorter live ranges).
void SinkLoads(Fn &f) {
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    uint32_t k = 0;
    for (uint32_t i = f.blocks[b].head; i != kNone; i = f.nodes[i].next) f.nodes[i].pos = k++;
    for (uint32_t i = f.blocks[b].head, next; i != kNone; i = next) {
      next = f.nodes[i].next;
      const Node &n = f.nodes[i];
      if (!IsInst(n) || (OpOf(n) != kInterp && OpOf(n) != kLoadUbo && OpOf(n) != kDescLoad) || !n.numUses) continue;
      uint32_t first = kNone, firstPos = kNone;
      bool local = true;
      for (uint32_t u = n.firstUse; u != kNone; u = f.UseNext(u)) {
        const Node &user = f.nodes[UseUser(u)];
        if (user.block != b || IsPhi(user)) {
          local = false;
          break;
        }
        if (user.pos < firstPos) {
          firstPos = user.pos;
          first = UseUser(u);
        }
      }
      if (!local || first == next || firstPos <= n.pos) continue;
      Unlink(f, i);
      InsertBefore(f, i, first);
      f.nodes[i].pos = firstPos; // keeps relative order for later candidates
      f.st.lowered++;
    }
  }
}

// nir_opt_move (comparisons): a branch condition computed in its block moves
// right before the terminator, next to its single use.
void MoveComparisons(Fn &f) {
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    const uint32_t c = f.blocks[b].cond;
    if (c == kNone || IsConst(f.nodes[c])) continue;
    Node &n = f.nodes[c];
    if (!IsInst(n) || n.block != b || n.numUses != 0 || n.next == kNone) continue;
    uint32_t tail = n.next;
    while (f.nodes[tail].next != kNone) tail = f.nodes[tail].next;
    Unlink(f, c);
    Node &t = f.nodes[tail];
    n.block = b;
    n.prev = tail;
    n.next = kNone;
    t.next = c;
    f.st.lowered++;
  }
}

// ACO-style source modifiers: fneg / fabs feeding float ALU instructions
// become modifier bits of the user's operand; the negation dies.
void FoldSourceModifiers(Fn &f) {
  ForEachInst(f, [&](uint32_t i, Node &n) {
    const uint32_t op = OpOf(n);
    if (op != kFAdd && op != kFMul && op != kFMad && op != kFMin && op != kFMax && op != kSaturate) return;
    for (uint32_t k = 0; k < Arity(op); ++k) {
      const Node &src = f.nodes[Operand(n, k)];
      if (!IsInst(src) || (OpOf(src) != kFNeg && OpOf(src) != kFAbs)) continue;
      const uint32_t inner = src.a, mod = (OpOf(src) == kFNeg ? kModNeg : kModAbs) << k;
      if (n.imm & ((kModNeg | kModAbs) << k)) continue;
      n.imm |= mod;
      SetOperand(f, i, k, inner);
      f.st.lowered++;
    }
  });
}

inline bool Divergent(const Fn &f, uint32_t v) {
  return v != kNone && (f.nodes[v].op & kDivergentFlag) != 0;
}
} // namespace

void RunEarlyLowering(Fn &f) {
  LowerIoAndResources(f);
  LowerConstantBuffers(f);
  LowerBuffers(f);
  LowerFsubToFneg(f);
  LowerDivByConst(f);
  LowerFdiv(f);
}

void RunLateLowering(Fn &f) {
#ifdef SIMV5_VALIDATE_TRACE
#define SIMV5_STEP(pass) pass(f); if (f.diag && ValidateIr(f)) SIMV5_TRACE("validate: after %s%c", #pass, 10);
#else
#define SIMV5_STEP(pass) pass(f);
#endif
  SIMV5_STEP(OptOffsets)
  SIMV5_STEP(FuseFfma)
  SIMV5_STEP(VectorizeLoads)
  SIMV5_STEP(SinkLoads)
  SIMV5_STEP(MoveComparisons)
  SIMV5_STEP(FoldSourceModifiers)
#undef SIMV5_STEP
}

// nir_divergence_analysis: interpolated inputs and thread ids are divergent,
// constants and uniform-buffer / descriptor loads with uniform operands
// uniform; values and phis inherit divergence from their operands, phis also
// from a divergent branch at their block's dominator. Forward sweeps in
// reverse post order until loops reach a fixed point.
void RunDivergence(Fn &f) {
  for (bool changed = true; changed;) {
    changed = false;
    f.st.divIters++;
    for (uint32_t k = 0; k < f.nrpo; ++k) {
      const uint32_t b = f.rpoOrder[k];
      const uint32_t cond = b ? f.blocks[f.blocks[b].idom].cond : kNone;
      const bool divergentJoin = Divergent(f, cond);
      for (uint32_t i = f.blocks[b].head; i != kNone; i = f.nodes[i].next) {
        Node &n = f.nodes[i];
        if (n.op & kDivergentFlag) continue;
        bool d;
        if (IsPhi(n)) d = divergentJoin || Divergent(f, n.a) || Divergent(f, n.b);
        else if (HasFlag(OpOf(n), kDivSource)) d = true;
        else {
          d = false;
          for (uint32_t s = 0, e = NumOperands(n); s < e; ++s) d |= Divergent(f, Operand(n, s));
        }
        if (d) {
          n.op |= kDivergentFlag;
          changed = true;
        }
      }
    }
  }
}

void GatherInfo(Fn &f) {
  ShaderInfo info{};
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    for (uint32_t i = f.blocks[b].head; i != kNone; i = f.nodes[i].next) {
      const Node &n = f.nodes[i];
      if (IsPhi(n)) {
        info.phis++;
        continue;
      }
      const uint32_t op = OpOf(n);
      info.unitCount[UnitOf(op)]++;
      if ((op == kInterp || op == kLoadInput) && IsC(f, n.a)) info.inputsRead |= 1ull << (CU(f, n.a) * 4 + CU(f, n.b) & 63);
      if (IsStoreOp(op)) info.stores++;
      else if (n.op & kDivergentFlag) info.divergent++;
      else info.uniform++;
    }
  }
  f.info = info;
  f.st.uniform += info.uniform;
}

// nir_validate-style consistency check (diagnostics and --self-test only):
// every operand of a live instruction is exactly one entry in its value's
// doubly linked use list, numUses matches, and each block's instruction list
// links back correctly and holds every live non-constant node once, and the
// constant map refers only to live constants.
// -DSIMV5_VALIDATE_TRACE prints each finding to stderr.
uint32_t ValidateIr(const Fn &f) {
  uint32_t errors = 0;
  uint64_t listedUses = 0, operandSlots = 0, listed = 0, liveInsts = 0;
  for (uint32_t v = 0; v < f.n; ++v) {
    const Node &d = f.nodes[v];
    uint32_t count = 0, prev = kNone;
    for (uint32_t u = d.firstUse; u != kNone && count <= 3 * f.n; u = f.nodes[UseUser(u)].useNext[u & 3]) {
      const Node &user = f.nodes[UseUser(u)];
      if (user.usePrev[u & 3] != prev || IsDead(user) || (u & 3) >= NumOperands(user) ||
          Operand(user, u & 3) != v) {
        errors++;
        SIMV5_TRACE("use: value %u use %u user op %08x prev %u (expected %u) operands %u,%u,%u\n", v,
                    u, user.op, user.usePrev[u & 3], prev, user.a, user.b, user.c);
      }
      prev = u;
      count++;
    }
    if (count != d.numUses) {
      errors++;
      SIMV5_TRACE("numUses: value %u listed %u counted %u op %08x\n", v, count, d.numUses, d.op);
    }
    listedUses += count;
    if (!IsDead(d)) {
      operandSlots += NumOperands(d);
      if (!IsConst(d)) liveInsts++;
    }
  }
  if (listedUses != operandSlots) {
    errors++;
    SIMV5_TRACE("uses: %llu listed, %llu operand slots\n", (unsigned long long)listedUses,
                (unsigned long long)operandSlots);
  }
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    uint32_t prev = kNone;
    for (uint32_t i = f.blocks[b].head; i != kNone && listed <= f.n; i = f.nodes[i].next) {
      const Node &n = f.nodes[i];
      if (n.prev != prev || n.block != b || (n.op & (kDeadFlag | kConstFlag))) {
        errors++;
        SIMV5_TRACE("list: block %u node %u prev %u (expected %u) parent %u op %08x\n", b, i, n.prev,
                    prev, n.block, n.op);
      }
      prev = i;
      listed++;
    }
  }
  // Constant uniquing: every map entry is a live constant with the entry's key
  // (a freed constant slot would be handed out twice: by GetConst and NewNode).
  for (uint32_t s = 0; s < f.consts.size; ++s) {
    if (f.consts.keys[s] == DenseMap::kEmpty) continue;
    const uint32_t v = f.consts.vals[s];
    if (v >= f.n || !IsConst(f.nodes[v]) || IsDead(f.nodes[v]) ||
        f.consts.keys[s] != (((uint64_t)f.nodes[v].type << 32) | (uint32_t)f.nodes[v].val)) {
      errors++;
      SIMV5_TRACE("const: map slot %u -> node %u op %08x%c", s, v, v < f.n ? f.nodes[v].op : 0u, 10);
    }
  }
  if (listed != liveInsts) {
    errors++;
#ifdef SIMV5_VALIDATE_TRACE
    std::vector<uint8_t> inList(f.n, 0);
    for (uint32_t b = 0; b < f.nblocks; ++b)
      for (uint32_t i = f.blocks[b].head; i != kNone; i = f.nodes[i].next) inList[i] = 1;
    for (uint32_t v = 0; v < f.n; ++v)
      if (!inList[v] && !(f.nodes[v].op & (kDeadFlag | kConstFlag)))
        SIMV5_TRACE("list: node %u op %08x block %u prev %u next %u uses %u not listed%c", v, f.nodes[v].op,
                    f.nodes[v].block, f.nodes[v].prev, f.nodes[v].next, f.nodes[v].numUses, 10);
#endif
    SIMV5_TRACE("list: %llu listed, %llu live instructions\n", (unsigned long long)listed,
                (unsigned long long)liveInsts);
  }
  return errors;
}
} // namespace simv5
