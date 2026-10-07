// WorkloadRealisticV5Lower.cpp - Realistic V5 lowering pipeline, as in Mesa
// drivers: many nir_shader_instructions_pass-style passes, each a full walk of
// every block's instruction list with a cheap filter that rejects most
// instructions and a small in-place rewrite for the rest (opcode lowering,
// operand canonicalization, bit-size lowering); then divergence analysis
// (uniform values use scalar encodings) and nir_shader_gather_info.
#include "workloads/WorkloadRealisticV5.h"
#include "workloads/WorkloadRealisticV5Format.h"
#include <array>
#include <utility>
#ifdef SIMV5_VALIDATE_TRACE
#include <cstdio>
#define SIMV5_TRACE(...) std::fprintf(stderr, __VA_ARGS__)
#else
#define SIMV5_TRACE(...) ((void)0)
#endif

namespace simv5 {
namespace {
constexpr uint32_t kMaxLowerPasses = 64; // generated passes (the driver runs a prefix)

template <class Body> inline void ForEachInst(Fn &f, Body &&body) {
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    for (uint32_t i = f.blocks[b].head; i != kNone;) {
      const uint32_t next = f.nodes[i].next; // body may rewrite the node
      body(i, f.nodes[i]);
      i = next;
    }
  }
}

// One generated pass: accepts 1/8 of one opcode family, then rewrites it.
template <uint32_t P> NOINLINE void LowerPass(Fn &f) {
  constexpr uint64_t K = OpConst(P, 0x4C4F);
  constexpr uint32_t fam = (uint32_t)(K & 7), sel = (uint32_t)((K >> 8) & 7), kind = P % 3;
  constexpr uint32_t to = 1 + (uint32_t)((K >> 16) % 15);
  uint64_t hits = 0;
  ForEachInst(f, [&](uint32_t i, Node &n) {
    const uint32_t op = n.op & kOpMask;
    if ((n.op & (kConstFlag | kPhiFlag | kInputFlag)) || Family(op) != fam ||
        ((op >> 4) & 7) != sel || IsStoreOp(op))
      return;
    if constexpr (kind == 0) { // unsupported opcode -> supported one (same arity)
      n.op = (n.op & ~kOpMask) | (op & 0x0Fu) | ((((op >> 4) + to) & 15) << 4);
      hits++;
    } else if constexpr (kind == 1) { // canonical operand order (helps CSE)
      if (IsCommutative(op) && n.a < n.b) {
        SwapOperands(f, i);
        hits++;
      }
    } else { // bit-size lowering: the opcode subset only needs 32 bits
      if (n.type == fmt::kTypeI64) {
        n.type = fmt::kTypeI32;
        hits++;
      }
    }
  });
  f.st.lowered += hits;
}

using PassFn = void (*)(Fn &);
template <uint32_t... I>
constexpr std::array<PassFn, sizeof...(I)> PassTable(std::integer_sequence<uint32_t, I...>) {
  return {{&LowerPass<I>...}};
}
constexpr auto kLower = PassTable(std::make_integer_sequence<uint32_t, kMaxLowerPasses>{});

inline bool Divergent(const Fn &f, uint32_t v) {
  return v != kNone && (f.nodes[v].op & kDivergentFlag) != 0;
}
} // namespace

void RunLowering(Fn &f, uint32_t firstPass, uint32_t endPass) {
  for (uint32_t p = firstPass; p < endPass && p < kMaxLowerPasses; ++p) kLower[p](f);
}

// nir_divergence_analysis: per-lane inputs are divergent, constants and
// uniform-buffer loads uniform; values and phis inherit divergence from their
// operands, phis also from a divergent branch at their block's dominator.
// Forward sweeps in reverse post order until loops reach a fixed point.
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
        if (n.op & (kConstFlag | kDivergentFlag)) continue;
        bool d = false;
        if (IsInput(n)) d = (n.op & 3) == 0; // 1/4: per-lane attributes
        else if (IsPhi(n)) d = divergentJoin || Divergent(f, n.a) || Divergent(f, n.b);
        else
          for (uint32_t s = 0, e = NumOperands(n); s < e; ++s) d |= Divergent(f, Operand(n, s));
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
  ForEachInst(f, [&](uint32_t, const Node &n) {
    if (IsConst(n)) return;
    if (IsInput(n)) info.inputsRead |= 1ull << (n.op & 63);
    else if (IsPhi(n)) info.phis++;
    else if (IsStore(n)) info.stores++;
    else {
      info.famCount[Family(n.op & kOpMask)]++;
      if (n.op & kDivergentFlag) info.divergent++;
      else info.uniform++;
    }
  });
  f.info = info;
  f.st.uniform += info.uniform;
}
} // namespace simv5

namespace simv5 {
// nir_validate-style consistency check (diagnostics and --self-test only):
// every operand of a live instruction is exactly one entry in its value's
// doubly linked use list, numUses matches, and each block's instruction list
// links back correctly and holds every live non-constant node once.
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
  if (listed != liveInsts) {
    errors++;
    SIMV5_TRACE("list: %llu listed, %llu live instructions\n", (unsigned long long)listed,
                (unsigned long long)liveInsts);
  }
  return errors;
}
} // namespace simv5
