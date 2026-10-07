// WorkloadRealisticV5Replica.h - Code footprint of a production compiler.
//
// Driver compilers execute megabytes of distinct code per pipeline (LLVM,
// ACO and vendor back ends: thousands of pattern handlers, per-opcode
// visitors, encoders), so their passes miss in the instruction cache, op
// cache, branch target buffer and iTLB; front-end width and cache sizes are a
// large part of how CPUs differ on real shader compiles. The V5 model's logic
// is compact (~150 KiB hot), so its hot paths run from kReplicas
// address-distinct copies: the per-opcode visitors and encoders and the
// per-node / per-instruction / per-block workers of instruction selection,
// the machine optimizer and s_waitcnt insertion are templates instantiated
// once per replica, and every basic block uses the replica its index hashes
// to (predictable inside a block, scattered across blocks). Logic and results are identical in
// every replica (golden checksum unchanged); only instruction addresses
// differ, so a pass streams through kReplicas times the code.
// -DSIMV5_CODE_REPLICAS=1 builds the compact form (power / footprint A/B).
#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <utility>

#ifndef SIMV5_CODE_REPLICAS
#define SIMV5_CODE_REPLICAS 8
#endif
#if defined(_MSC_VER) && !defined(__clang__)
// MSVC: /OPT:ICF folds identical replicas (comparison build only).
#define SIMV5_REPLICA_TAG(R) ((void)0)
#else
// Materializes R in a register so identical-code folding can never merge
// replicas (one move per call).
#define SIMV5_REPLICA_TAG(R) __asm__ volatile("" : : "r"(R))
#endif

namespace simv5 {
constexpr uint32_t kReplicas = SIMV5_CODE_REPLICAS;
static_assert(kReplicas >= 1 && kReplicas <= 64 && (kReplicas & (kReplicas - 1)) == 0,
              "code replicas: power of two");
inline uint32_t ReplicaOf(uint32_t key) {
  if constexpr (kReplicas == 1) return 0;
  else return (key * 0x9E3779B1u) >> (32 - std::countr_zero(kReplicas));
}

// Dispatch table over replicas: kTable[R] = &Fn<R> (see the users).
template <class Fp, template <uint32_t> class Pick, uint32_t... R>
constexpr std::array<Fp, sizeof...(R)> ReplicaTable(std::integer_sequence<uint32_t, R...>) {
  return {{Pick<R>::value...}};
}
} // namespace simv5
