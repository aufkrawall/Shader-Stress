// SynthKernelsX86.cpp - AVX2/FMA and AVX-512 synthetic power kernels.
// Clang/GCC compile them via function target attributes, so the baseline
// binary still dispatches to them at runtime. MSVC (v3 build only) compiles
// this file with /arch:AVX2 and emits the explicit AVX-512 intrinsics as is.
#include "workloads/Workloads.h"

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>

#if defined(_MSC_VER) && !defined(__clang__)
#define TARGET_AVX2 __declspec(noinline)
#define TARGET_AVX512 __declspec(noinline)
#else
#define TARGET_AVX2 __attribute__((target("avx2,fma"), hot, noinline))
#if defined(__clang__) && __clang_major__ >= 22
#define TARGET_AVX512 __attribute__((target("avx512f"), hot, noinline))
#else
#define TARGET_AVX512 __attribute__((target("avx512f,evex512"), hot, noinline))
#endif
#endif

TARGET_AVX2
uint64_t SynthKernelAVX2(uint64_t seed, int complexity, KernelDiag *diag) {
#if defined(__clang__)
#pragma clang fp contract(off)
#endif
#define SK_VEC __m256d
#define SK_W 4
#define SK_LOAD(p) _mm256_load_pd(p)
#define SK_STORE(p, v) _mm256_store_pd((p), (v))
#define SK_SET1(x) _mm256_set1_pd(x)
#define SK_MUL(a, b) _mm256_mul_pd((a), (b))
#define SK_FMADD(a, b, c) _mm256_fmadd_pd((a), (b), (c))
#define SK_FNMADD(a, b, c) _mm256_fnmadd_pd((a), (b), (c))
#define SK_BLOCKS SYNTH_BLOCKS_AVX2
#include "SynthKernel.inc"
#undef SK_VEC
#undef SK_W
#undef SK_LOAD
#undef SK_STORE
#undef SK_SET1
#undef SK_MUL
#undef SK_FMADD
#undef SK_FNMADD
#undef SK_BLOCKS
}

#if !defined(PLATFORM_MACOS)
TARGET_AVX512
uint64_t SynthKernelAVX512(uint64_t seed, int complexity, KernelDiag *diag) {
#if defined(__clang__)
#pragma clang fp contract(off)
#endif
#define SK_VEC __m512d
#define SK_W 8
#define SK_LOAD(p) _mm512_load_pd(p)
#define SK_STORE(p, v) _mm512_store_pd((p), (v))
#define SK_SET1(x) _mm512_set1_pd(x)
#define SK_MUL(a, b) _mm512_mul_pd((a), (b))
#define SK_FMADD(a, b, c) _mm512_fmadd_pd((a), (b), (c))
#define SK_FNMADD(a, b, c) _mm512_fnmadd_pd((a), (b), (c))
#define SK_BLOCKS SYNTH_BLOCKS_AVX512
#include "SynthKernel.inc"
#undef SK_VEC
#undef SK_W
#undef SK_LOAD
#undef SK_STORE
#undef SK_SET1
#undef SK_MUL
#undef SK_FMADD
#undef SK_FNMADD
#undef SK_BLOCKS
}
#else
// macOS x86: AVX-512 path disabled (falls back to AVX2).
uint64_t SynthKernelAVX512(uint64_t seed, int complexity, KernelDiag *diag) {
  return SynthKernelAVX2(seed, complexity, diag);
}
#endif

#else
// Non-x86 targets: the wide kernels are never dispatched (CPU feature flags
// are false); keep the symbols for the shared perf/self-test tables.
uint64_t SynthKernelAVX2(uint64_t seed, int complexity, KernelDiag *diag) {
  return SynthKernel128(seed, complexity, diag);
}
uint64_t SynthKernelAVX512(uint64_t seed, int complexity, KernelDiag *diag) {
  return SynthKernel128(seed, complexity, diag);
}
#endif
