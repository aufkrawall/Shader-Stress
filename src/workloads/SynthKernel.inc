// SynthKernel.inc - ISA-generic synthetic power kernel body.
//
// Included inside a kernel function body after defining:
//   SK_VEC              vector type
//   SK_W                doubles per vector
//   SK_LOAD(p)          aligned load of SK_W doubles
//   SK_STORE(p, v)      aligned store
//   SK_SET1(x)          broadcast
//   SK_MUL(a, b)        a * b
//   SK_ADD(a, b)        a + b
//   SK_SUB(a, b)        a - b
//   SK_FMADD(a, b, c)   a * b + c   (fused on FMA ISAs, mul+add otherwise)
//   SK_FNMADD(a, b, c)  c - a * b
//   SK_BLOCKS           radix-4 blocks per complexity unit
// with `seed`, `complexity` and `diag` (KernelDiag*) in scope. The body
// `return`s the job checksum.
//
// Data layout: complex vectors in AoSoA form — vector j occupies
// buf[j*2W .. j*2W+W) (real parts) and buf[j*2W+W .. j*2W+2W) (imag parts).
// Every pass visits each vector exactly once in radix-4 blocks
// {j, j+s, j+2s, j+3s}; the stride s cycles through 1, 4, 16, 64 so data mixes
// across the buffer like the stages of a radix-4 FFT. Each block is loaded,
// pushed through SYNTH_ROUNDS rounds of 4 butterflies in registers, and
// stored back (store-every-result).
{
  double *const buf = GetSynthBuffer();
  constexpr size_t kVecs = SYNTH_BUF_DOUBLES / (2 * SK_W);
  static_assert(kVecs % 256 == 0, "buffer must hold a multiple of 256 vectors");

  SynthFill(buf, SYNTH_BUF_DOUBLES, seed);
  if (diag) diag->energyIn = SynthEnergy(buf, SYNTH_BUF_DOUBLES);

  const SK_VEC wr = SK_SET1(SYNTH_TW_RE);
  const SK_VEC wi = SK_SET1(SYNTH_TW_IM);
  const SK_VEC kk = SK_SET1(SYNTH_SCALE);

  // Integer side: eight live states; four multiply/rotate/xor chains, three
  // additions and one 64-bit divide per block. Independent of the FP data, so
  // a fault in either cluster changes the checksum.
  uint64_t g0 = Mix64(seed ^ 0x01), g1 = Mix64(seed ^ 0x02);
  uint64_t g2 = Mix64(seed ^ 0x03), g3 = Mix64(seed ^ 0x04);
  uint64_t g4 = Mix64(seed ^ 0x05), g5 = Mix64(seed ^ 0x06);
  uint64_t g6 = Mix64(seed ^ 0x07), g7 = Mix64(seed ^ 0x08);

  // Butterfly with twiddle w:      (x, y) -> (k*x + w*y,  w*y - k*x)
  // Butterfly with twiddle conj(w):(x, y) -> (k*x + w'*y, w'*y - k*x)
  // Unfused k*x multiply + add/sub exercises Zen 3 FADD pipes (FP2/FP3)
  // in parallel with FMA/MUL (FP0/FP1).
#define SK_BFLY(xr, xi, yr, yi)                                               \
  do {                                                                        \
    SK_VEC p_ = SK_MUL(wr, yr), q_ = SK_MUL(wr, yi);                          \
    SK_VEC tr_ = SK_FNMADD(wi, yi, p_); /* wr*yr - wi*yi */                   \
    SK_VEC ti_ = SK_FMADD(wi, yr, q_);  /* wr*yi + wi*yr */                   \
    SK_VEC kxr_ = SK_MUL(xr, kk), kxi_ = SK_MUL(xi, kk);                      \
    SK_VEC nr_ = SK_ADD(kxr_, tr_);                                           \
    yr = SK_SUB(tr_, kxr_);                                                   \
    xr = nr_;                                                                 \
    SK_VEC ni_ = SK_ADD(kxi_, ti_);                                           \
    yi = SK_SUB(ti_, kxi_);                                                   \
    xi = ni_;                                                                 \
  } while (0)
#define SK_BFLY_CONJ(xr, xi, yr, yi)                                          \
  do {                                                                        \
    SK_VEC p_ = SK_MUL(wr, yr), q_ = SK_MUL(wr, yi);                          \
    SK_VEC tr_ = SK_FMADD(wi, yi, p_);  /* wr*yr + wi*yi */                   \
    SK_VEC ti_ = SK_FNMADD(wi, yr, q_); /* wr*yi - wi*yr */                   \
    SK_VEC kxr_ = SK_MUL(xr, kk), kxi_ = SK_MUL(xi, kk);                      \
    SK_VEC nr_ = SK_ADD(kxr_, tr_);                                           \
    yr = SK_SUB(tr_, kxr_);                                                   \
    xr = nr_;                                                                 \
    SK_VEC ni_ = SK_ADD(kxi_, ti_);                                           \
    yi = SK_SUB(ti_, kxi_);                                                   \
    xi = ni_;                                                                 \
  } while (0)

  const uint64_t budget =
      (uint64_t)std::clamp(complexity, 1, MAX_JOB_COMPLEXITY) * (uint64_t)(SK_BLOCKS);
  uint64_t blocks = 0;
  unsigned strideSel = (unsigned)(seed & 3u);
  bool aborted = false;

  while (blocks < budget) {
    if (StopRequested()) [[unlikely]] {
      aborted = true;
      break;
    }
    const size_t s = (size_t)1 << (2u * strideSel); // 1, 4, 16, 64 vectors
    strideSel = (strideSel + 1u) & 3u;
    for (size_t base = 0; base < kVecs; base += 4 * s) {
#if defined(_MSC_VER) && !defined(__clang__)
      // SIMD is explicit; retain the integer network on the integer side.
#pragma loop(no_vector)
#endif
      for (size_t j = base; j < base + s; ++j) {
        double *pa = buf + (j) * 2 * SK_W;
        double *pb = buf + (j + s) * 2 * SK_W;
        double *pc = buf + (j + 2 * s) * 2 * SK_W;
        double *pd = buf + (j + 3 * s) * 2 * SK_W;
        SK_VEC ar = SK_LOAD(pa), ai = SK_LOAD(pa + SK_W);
        SK_VEC br = SK_LOAD(pb), bi = SK_LOAD(pb + SK_W);
        SK_VEC cr = SK_LOAD(pc), ci = SK_LOAD(pc + SK_W);
        SK_VEC dr = SK_LOAD(pd), di = SK_LOAD(pd + SK_W);
        for (int r = 0; r < SYNTH_ROUNDS; ++r) {
          SK_BFLY(ar, ai, cr, ci);
          SK_BFLY(br, bi, dr, di);
          SK_BFLY_CONJ(ar, ai, br, bi);
          SK_BFLY_CONJ(cr, ci, dr, di);
        }
        SK_STORE(pa, ar); SK_STORE(pa + SK_W, ai);
        SK_STORE(pb, br); SK_STORE(pb + SK_W, bi);
        SK_STORE(pc, cr); SK_STORE(pc + SK_W, ci);
        SK_STORE(pd, dr); SK_STORE(pd + SK_W, di);

        // Idle load/store fill: swap the real/imag halves of two vectors half
        // a buffer away. A second data cursor streams through the L2/L3 side
        // of the buffer at zero ALU cost (swaps are register moves only), so
        // every block pushes more cache traffic per butterfly work. Swaps are
        // memory-observable (the checksum reads every position), deterministic
        // and entropy-preserving. Measured +3.2 W avx2 / +1.0 W scalar on the
        // 5700X (P045): package power tracks the cache-traffic rate, and this
        // raises bytes/block ~50% for ~6% more instructions.
        {
          size_t jf;
          if constexpr ((kVecs & (kVecs - 1)) == 0)
            jf = j ^ (kVecs / 2);
          else
            jf = SynthFarVector(j, kVecs);
          double *pf = buf + jf * 2 * SK_W;
          double *pg = buf + (jf ^ (size_t)1) * 2 * SK_W;
          SK_VEC t1_ = SK_LOAD(pf), t2_ = SK_LOAD(pf + SK_W);
          SK_STORE(pf, t2_); SK_STORE(pf + SK_W, t1_);
          t1_ = SK_LOAD(pg); t2_ = SK_LOAD(pg + SK_W);
          SK_STORE(pg, t2_); SK_STORE(pg + SK_W, t1_);
        }

        g0 = Rotl64(g0 * 0x9E3779B97F4A7C15ull, 29) ^ g4;
        g1 = Rotl64(g1 * 0xBF58476D1CE4E5B9ull, 31) ^ g5;
        g2 = Rotl64(g2 * 0x94D049BB133111EBull, 27) ^ g6;
        g3 = Rotl64(g3 * 0xD6E8FEB86659FD93ull, 33) ^ g7;
        g4 += g1;
        g5 += g2;
        g6 += g3;
        g7 ^= g5 / ((g0 >> 31) | 0x100000001ull);
      }
    }
    blocks += kVecs / 4;
  }
#undef SK_BFLY
#undef SK_BFLY_CONJ

  const uint64_t g[8] = {g0, g1, g2, g3, g4, g5, g6, g7};
  if (diag) {
    diag->blocks = blocks;
    diag->aborted = aborted;
    SynthFinishDiag(buf, SYNTH_BUF_DOUBLES, diag);
  }
  return SynthChecksum(buf, SYNTH_BUF_DOUBLES, g);
}
