// WorkloadRealisticV5Mach.h - Machine IR of the realistic V5 compiler model:
// a GCN (GFX9)-like instruction set as ACO selects it. Instruction selection
// (WorkloadRealisticV5Isel.cpp) turns the IR into machine instructions on
// virtual temporaries (SGPR / VGPR classes, 1-8 dwords), split by the
// divergence analysis into scalar (SALU / SMEM) and vector (VALU / VMEM)
// code. WorkloadRealisticV5Sched.cpp computes the register demand and hoists
// memory loads within the occupancy it allows. WorkloadRealisticV5Ra.cpp
// computes machine liveness, allocates
// registers (linear scan with alignment, precolored inputs, phi affinity) and
// lowers pseudo instructions (phis on split critical edges, parallel copies
// with swap cycles). WorkloadRealisticV5Asm.cpp inserts s_waitcnt from the
// outstanding vmcnt / lgkmcnt / expcnt per register (block dataflow) and
// encodes the program with the real GFX9 instruction formats.
#pragma once
#include "workloads/WorkloadRealisticV5.h"
#include "workloads/WorkloadRealisticV5Alloc.h"
#include <vector>

namespace simv5 {
enum MFmt : uint8_t {
  kFSop2, kFSopk, kFSop1, kFSopc, kFSopp, kFSmem, kFVop2, kFVop1, kFVopc, kFVop3,
  kFVintrp, kFMubuf, kFMimg, kFExp, kFPseudo,
};
enum MFlags : uint16_t {
  kMWScc = 1,     // writes SCC
  kMRScc = 2,     // reads SCC
  kMVmem = 4,     // vector memory (vmcnt)
  kMLgkm = 8,     // scalar memory (lgkmcnt, out of order)
  kMExpCnt = 16,  // export (expcnt)
  kMBranch = 32,  // SOPP branch (simm16 = dword offset)
  kMStore = 64,   // memory store / export: no definition
  kMComm = 128,   // commutative sources 0 / 1
  kMFloat = 256,  // float operation (inline float constants, modifiers)
  kM64 = 512,     // 64-bit scalar operands (lane masks)
  kMRev = 1024,   // "rev" form: sources swapped (v_lshlrev, v_subrev)
};

// X(name, format, opcode in the format, flags)
#define SIMV5_MOPS(X)                                                                     \
  X(s_add_u32, kFSop2, 0, kMWScc | kMComm) X(s_sub_u32, kFSop2, 1, kMWScc)               \
  X(s_min_i32, kFSop2, 6, kMWScc | kMComm) X(s_min_u32, kFSop2, 7, kMWScc | kMComm)      \
  X(s_max_i32, kFSop2, 8, kMWScc | kMComm) X(s_max_u32, kFSop2, 9, kMWScc | kMComm)      \
  X(s_cselect_b32, kFSop2, 10, kMRScc) X(s_cselect_b64, kFSop2, 11, kMRScc | kM64)       \
  X(s_and_b32, kFSop2, 12, kMWScc | kMComm) X(s_and_b64, kFSop2, 13, kMWScc | kMComm | kM64) \
  X(s_or_b32, kFSop2, 14, kMWScc | kMComm) X(s_or_b64, kFSop2, 15, kMWScc | kMComm | kM64) \
  X(s_xor_b32, kFSop2, 16, kMWScc | kMComm) X(s_xor_b64, kFSop2, 17, kMWScc | kMComm | kM64) \
  X(s_andn2_b64, kFSop2, 19, kMWScc | kM64) X(s_lshl_b32, kFSop2, 28, kMWScc)            \
  X(s_lshr_b32, kFSop2, 30, kMWScc) X(s_ashr_i32, kFSop2, 32, kMWScc)                    \
  X(s_mul_i32, kFSop2, 36, kMComm) X(s_bfe_u32, kFSop2, 38, kMWScc)                       \
  X(s_bfe_i32, kFSop2, 39, kMWScc) X(s_mul_hi_u32, kFSop2, 44, kMComm)                   \
  X(s_mul_hi_i32, kFSop2, 45, kMComm) X(s_movk_i32, kFSopk, 0, 0)                         \
  X(s_mov_b32, kFSop1, 0, 0) X(s_mov_b64, kFSop1, 1, kM64) X(s_not_b32, kFSop1, 4, kMWScc) \
  X(s_brev_b32, kFSop1, 8, 0) X(s_bcnt1_i32_b32, kFSop1, 12, kMWScc)                     \
  X(s_ff1_i32_b32, kFSop1, 16, 0) X(s_flbit_i32_b32, kFSop1, 21, 0)                       \
  X(s_and_saveexec_b64, kFSop1, 32, kMWScc | kM64) X(s_or_saveexec_b64, kFSop1, 33, kMWScc | kM64) \
  X(s_cmp_eq_i32, kFSopc, 0, kMWScc | kMComm) X(s_cmp_lg_i32, kFSopc, 1, kMWScc | kMComm) \
  X(s_cmp_gt_i32, kFSopc, 2, kMWScc) X(s_cmp_ge_i32, kFSopc, 3, kMWScc)                   \
  X(s_cmp_lt_i32, kFSopc, 4, kMWScc) X(s_cmp_le_i32, kFSopc, 5, kMWScc)                   \
  X(s_cmp_eq_u32, kFSopc, 6, kMWScc | kMComm) X(s_cmp_lg_u32, kFSopc, 7, kMWScc | kMComm) \
  X(s_cmp_gt_u32, kFSopc, 8, kMWScc) X(s_cmp_ge_u32, kFSopc, 9, kMWScc)                   \
  X(s_cmp_lt_u32, kFSopc, 10, kMWScc) X(s_cmp_le_u32, kFSopc, 11, kMWScc)                 \
  X(s_cmp_lg_u64, kFSopc, 19, kMWScc | kM64)                                              \
  X(s_nop, kFSopp, 0, 0) X(s_endpgm, kFSopp, 1, 0) X(s_branch, kFSopp, 2, kMBranch)       \
  X(s_cbranch_scc0, kFSopp, 4, kMBranch | kMRScc) X(s_cbranch_scc1, kFSopp, 5, kMBranch | kMRScc) \
  X(s_cbranch_vccz, kFSopp, 6, kMBranch) X(s_cbranch_vccnz, kFSopp, 7, kMBranch)         \
  X(s_cbranch_execz, kFSopp, 8, kMBranch) X(s_cbranch_execnz, kFSopp, 9, kMBranch)       \
  X(s_waitcnt, kFSopp, 12, 0)                                                             \
  X(s_load_dwordx2, kFSmem, 1, kMLgkm) X(s_load_dwordx4, kFSmem, 2, kMLgkm)              \
  X(s_load_dwordx8, kFSmem, 3, kMLgkm) X(s_buffer_load_dword, kFSmem, 8, kMLgkm)         \
  X(s_buffer_load_dwordx2, kFSmem, 9, kMLgkm) X(s_buffer_load_dwordx4, kFSmem, 10, kMLgkm) \
  X(v_cndmask_b32, kFVop2, 0, 0) X(v_add_f32, kFVop2, 1, kMFloat | kMComm)                \
  X(v_sub_f32, kFVop2, 2, kMFloat) X(v_subrev_f32, kFVop2, 3, kMFloat | kMRev)            \
  X(v_mul_f32, kFVop2, 5, kMFloat | kMComm) X(v_mul_u32_u24, kFVop2, 8, kMComm)          \
  X(v_min_f32, kFVop2, 10, kMFloat | kMComm) X(v_max_f32, kFVop2, 11, kMFloat | kMComm)  \
  X(v_min_i32, kFVop2, 12, kMComm) X(v_max_i32, kFVop2, 13, kMComm)                       \
  X(v_min_u32, kFVop2, 14, kMComm) X(v_max_u32, kFVop2, 15, kMComm)                       \
  X(v_lshrrev_b32, kFVop2, 16, kMRev) X(v_ashrrev_i32, kFVop2, 17, kMRev)                 \
  X(v_lshlrev_b32, kFVop2, 18, kMRev) X(v_and_b32, kFVop2, 19, kMComm)                    \
  X(v_or_b32, kFVop2, 20, kMComm) X(v_xor_b32, kFVop2, 21, kMComm)                        \
  X(v_mac_f32, kFVop2, 22, kMFloat | kMComm) X(v_add_u32, kFVop2, 52, kMComm)            \
  X(v_sub_u32, kFVop2, 53, 0) X(v_subrev_u32, kFVop2, 54, kMRev)                          \
  X(v_nop, kFVop1, 0, 0) X(v_mov_b32, kFVop1, 1, 0) X(v_readfirstlane_b32, kFVop1, 2, 0)  \
  X(v_cvt_f32_i32, kFVop1, 5, 0) X(v_cvt_f32_u32, kFVop1, 6, 0)                            \
  X(v_cvt_u32_f32, kFVop1, 7, kMFloat) X(v_cvt_i32_f32, kFVop1, 8, kMFloat)               \
  X(v_cvt_f16_f32, kFVop1, 10, kMFloat) X(v_cvt_f32_f16, kFVop1, 11, 0)                   \
  X(v_fract_f32, kFVop1, 27, kMFloat) X(v_trunc_f32, kFVop1, 28, kMFloat)                 \
  X(v_ceil_f32, kFVop1, 29, kMFloat) X(v_rndne_f32, kFVop1, 30, kMFloat)                  \
  X(v_floor_f32, kFVop1, 31, kMFloat) X(v_exp_f32, kFVop1, 32, kMFloat)                   \
  X(v_log_f32, kFVop1, 33, kMFloat) X(v_rcp_f32, kFVop1, 34, kMFloat)                     \
  X(v_rcp_iflag_f32, kFVop1, 35, kMFloat) X(v_rsq_f32, kFVop1, 36, kMFloat)               \
  X(v_sqrt_f32, kFVop1, 39, kMFloat) X(v_sin_f32, kFVop1, 41, kMFloat)                    \
  X(v_cos_f32, kFVop1, 42, kMFloat) X(v_not_b32, kFVop1, 43, 0) X(v_bfrev_b32, kFVop1, 44, 0) \
  X(v_ffbh_u32, kFVop1, 45, 0) X(v_ffbl_b32, kFVop1, 46, 0) X(v_swap_b32, kFVop1, 81, 0)  \
  X(v_cmp_class_f32, kFVopc, 0x10, kMFloat) X(v_cmp_lt_f32, kFVopc, 0x41, kMFloat)        \
  X(v_cmp_eq_f32, kFVopc, 0x42, kMFloat | kMComm) X(v_cmp_le_f32, kFVopc, 0x43, kMFloat)  \
  X(v_cmp_gt_f32, kFVopc, 0x44, kMFloat) X(v_cmp_lg_f32, kFVopc, 0x45, kMFloat | kMComm)  \
  X(v_cmp_ge_f32, kFVopc, 0x46, kMFloat) X(v_cmp_o_f32, kFVopc, 0x47, kMFloat | kMComm)   \
  X(v_cmp_u_f32, kFVopc, 0x48, kMFloat | kMComm) X(v_cmp_nlg_f32, kFVopc, 0x4A, kMFloat | kMComm) \
  X(v_cmp_neq_f32, kFVopc, 0x4D, kMFloat | kMComm) X(v_cmp_lt_i32, kFVopc, 0xC1, 0)       \
  X(v_cmp_eq_i32, kFVopc, 0xC2, kMComm) X(v_cmp_le_i32, kFVopc, 0xC3, 0)                  \
  X(v_cmp_gt_i32, kFVopc, 0xC4, 0) X(v_cmp_ne_i32, kFVopc, 0xC5, kMComm)                  \
  X(v_cmp_ge_i32, kFVopc, 0xC6, 0) X(v_cmp_lt_u32, kFVopc, 0xC9, 0)                       \
  X(v_cmp_eq_u32, kFVopc, 0xCA, kMComm) X(v_cmp_le_u32, kFVopc, 0xCB, 0)                  \
  X(v_cmp_gt_u32, kFVopc, 0xCC, 0) X(v_cmp_ne_u32, kFVopc, 0xCD, kMComm)                  \
  X(v_cmp_ge_u32, kFVopc, 0xCE, 0)                                                         \
  X(v_mad_f32, kFVop3, 0x1C1, kMFloat) X(v_mad_u32_u24, kFVop3, 0x1C3, 0)                  \
  X(v_bfe_u32, kFVop3, 0x1C8, 0) X(v_bfe_i32, kFVop3, 0x1C9, 0) X(v_fma_f32, kFVop3, 0x1CB, kMFloat) \
  X(v_med3_f32, kFVop3, 0x1D6, kMFloat) X(v_lshl_add_u32, kFVop3, 0x1FD, 0)              \
  X(v_add3_u32, kFVop3, 0x1FF, 0) X(v_mul_lo_u32, kFVop3, 0x285, kMComm)                 \
  X(v_mul_hi_u32, kFVop3, 0x286, kMComm) X(v_mul_hi_i32, kFVop3, 0x287, kMComm)          \
  X(v_bcnt_u32_b32, kFVop3, 0x28B, 0)                                                      \
  X(v_interp_p1_f32, kFVintrp, 0, kMFloat) X(v_interp_p2_f32, kFVintrp, 1, kMFloat)       \
  X(buffer_load_dword, kFMubuf, 0x14, kMVmem) X(buffer_load_dwordx4, kFMubuf, 0x17, kMVmem) \
  X(buffer_store_dword, kFMubuf, 0x1C, kMVmem | kMStore)                                   \
  X(image_load, kFMimg, 0x00, kMVmem) X(image_sample, kFMimg, 0x20, kMVmem)               \
  X(exp, kFExp, 0, kMExpCnt | kMStore)                                                     \
  X(p_startpgm, kFPseudo, 0, 0) X(p_phi, kFPseudo, 1, 0) X(p_parallelcopy, kFPseudo, 2, 0) \
  X(p_create_vector, kFPseudo, 3, 0) X(p_as_uniform, kFPseudo, 4, 0)

enum MOp : uint16_t {
#define SIMV5_MENUM(name, fmt, code, flags) m_##name,
  SIMV5_MOPS(SIMV5_MENUM)
#undef SIMV5_MENUM
      kMOpCount
};
struct MOpInfo {
  uint8_t fmt;
  uint16_t code, flags;
};
inline constexpr MOpInfo kMOpInfo[kMOpCount] = {
#define SIMV5_MINFO(name, fmt, code, flags) {fmt, code, (uint16_t)(flags)},
    SIMV5_MOPS(SIMV5_MINFO)
#undef SIMV5_MINFO
};
inline constexpr bool MHas(uint32_t op, uint16_t f) { return (kMOpInfo[op].flags & f) != 0; }

// Operands: virtual temporary (id, dword offset into a vector temp), hardware
// inline constant (9-bit source code), the instruction's literal dword, or a
// fixed register (source code: vcc 106, m0 124, exec 126, vN 256 + N).
constexpr uint32_t kOKind = 0xC0000000u, kOTemp = 0, kOInline = 0x40000000u, kOLit = 0x80000000u,
                   kOFixed = 0xC0000000u;
constexpr uint32_t kONone = 0xFFFFFFFFu;
constexpr uint32_t kTempMask = 0x00FFFFFFu;
constexpr uint32_t kRegVcc = 106, kRegM0 = 124, kRegExec = 126, kRegVgpr = 256;
constexpr uint32_t kSgprAlloc = 101, kSgprScratch = 101; // s0..s100 allocatable, s101 copy scratch
constexpr uint32_t kVgprs = 256;
constexpr uint32_t kPhysSpill = 0xFFFF;
inline uint32_t OTemp(uint32_t t, uint32_t sub = 0) { return t | (sub << 24); }
inline bool IsTempOp(uint32_t o) { return o != kONone && (o & kOKind) == kOTemp; }
inline uint32_t TempOf(uint32_t o) { return o & kTempMask; }
inline uint32_t SubOf(uint32_t o) { return (o >> 24) & 0x3F; }

// One machine instruction: 64 bytes (an ACO Instruction with inline operand /
// definition storage), so instruction streams are real-sized.
struct MInst {
  uint16_t op;           // MOp
  uint8_t nops, ndefs;
  uint8_t mods;          // VOP3: neg bits 0-2, abs bits 3-5; bit 6 clamp
  uint8_t flags;         // SMEM/MUBUF imm offset valid, exp done / vm, MUBUF offen
  uint16_t imm;          // SOPP simm16, memory offset, interp attr / chan, exp target / mask
  uint32_t defs[2];      // temporaries (kONone when unused)
  uint32_t ops[4];
  uint32_t literal;
  uint32_t node;         // IR node (kNone: none)
  uint32_t block;        // machine block
  uint16_t pdef[2];      // register source codes after allocation
  uint16_t pop[4];
  uint32_t aux;          // branch target machine block
  uint32_t pad;
};
static_assert(sizeof(MInst) == 64, "machine instructions are one cache line");

// Instruction list as in ACO (std::vector<aco_ptr<Instruction>>): every
// instruction is its own object from the compile's monotonic buffer (ACO's
// instruction_buffer), so instructions lie in creation order; passes that
// rebuild a block move the pointers (take), new instructions are allocated,
// dropped ones stay in the buffer until the next compile releases it.
class InstrList {
public:
  explicit InstrList(MonotonicBuffer &pool) : pool_(&pool) {}
  InstrList(const InstrList &) = delete;
  InstrList &operator=(const InstrList &) = delete;
  MInst &operator[](size_t i) { return *p_[i]; }
  const MInst &operator[](size_t i) const { return *p_[i]; }
  size_t size() const { return p_.size(); }
  MInst &back() { return *p_.back(); }
  void push_back(const MInst &x) {
    MInst *n = static_cast<MInst *>(pool_->Alloc(sizeof(MInst), 64));
    *n = x;
    p_.push_back(n);
  }
  void take(InstrList &from, size_t i) { // move instruction i of `from` here
    p_.push_back(from.p_[i]);
    from.p_[i] = nullptr;
  }
  void clear() { p_.clear(); } // memory returns with the pool's Release()
  void swap(InstrList &o) { p_.swap(o.p_); }
  MInst **data() { return p_.data(); } // scheduler: moves pointers in place
  class It {
  public:
    explicit It(MInst *const *p) : p_(p) {}
    MInst &operator*() const { return **p_; }
    It &operator++() { ++p_; return *this; }
    bool operator!=(const It &o) const { return p_ != o.p_; }
  private:
    MInst *const *p_;
  };
  It begin() const { return It(p_.data()); }
  It end() const { return It(p_.data() + p_.size()); }

private:
  MonotonicBuffer *pool_;
  std::vector<MInst *> p_;
};
constexpr uint8_t kMfOffset = 1, kMfOffen = 2, kMfDone = 4, kMfVm = 8, kMfGlc = 16;

enum RegClass : uint8_t { kSgpr, kVgpr };
struct MTemp {
  uint32_t def;      // defining instruction (index at selection)
  uint32_t end;      // live-range end (instruction position)
  uint32_t start;
  uint32_t hint;     // preferred register (kNone)
  uint16_t phys;     // register source code (kPhysSpill)
  uint8_t cls, size; // RegClass, dwords
  uint32_t uses;
  uint32_t fixed;    // precolored register (kNone)
  uint32_t pad;
};

// Machine blocks form the linear CFG (what executes: both sides of a
// divergent branch run under exec masks); phis use the logical predecessors.
struct MBlock {
  uint32_t ir;          // IR block (kNone: split critical edge or exec flip block)
  uint32_t start, term, end; // instruction range; [term, end) terminator
  uint32_t succ[2];     // linear successors
  uint32_t pred[4], npred;   // linear predecessors
  uint32_t lpred[2], nlpred; // logical predecessors (phi operand order)
  uint32_t offset;      // code offset in dwords (assembler)
  uint32_t phiFrom[2];  // edge block: phi copies for (from IR block, to IR block)
  uint32_t flipOf;      // exec flip block of the divergent if at this IR block (kNone)
};
// Divergent control flow per IR block (exec-mask lowering, ACO style).
enum CfKind : uint8_t { kCfNone, kCfDivIf, kCfDivLatch };
struct CfInfo {
  uint8_t kind, flip;   // flip: an else side runs (else region or phi copies)
  uint32_t merge;       // divergent if: immediate post-dominator
  uint32_t thenEnd;     // divergent if: logical predecessor of merge on the then side
  uint32_t header, exit, preheader; // divergent latch
  uint32_t flipBefore;  // IR block whose layout position the flip block precedes
  uint32_t teOf;        // this block ends a then side: the divergent if (kNone)
  uint32_t flipFor;     // a flip block precedes this block: the divergent if (kNone)
  uint32_t preheaderOf; // this block is the preheader of a divergent loop: its latch
  uint32_t saved;       // exec mask saved at the if / preheader (temp operand)
  uint32_t restore[2];  // exec masks to restore at this block's start (merge / loop exit)
  uint8_t restoreLoop[2];
};

// Per-thread machine IR storage, reused across compiles (vectors keep their
// capacity; every pass writes before it reads). The instruction pool is
// released when a compile starts (BeginCompile), never while lists use it.
struct Mach {
  MonotonicBuffer pool;              // declared first: the lists allocate from it
  InstrList code{pool}, tmp{pool};
  std::vector<MTemp> temps;
  std::vector<MBlock> blocks;
  std::vector<uint32_t> blockOf;     // IR block -> machine block (kNone: deleted)
  std::vector<CfInfo> cf;            // per IR block
  std::vector<uint32_t> ipdom;       // immediate post-dominators (IR blocks)
  std::vector<uint64_t> liveIn, liveOut, live;
  std::vector<uint32_t> work, order, heap, scratch, scratch2;
  std::vector<uint32_t> phiUseFirst, phiUse; // per block: temporaries read by successor phis
  std::vector<uint8_t> waitState, bytes;
  std::vector<uint32_t> demand;      // per instruction: SGPR | VGPR << 16 dwords live there
  uint32_t liveWords = 0;
  uint32_t demandS = 0, demandV = 0; // program maximum (occupancy)
  uint32_t waves = 0;                // waves per SIMD the register demand allows
  uint32_t sgprs = 0, vgprs = 0;     // registers used (shader resource descriptor)
};

inline void BeginCompile(Mach &m) { // drop the previous compile's instructions
  m.code.clear();
  m.tmp.clear();
  m.pool.Release();
}
void SelectInstructions(Fn &f, Mach &m);  // IR (scheduled) -> machine code on temporaries
void OptimizeMachine(Fn &f, Mach &m);     // labels, constants / modifiers, combines, DCE
void MachineLiveness(Fn &f, Mach &m);     // block live-in / live-out bitsets (linear CFG)
void ComputeRegisterDemand(Fn &f, Mach &m); // liveness + per-instruction demand + occupancy
void ScheduleMachine(Fn &f, Mach &m);     // ACO-style SMEM / VMEM hoisting within the demand limit
void AllocateRegisters(Fn &f, Mach &m);   // linear scan (needs MachineLiveness)
void LowerToHw(Fn &f, Mach &m);           // phis / parallel copies / pseudos -> moves
void InsertWaitcnt(Fn &f, Mach &m);       // s_waitcnt from outstanding counters
uint64_t AssembleAndHash(Fn &f, Mach &m); // GFX9 encodings, branch offsets, hash
uint32_t ValidateMachine(const Fn &f, const Mach &m); // diag: temp / block consistency
} // namespace simv5
