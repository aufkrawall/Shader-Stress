// WorkloadRealisticV5Corpus.cpp - Deterministic shader corpus for realistic V5:
// structured-control-flow SSA shaders encoded as LLVM-style bitstreams, the
// container format of DXIL. Built once per process (thread-safe static), then
// shared read-only by all workers, like a game's shader set that the driver
// compiles for many pipeline variants. Generation is not part of the timed
// work model; ReadShader (WorkloadRealisticV5Front.cpp) decodes this format.
#include "workloads/WorkloadRealisticV5.h"
#include "workloads/WorkloadRealisticV5Format.h"
#include <vector>

namespace simv5 {
namespace {
constexpr uint32_t kPerClass = 12;      // shaders per size class
constexpr uint32_t kClasses = 6;        // 512 .. 16384 values
constexpr uint32_t kMaxDepth = 5;       // control-flow nesting
constexpr uint32_t kPending = 12;       // unused values of open expression trees

class BitWriter {
public:
  explicit BitWriter(std::vector<uint32_t> &words) : w_(words) {}
  void Emit(uint64_t v, unsigned bits) {
    cur_ |= v << nbits_;
    nbits_ += bits;
    if (nbits_ >= 32) {
      w_.push_back((uint32_t)cur_);
      cur_ >>= 32;
      nbits_ -= 32;
    }
  }
  void EmitVBR(uint64_t v, unsigned bits) {
    const uint64_t hi = 1ull << (bits - 1);
    while (v >= hi) {
      Emit((v & (hi - 1)) | hi, bits);
      v >>= bits - 1;
    }
    Emit(v, bits);
  }
  void EmitSigned(int64_t v) { EmitVBR(v >= 0 ? (uint64_t)v << 1 : ((uint64_t)-v << 1) | 1, 6); }
  void Align32() {
    if (nbits_) Emit(0, 32 - nbits_);
  }
  size_t Words() const { return w_.size(); }
  void Patch(size_t word, uint32_t v) { w_[word] = v; }

private:
  std::vector<uint32_t> &w_;
  uint64_t cur_ = 0;
  unsigned nbits_ = 0;
};

// Block framing as in LLVM: ENTER_SUBBLOCK [id, new abbrev width, aligned
// 32-bit length], END_BLOCK [aligned].
struct BlockScope {
  BitWriter &bw;
  unsigned width;
  size_t lenWord;
  BlockScope(BitWriter &w, unsigned outerWidth, uint32_t id, unsigned newWidth) : bw(w), width(newWidth) {
    bw.Emit(fmt::kEnterSubblock, outerWidth);
    bw.EmitVBR(id, 8);
    bw.EmitVBR(newWidth, 4);
    bw.Align32();
    lenWord = bw.Words();
    bw.Emit(0, 32); // length placeholder
  }
  ~BlockScope() {
    bw.Emit(fmt::kEndBlock, width);
    bw.Align32();
    bw.Patch(lenWord, (uint32_t)(bw.Words() - lenWord - 1));
  }
};

void DefineAbbrev(BitWriter &bw, unsigned width, std::initializer_list<fmt::AbbrevOp> ops) {
  bw.Emit(fmt::kDefineAbbrev, width);
  bw.EmitVBR(ops.size(), 5);
  for (const fmt::AbbrevOp &op : ops) {
    bw.Emit(op.kind == fmt::kLiteral ? 1 : 0, 1);
    if (op.kind == fmt::kLiteral) {
      bw.EmitVBR(op.value, 8);
    } else {
      bw.Emit(op.kind, 3);
      if (op.kind == fmt::kFixed || op.kind == fmt::kVbr) bw.EmitVBR(op.value, 5);
    }
  }
}

void Unabbrev(BitWriter &bw, unsigned width, uint32_t code, std::initializer_list<uint64_t> ops) {
  bw.Emit(fmt::kUnabbrevRecord, width);
  bw.EmitVBR(code, 6);
  bw.EmitVBR(ops.size(), 6);
  for (uint64_t v : ops) bw.EmitVBR(v, 6);
}

// Skewed opcode: geometric choice of a group of 16, uniform inside the group,
// rotated by the shader's feature mix.
uint32_t SkewOp(uint64_t r, uint32_t rot) {
  const uint32_t group = (uint32_t)std::countr_zero(r | (1ull << 40));
  return ((group * 16 + (uint32_t)((r >> 48) & 15)) + rot) & (kOps - 1);
}

enum Kind : uint8_t { kInst, kLoad, kPhi, kBr, kBrCond, kRet };
struct WInst {
  Kind kind;
  uint32_t op = 0, a = kNone, b = kNone, c = kNone; // values; br: c = condition
  uint32_t t = kNone, f = kNone;                    // labels (br, phi preds)
};

// Generates one shader as a structured SSA program, then encodes it.
class ShaderGen {
public:
  ShaderGen(uint64_t seed, uint32_t values) : rng_(seed) {
    rot_ = (uint32_t)(Next(rng_) & (kOps - 1));
    nconst_ = std::max<uint32_t>(kSpecConsts + 8, values / 8);
    next_ = nconst_;
    for (uint32_t k = 0; k < nconst_; ++k) {
      const uint64_t r = Next(rng_);
      consts_.push_back(((r >> 40) & 1) ? ((r >> 12) & 0xFF) : Next(rng_));
    }
    cur_ = NewLabel();
    Start(cur_);
    inputs_ = 8 + std::min(24u, values / 256);
    for (uint32_t k = inputs_; k; --k) EmitLoad(); // shader inputs, constant buffers
    GenRegion(0, values - nconst_ - 1);
    insts_.push_back({kRet, 0, LastValue()});
  }
  void Encode(BitWriter &bw, ShaderRef &ref) const;

private:
  struct Recipe {
    uint32_t id, op, a, b, c;
  };
  struct Scope {
    size_t pool;
    uint32_t pending[kPending];
    uint32_t np;
  };
  uint32_t NewLabel() {
    labels_.push_back(kNone);
    return (uint32_t)labels_.size() - 1;
  }
  void Start(uint32_t label) {
    labels_[label] = nblocks_++;
    cur_ = label;
  }
  Scope Save() const {
    Scope s{pool_.size(), {}, np_};
    std::memcpy(s.pending, pending_, sizeof(pending_));
    return s;
  }
  void Restore(const Scope &s) {
    pool_.resize(s.pool);
    std::memcpy(pending_, s.pending, sizeof(pending_));
    np_ = s.np;
  }
  uint32_t LastValue() const { return pool_.empty() ? nconst_ - 1 : pool_.back(); }
  uint32_t Define(bool value) {
    const uint32_t id = next_++;
    if (value) {
      pool_.push_back(id);
      if (np_ == kPending) {
        std::memmove(pending_, pending_ + 1, (kPending - 1) * sizeof(uint32_t));
        --np_;
      }
      pending_[np_++] = id;
    }
    return id;
  }
  // DXIL arrives optimized (DXC runs LLVM -O3): no constant-only expressions;
  // constants appear as immediates in the last operand slots, a few of them
  // specialization constants that only the driver can fold.
  uint32_t PickOperand(uint64_t q, uint32_t slot) {
    if ((slot == 1 && (q & 3) == 0) || pool_.empty()) { // never a select condition
      if (((q >> 2) & 15) == 0 || pool_.empty()) return (uint32_t)((q >> 8) % kSpecConsts);
      return kSpecConsts + (uint32_t)((q >> 8) % (nconst_ - kSpecConsts));
    }
    if (np_ && ((q >> 6) & 3) != 0) return pending_[--np_];
    if ((q >> 5) & 7) { // mostly local (expression trees)
      const size_t d = 1 + ((q >> 12) & 15);
      return pool_[pool_.size() - std::min(d, pool_.size())];
    }
    if ((q >> 44) & 3) { // nearby (same region)
      const size_t d = 1 + (size_t)((q >> 20) % 64);
      return pool_[pool_.size() - std::min(d, pool_.size())];
    }
    return pool_[(q >> 20) % std::min<size_t>(inputs_, pool_.size())]; // long-lived shader input
  }
  void EmitLoad() { // input / constant-buffer / texture load: opaque to the optimizer
    insts_.push_back({kLoad, 0, (uint32_t)(Next(rng_) % 64)});
    Define(true);
  }
  void EmitInst() {
    const uint64_t r = Next(rng_);
    if (((r >> 56) & 15) == 0) {
      EmitLoad();
      return;
    }
    WInst in{kInst};
    bool dup = false;
    if (((r >> 3) & 31) == 0 && !pool_.empty()) { // redundancy exposed by lowering
      const size_t back = 1 + (size_t)((r >> 52) % std::min<size_t>(pool_.size(), 64));
      const uint32_t src = pool_[pool_.size() - back];
      for (const Recipe &d : recent_) {
        if (d.id == src) { // visible, so its operands are visible too
          in.op = d.op;
          in.a = d.a;
          in.b = d.b;
          in.c = d.c;
          dup = true;
          break;
        }
      }
    }
    if (!dup) {
      in.op = SkewOp(r, rot_);
      uint32_t *slots[3] = {&in.a, &in.b, &in.c};
      for (uint32_t k = 0; k < Arity(in.op); ++k) *slots[k] = PickOperand(Next(rng_), k);
      if (in.b == in.a && in.b >= nconst_) in.b = in.a == pool_.front() ? kSpecConsts : pool_.front(); // DXC folds x op x
    }
    insts_.push_back(in);
    const uint32_t id = Define(!IsStoreOp(in.op));
    if (!IsStoreOp(in.op)) {
      if (recent_.size() == 64) recent_.erase(recent_.begin());
      recent_.push_back({id, in.op, in.a, in.b, in.c});
    }
  }
  uint32_t PickCond() {
    const uint64_t q = Next(rng_);
    if ((q & 15) == 0 || pool_.empty()) return (uint32_t)((q >> 4) % kSpecConsts); // spec constant
    return pool_[pool_.size() - 1 - (size_t)((q >> 8) % std::min<size_t>(pool_.size(), 8))];
  }
  void Branch(uint32_t label) { insts_.push_back({kBr, 0, kNone, kNone, kNone, label}); }
  uint32_t Used() const { return next_ - nconst_; }

  void GenRegion(uint32_t depth, uint32_t budget) {
    const uint32_t end = Used() + budget;
    while (Used() < end) {
      const uint32_t left = end - Used();
      const uint64_t r = Next(rng_);
      const uint32_t pick = (uint32_t)(r % 100);
      if (depth >= kMaxDepth || left < 48 || pick < 45) {
        for (uint32_t k = std::min<uint32_t>(left, 8 + (uint32_t)((r >> 8) % 40)); k; --k) EmitInst();
        continue;
      }
      const uint32_t sub = std::max<uint32_t>(4, left * (20 + (uint32_t)((r >> 16) % 40)) / 100);
      if (pick < 80) { // if / if-else with phis at the merge
        const bool hasElse = pick >= 65;
        const uint32_t lthen = NewLabel(), lelse = hasElse ? NewLabel() : kNone, lmerge = NewLabel();
        const uint32_t pre = cur_, preVal = LastValue();
        insts_.push_back({kBrCond, 0, kNone, kNone, PickCond(), lthen, hasElse ? lelse : lmerge});
        uint32_t armVal[2] = {preVal, preVal}, armEnd[2] = {pre, pre};
        for (uint32_t arm = 0; arm < (hasElse ? 2u : 1u); ++arm) {
          Start(arm ? lelse : lthen);
          const Scope s = Save();
          GenRegion(depth + 1, arm ? sub / 2 + 1 : sub);
          armVal[arm] = LastValue();
          armEnd[arm] = cur_;
          Branch(lmerge);
          Restore(s);
        }
        Start(lmerge);
        for (uint32_t p = 1 + (uint32_t)((r >> 32) % 3); p; --p) {
          insts_.push_back({kPhi, 0, armVal[0], armVal[1], kNone, armEnd[0], armEnd[1]});
          Define(true);
        }
      } else { // do-while loop: header phis, body, latch branch
        const uint32_t lhead = NewLabel(), lexit = NewLabel(), pre = cur_;
        Branch(lhead);
        Start(lhead);
        const size_t firstPhi = insts_.size();
        const uint32_t nphi = 1 + (uint32_t)((r >> 32) % 2);
        for (uint32_t p = 0; p < nphi; ++p) {
          insts_.push_back({kPhi, 0, LastValue(), kNone, kNone, pre, kNone});
          Define(true);
        }
        GenRegion(depth + 1, sub);
        for (uint32_t p = 0; p < nphi; ++p) { // back-edge values (forward references)
          insts_[firstPhi + p].b = pool_[pool_.size() - 1 - std::min<size_t>(p, pool_.size() - 1)];
          insts_[firstPhi + p].f = cur_;
        }
        insts_.push_back({kBrCond, 0, kNone, kNone, PickCond(), lhead, lexit});
        Start(lexit);
      }
    }
  }

  uint64_t rng_;
  uint32_t inputs_ = 0, rot_ = 0, nconst_ = 0, next_ = 0, nblocks_ = 0, cur_ = 0;
  std::vector<uint64_t> consts_;
  std::vector<uint32_t> pool_, labels_;
  std::vector<WInst> insts_;
  std::vector<Recipe> recent_;
  uint32_t pending_[kPending] = {};
  uint32_t np_ = 0;
};

void ShaderGen::Encode(BitWriter &bw, ShaderRef &ref) const {
  using namespace fmt;
  BlockScope fn(bw, kTopWidth, kFunctionBlock, kFnWidth);
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstCast}, {kVbr, 6}, {kFixed, 4}, {kFixed, 8}});
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstBinop}, {kVbr, 6}, {kVbr, 6}, {kFixed, 8}});
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstRet}, {kVbr, 6}});
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstLoad}, {kVbr, 6}, {kFixed, 4}, {kVbr, 4}, {kFixed, 1}});
  Unabbrev(bw, kFnWidth, kDeclareBlocks, {nblocks_});
  {
    BlockScope cb(bw, kFnWidth, kConstantsBlock, kCstWidth);
    DefineAbbrev(bw, kCstWidth, {{kLiteral, kCstInteger}, {kVbr, 8}});
    Unabbrev(bw, kCstWidth, kCstSetType, {kTypeI64});
    for (uint32_t k = 0; k < nconst_; ++k) {
      if (k < kSpecConsts) {
        Unabbrev(bw, kCstWidth, kCstSpec, {k});
      } else {
        bw.Emit(kAbbrevFirst, kCstWidth);
        const int64_t v = (int64_t)consts_[k];
        bw.EmitVBR(v >= 0 ? (uint64_t)v << 1 : ((uint64_t)-v << 1) | 1, 8);
      }
    }
  }
  uint32_t id = nconst_;
  for (const WInst &in : insts_) {
    switch (in.kind) {
    case kInst: {
      const uint32_t ar = Arity(in.op);
      if (IsStoreOp(in.op)) {
        Unabbrev(bw, kFnWidth, kInstStore, {id - in.a, id - in.b, 4, in.op});
      } else if (ar == 3) {
        Unabbrev(bw, kFnWidth, kInstVSelect, {id - in.a, id - in.b, id - in.c, in.op});
      } else if (in.op >= 0x80) { // dx.op intrinsic: call @dx.op.*(i32 opcode, args)
        bw.Emit(kUnabbrevRecord, kFnWidth);
        bw.EmitVBR(kInstCall, 6);
        bw.EmitVBR(5 + ar, 6);
        for (uint64_t v : {(uint64_t)0, (uint64_t)kCallExplicitType, (uint64_t)kTypeDxOp,
                           (uint64_t)(id + kDxOpFunction), (uint64_t)in.op})
          bw.EmitVBR(v, 6);
        bw.EmitVBR(id - in.a, 6);
        if (ar == 2) bw.EmitVBR(id - in.b, 6);
      } else if (ar == 1) {
        bw.Emit(kAbbrevFirst + 0, kFnWidth);
        bw.EmitVBR(id - in.a, 6);
        bw.Emit(0, 4);
        bw.Emit(in.op, 8);
      } else {
        bw.Emit(kAbbrevFirst + 1, kFnWidth);
        bw.EmitVBR(id - in.a, 6);
        bw.EmitVBR(id - in.b, 6);
        bw.Emit(in.op, 8);
      }
      ++id;
      break;
    }
    case kLoad: // [slot, ty, align, volatile]
      bw.Emit(kAbbrevFirst + 3, kFnWidth);
      bw.EmitVBR(in.a, 6);
      bw.Emit(kTypeI64, 4);
      bw.EmitVBR(4, 4);
      bw.Emit(0, 1);
      ++id;
      break;
    case kPhi:
      bw.Emit(kUnabbrevRecord, kFnWidth);
      bw.EmitVBR(kInstPhi, 6);
      bw.EmitVBR(5, 6);
      bw.EmitVBR(kTypeI64, 6);
      bw.EmitSigned((int64_t)id - (int64_t)in.a);
      bw.EmitVBR(labels_[in.t], 6);
      bw.EmitSigned((int64_t)id - (int64_t)in.b);
      bw.EmitVBR(labels_[in.f], 6);
      ++id;
      break;
    case kBr:
      Unabbrev(bw, kFnWidth, kInstBr, {labels_[in.t]});
      break;
    case kBrCond:
      Unabbrev(bw, kFnWidth, kInstBr, {labels_[in.t], labels_[in.f], id - in.c});
      break;
    case kRet:
      bw.Emit(kAbbrevFirst + 2, kFnWidth);
      bw.EmitVBR(id - in.a, 6);
      break;
    }
  }
  {
    // Symbol table: resource / global / metadata-like names, skewed so that
    // common names repeat (interning hits).
    BlockScope vst(bw, kFnWidth, kValueSymtabBlock, kVstWidth);
    DefineAbbrev(bw, kVstWidth, {{kLiteral, kVstEntry}, {kVbr, 8}, {kArray, 0}, {kChar6, 0}});
    uint64_t r = rng_ ^ 0x5653545641535354ull;
    for (uint32_t k = 0, names = std::max(8u, id / 32); k < names; ++k) {
      const uint64_t q = Next(r);
      const uint64_t nameId = (uint64_t)std::countr_zero(q | (1ull << 20)) * 64 + ((q >> 40) & 63);
      const uint64_t m = OpConst((uint32_t)nameId, 9);
      const uint32_t len = 4 + (uint32_t)((m >> 40) % 28);
      bw.Emit(kAbbrevFirst, kVstWidth);
      bw.EmitVBR((q >> 8) % id, 8);
      bw.EmitVBR(len, 6);
      uint64_t c = m;
      for (uint32_t j = 0; j < len; ++j) {
        if ((j & 7) == 7) c = Mix(c + j);
        bw.Emit((c >> (6 * (j & 7))) & 63, 6);
      }
    }
  }
  ref.values = id;
  ref.blocks = nblocks_;
  ref.consts = nconst_;
}

struct CorpusStorage {
  std::vector<uint32_t> words;
  std::vector<ShaderRef> shaders;
  Corpus view{};
  CorpusStorage() {
    BitWriter bw(words);
    for (uint32_t c = 0; c < kClasses; ++c) {
      for (uint32_t k = 0; k < kPerClass; ++k) {
        ShaderRef ref{};
        ref.wordOffset = (uint32_t)words.size();
        ShaderGen gen(0x4458494C53484452ull + c * 0x10001ull + k * 0x9E37ull, ClassValues(c));
        gen.Encode(bw, ref);
        bw.Align32();
        ref.words = (uint32_t)words.size() - ref.wordOffset;
        shaders.push_back(ref);
      }
    }
    words.resize(words.size() + 2); // reader refills 64 bits at a time
    view = {words.data(), shaders.data(), kClasses, kPerClass};
  }
};
} // namespace

const Corpus &GetCorpus() {
  static const CorpusStorage storage; // thread-safe one-time construction
  return storage.view;
}
} // namespace simv5
