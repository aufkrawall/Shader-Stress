// WorkloadRealisticV5Encode.cpp - Realistic V5 corpus encoding and storage:
// generated shader programs (WorkloadRealisticV5Corpus.cpp) become LLVM-style
// bitstreams (abbreviations, VBR, relative value ids; constants, function and
// symbol-table blocks). The corpus is built once per process (thread-safe
// static, generated in parallel, concatenated in index order) and shared
// read-only by all workers like a game's shader set that the driver compiles
// for many pipeline states.
#include "workloads/WorkloadRealisticV5Gen.h"
#include "workloads/WorkloadRealisticV5Format.h"
#include <algorithm>
#include <atomic>
#include <bit>
#include <thread>
#include <vector>

namespace simv5 {
namespace {
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

void Encode(const Program &p, BitWriter &bw, ShaderRef &ref) {
  using namespace fmt;
  BlockScope fn(bw, kTopWidth, kFunctionBlock, kFnWidth);
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstCast}, {kVbr, 6}, {kFixed, 4}, {kFixed, 4}});
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstBinop}, {kVbr, 6}, {kVbr, 6}, {kFixed, 4}});
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstRet}});
  DefineAbbrev(bw, kFnWidth, {{kLiteral, kInstExtractVal}, {kVbr, 6}, {kFixed, 2}});
  Unabbrev(bw, kFnWidth, kDeclareBlocks, {p.nblocks});
  {
    BlockScope cb(bw, kFnWidth, kConstantsBlock, kCstWidth);
    DefineAbbrev(bw, kCstWidth, {{kLiteral, kCstInteger}, {kVbr, 8}});
    DefineAbbrev(bw, kCstWidth, {{kLiteral, kCstFloat}, {kFixed, 32}});
    uint32_t curTy = kVoid;
    for (const ConstDef &c : p.consts) {
      if (c.ty != curTy) {
        Unabbrev(bw, kCstWidth, kCstSetType, {c.ty});
        curTy = c.ty;
      }
      if (c.spec >= 0) {
        Unabbrev(bw, kCstWidth, kCstSpec, {(uint64_t)c.spec});
      } else if (c.ty == kF32) {
        bw.Emit(kAbbrevFirst + 1, kCstWidth);
        bw.Emit(c.bits, 32);
      } else {
        bw.Emit(kAbbrevFirst, kCstWidth);
        const int64_t v = (int32_t)c.bits;
        bw.EmitVBR(v >= 0 ? (uint64_t)v << 1 : ((uint64_t)-v << 1) | 1, 8);
      }
    }
  }
  uint32_t id = p.nconst, nodes = p.nconst;
  for (const WInst &in : p.insts) {
    switch (in.kind) {
    case kInst: {
      const OpInfo &info = Info(in.op);
      switch (info.rec) {
      case kRecBinop:
        bw.Emit(kAbbrevFirst + 1, kFnWidth);
        bw.EmitVBR(id - in.a, 6);
        bw.EmitVBR(id - in.b, 6);
        bw.Emit(info.code, 4);
        break;
      case kRecCast:
        bw.Emit(kAbbrevFirst + 0, kFnWidth);
        bw.EmitVBR(id - in.a, 6);
        bw.Emit(in.ty, 4);
        bw.Emit(info.code, 4);
        break;
      case kRecCmp: Unabbrev(bw, kFnWidth, kInstCmp2, {id - in.a, id - in.b, info.code}); break;
      case kRecSelect: Unabbrev(bw, kFnWidth, kInstVSelect, {id - in.a, id - in.b, id - in.c}); break;
      case kRecExtract:
        bw.Emit(kAbbrevFirst + 3, kFnWidth);
        bw.EmitVBR(id - in.a, 6);
        bw.Emit(in.imm, 2);
        break;
      default: { // dx.op call: [attrs, cc, fnty, callee, opcode constant, args...]
        bw.Emit(kUnabbrevRecord, kFnWidth);
        bw.EmitVBR(kInstCall, 6);
        bw.EmitVBR(5 + info.arity, 6);
        for (uint64_t v : {(uint64_t)0, (uint64_t)kCallExplicitType, (uint64_t)kTypeDxOpFn,
                           (uint64_t)(id + kDxOpCallee + in.ty), (uint64_t)(id - p.dxop[in.op])})
          bw.EmitVBR(v, 6);
        for (uint32_t v : {in.a, in.b, in.c})
          if (v != kNone) bw.EmitVBR(id - v, 6);
        break;
      }
      }
      ++nodes;
      if (info.ty != kVoid) ++id;
      break;
    }
    case kPhi:
      bw.Emit(kUnabbrevRecord, kFnWidth);
      bw.EmitVBR(kInstPhi, 6);
      bw.EmitVBR(5, 6);
      bw.EmitVBR(in.ty, 6);
      bw.EmitSigned((int64_t)id - (int64_t)in.a);
      bw.EmitVBR(p.labels[in.t], 6);
      bw.EmitSigned((int64_t)id - (int64_t)in.b);
      bw.EmitVBR(p.labels[in.f], 6);
      ++id;
      ++nodes;
      break;
    case kBr: Unabbrev(bw, kFnWidth, kInstBr, {p.labels[in.t]}); break;
    case kBrCond: Unabbrev(bw, kFnWidth, kInstBr, {p.labels[in.t], p.labels[in.f], id - in.c}); break;
    case kRet: bw.Emit(kAbbrevFirst + 2, kFnWidth); break;
    }
  }
  {
    // Symbol table: resource / input / temporary names, skewed so that common
    // names repeat (interning hits).
    BlockScope vst(bw, kFnWidth, kValueSymtabBlock, kVstWidth);
    DefineAbbrev(bw, kVstWidth, {{kLiteral, kVstEntry}, {kVbr, 8}, {kArray, 0}, {kChar6, 0}});
    uint64_t r = p.nameSeed ^ 0x5653545641535354ull;
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
  ref.values = nodes; // IR nodes = constants + instructions (incl. void ones)
  ref.blocks = p.nblocks;
  ref.consts = p.nconst;
  ref.unused = p.unused;
}

struct CorpusStorage {
  std::vector<uint32_t> words;
  std::vector<ShaderRef> shaders;
  uint32_t classFirst[kClasses] = {}, classCount[kClasses] = {};
  Corpus view{};
  CorpusStorage() {
    uint32_t total = 0;
    for (uint32_t c = 0; c < kClasses; ++c) {
      classFirst[c] = total;
      classCount[c] = kClassShaders[c];
      total += kClassShaders[c];
    }
    // Shaders are independent (own seed): generate in parallel, concatenate
    // in index order, so the corpus is identical for any thread count.
    std::vector<std::vector<uint32_t>> parts(total);
    std::vector<ShaderRef> refs(total);
    std::atomic<uint32_t> nextShader{0};
    auto work = [&] {
      for (uint32_t s; (s = nextShader.fetch_add(1)) < total;) {
        uint32_t c = 0;
        while (s >= classFirst[c] + classCount[c]) ++c;
        Program prog;
        GenerateShader(0x4458494C53484452ull + s * 0x9E3779B97F4A7C15ull, ClassValues(c), prog);
        BitWriter bw(parts[s]);
        Encode(prog, bw, refs[s]);
        bw.Align32();
      }
    };
    const uint32_t threads = std::clamp(std::thread::hardware_concurrency(), 1u, 16u);
    std::vector<std::thread> pool;
    for (uint32_t t = 1; t < threads; ++t) pool.emplace_back(work);
    work();
    for (std::thread &t : pool) t.join();
    size_t size = 2; // reader refills 64 bits at a time
    for (const auto &p : parts) size += p.size();
    words.reserve(size);
    for (uint32_t s = 0; s < total; ++s) {
      refs[s].wordOffset = (uint32_t)words.size();
      refs[s].words = (uint32_t)parts[s].size();
      words.insert(words.end(), parts[s].begin(), parts[s].end());
      std::vector<uint32_t>().swap(parts[s]);
    }
    words.resize(words.size() + 2);
    shaders = std::move(refs);
    view = {words.data(), shaders.data(), kClasses, classFirst, classCount, total};
  }
};
} // namespace

const Corpus &GetCorpus() {
  static const CorpusStorage storage; // thread-safe one-time construction
  return storage.view;
}
} // namespace simv5
