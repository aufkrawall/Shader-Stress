// WorkloadRealisticV5Front.cpp - Realistic V5 front end: LLVM-style bitstream
// reader (as in DXIL loaders: abbreviation tables, VBR fields, generic record
// reader feeding a per-record-code IR builder) and SSA/CFG construction.
#include "workloads/WorkloadRealisticV5.h"
#include "workloads/WorkloadRealisticV5Alloc.h"
#include "workloads/WorkloadRealisticV5Format.h"
#ifdef SIMV5_VALIDATE_TRACE // -DSIMV5_VALIDATE_TRACE: report decode failures
#include <cstdio>
#define SIMV5_TRACE(...) std::fprintf(stderr, __VA_ARGS__)
#else
#define SIMV5_TRACE(...) ((void)0)
#endif

namespace simv5 {
namespace {
// BitstreamCursor: little-endian 32-bit words, refilled on demand.
class Cursor {
public:
  Cursor(const uint32_t *words, size_t start) : w_(words), pos_(start) {}
  uint32_t Read(unsigned n) { // 1 <= n <= 32
    if (bits_ < n) {
      cur_ |= (uint64_t)w_[pos_++] << bits_;
      bits_ += 32;
    }
    const uint32_t v = (uint32_t)(cur_ & ((1ull << n) - 1));
    cur_ >>= n;
    bits_ -= n;
    return v;
  }
  uint64_t ReadVBR(unsigned n) {
    const uint32_t hi = 1u << (n - 1);
    uint32_t piece = Read(n);
    if (!(piece & hi)) return piece;
    uint64_t v = 0;
    for (unsigned shift = 0; shift < 64; shift += n - 1) {
      v |= (uint64_t)(piece & (hi - 1)) << shift;
      if (!(piece & hi)) return v;
      piece = Read(n);
    }
    ok_ = false; // over-long VBR
    return 0;
  }
  // After any read fewer than 32 bits remain, all from the current word.
  void Align32() {
    cur_ = 0;
    bits_ = 0;
  }
  size_t WordPos() const { return pos_; }
  bool ok_ = true;

private:
  const uint32_t *w_;
  size_t pos_;
  uint64_t cur_ = 0;
  unsigned bits_ = 0;
};

struct Abbrev {
  uint32_t nops;
  fmt::AbbrevOp ops[fmt::kMaxAbbrevOps];
};
struct AbbrevTable {
  Abbrev list[fmt::kMaxAbbrevs];
  uint32_t count = 0;
};

constexpr char kChar6[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
constexpr uint32_t kMaxVals = 64;

bool ReadAbbrevDef(Cursor &c, AbbrevTable &t) {
  const uint32_t nops = (uint32_t)c.ReadVBR(5);
  if (nops == 0 || nops > fmt::kMaxAbbrevOps || t.count == fmt::kMaxAbbrevs) return false;
  Abbrev &a = t.list[t.count++];
  a.nops = nops;
  for (uint32_t k = 0; k < nops; ++k) {
    if (c.Read(1)) {
      a.ops[k] = {fmt::kLiteral, (uint32_t)c.ReadVBR(8)};
    } else {
      const auto kind = (fmt::AbbrevKind)c.Read(3);
      uint32_t width = 0;
      if (kind == fmt::kFixed || kind == fmt::kVbr) width = (uint32_t)c.ReadVBR(5);
      if (kind < fmt::kFixed || kind > fmt::kChar6 || ((kind == fmt::kFixed || kind == fmt::kVbr) &&
                                                      (width == 0 || width > 32)))
        return false;
      a.ops[k] = {kind, width};
    }
  }
  return true;
}

uint64_t ReadScalar(Cursor &c, const fmt::AbbrevOp &op) {
  switch (op.kind) {
  case fmt::kLiteral: return op.value;
  case fmt::kFixed: return c.Read(op.value);
  case fmt::kVbr: return c.ReadVBR(op.value);
  case fmt::kChar6: return (uint64_t)(unsigned char)kChar6[c.Read(6)];
  default: return 0;
  }
}

// Generic record reader: returns the record code, fills vals (operands).
uint32_t ReadRecord(Cursor &c, uint32_t abbrevId, const AbbrevTable &t, uint64_t *vals,
                    uint32_t &nvals) {
  nvals = 0;
  if (abbrevId == fmt::kUnabbrevRecord) {
    const uint32_t code = (uint32_t)c.ReadVBR(6);
    const uint32_t n = (uint32_t)c.ReadVBR(6);
    if (n > kMaxVals) {
      c.ok_ = false;
      return 0;
    }
    for (uint32_t k = 0; k < n; ++k) vals[nvals++] = c.ReadVBR(6);
    return code;
  }
  const uint32_t index = abbrevId - fmt::kAbbrevFirst;
  if (index >= t.count) {
    c.ok_ = false;
    return 0;
  }
  const Abbrev &a = t.list[index];
  const uint32_t code = (uint32_t)ReadScalar(c, a.ops[0]);
  for (uint32_t k = 1; k < a.nops; ++k) {
    if (a.ops[k].kind == fmt::kArray) {
      const uint32_t len = (uint32_t)c.ReadVBR(6);
      if (k + 1 >= a.nops || nvals + len > kMaxVals) {
        c.ok_ = false;
        return 0;
      }
      const fmt::AbbrevOp &elt = a.ops[++k];
      for (uint32_t j = 0; j < len; ++j) vals[nvals++] = ReadScalar(c, elt);
    } else {
      if (nvals == kMaxVals) {
        c.ok_ = false;
        return 0;
      }
      vals[nvals++] = ReadScalar(c, a.ops[k]);
    }
  }
  return code;
}

inline int64_t DecodeSigned(uint64_t v) {
  return (v & 1) ? -(int64_t)(v >> 1) : (int64_t)(v >> 1);
}

// Pipeline-state constant of the given type from the driver's state key.
uint64_t SpecValue(uint64_t v, uint32_t ty) {
  if (ty != kF32) return (uint32_t)v;
  const uint32_t sel = (uint32_t)(v >> 9) & 3;
  if (sel == 0) return F32Bits(1.0f);
  if (sel == 1) return F32Bits(0.0f);
  return F32Bits((float)((int32_t)(v & 0x1FF) - 256) * (1.0f / 128.0f));
}

class Builder {
public:
  Builder(Fn &f, const uint64_t *spec, uint32_t *valueMap) : f_(f), spec_(spec), map_(valueMap) {}
  bool Run(Cursor &c);

private:
  bool FunctionBlock(Cursor &c, unsigned width);
  bool ConstantsBlock(Cursor &c, unsigned width);
  bool SymtabBlock(Cursor &c, unsigned width);
  bool Instruction(uint32_t code, uint32_t nvals);
  bool EnterBlock(Cursor &c, uint32_t &id, unsigned &width) {
    id = (uint32_t)c.ReadVBR(8);
    width = (unsigned)c.ReadVBR(4);
    c.Align32();
    c.Read(32); // block length in words (used by readers that skip blocks)
    return width >= 2 && width <= 8;
  }
  // Constants are not instructions: block 0, outside every instruction list.
  // Non-void values get the next value id (LLVM numbering); the node index
  // runs over all instructions.
  Node *NewNode(uint32_t op, uint32_t type) {
    if (node_ >= f_.n) return nullptr;
    Node &n = f_.nodes[node_];
    const bool inst = !(op & kConstFlag);
    const uint32_t prev = inst && node_ > f_.blocks[cur_].first ? node_ - 1 : kNone;
    n.op = op;
    n.a = n.b = n.c = n.firstUse = kNone;
    n.reg = kNoReg;
    n.val = 0;
    n.numUses = 0;
    n.type = type;
    n.block = inst ? cur_ : 0;
    n.prev = prev;
    n.next = kNone;
    n.name = n.liveIdx = n.pos = kNone;
    n.imm = 0;
    if (prev != kNone) f_.nodes[prev].next = node_;
    if (type != kVoid) map_[vid_++] = node_;
    node_++;
    return &n;
  }
  uint32_t TypeOf(uint32_t node) const { return f_.nodes[node].type; }
  // Relative value id -> node index.
  bool Value(uint64_t rel, uint32_t &out) const {
    if (rel == 0 || rel > vid_) return false;
    out = map_[vid_ - (uint32_t)rel];
    return true;
  }
  bool EndBlock() {
    f_.blocks[cur_].last = node_;
    f_.blocks[cur_].head = f_.blocks[cur_].first < node_ ? f_.blocks[cur_].first : kNone;
    if (++cur_ > f_.nblocks) return false;
    if (cur_ < f_.nblocks) f_.blocks[cur_].first = node_;
    return true;
  }

  Fn &f_;
  const uint64_t *spec_;
  uint32_t *map_; // value id -> node
  uint32_t node_ = 0, vid_ = 0, cur_ = 0, fixups_ = 0, cstType_ = kVoid;
  uint64_t vals_[kMaxVals];
};

bool Builder::Run(Cursor &c) {
  if (c.Read(fmt::kTopWidth) != fmt::kEnterSubblock) return false;
  uint32_t id;
  unsigned width;
  if (!EnterBlock(c, id, width) || id != fmt::kFunctionBlock) return false;
  if (!FunctionBlock(c, width) || !c.ok_) return false;
  // Forward phi operands (loop back edges) are resolved once their value exists:
  // the phi's b field holds the value id until then.
  for (uint32_t k = 0; k < fixups_; ++k) {
    const uint32_t i = f_.stack[k];
    Node &n = f_.nodes[i];
    if (n.b >= vid_) return false;
    n.b = map_[n.b];
    if (TypeOf(n.b) != n.type) return false;
    AddUse(f_, i, 1, n.b);
  }
  return cur_ == f_.nblocks && node_ == f_.n;
}

bool Builder::ConstantsBlock(Cursor &c, unsigned width) {
  AbbrevTable t;
  uint32_t nvals;
  for (;;) {
    const uint32_t abbrev = c.Read(width);
    if (abbrev == fmt::kEndBlock) {
      c.Align32();
      return true;
    }
    if (abbrev == fmt::kDefineAbbrev) {
      if (!ReadAbbrevDef(c, t)) return false;
      continue;
    }
    if (abbrev == fmt::kEnterSubblock) return false;
    const uint32_t code = ReadRecord(c, abbrev, t, vals_, nvals);
    if (!c.ok_ || nvals != 1) return false;
    if (code == fmt::kCstSetType) {
      if (vals_[0] >= kTyCount) return false;
      cstType_ = (uint32_t)vals_[0];
      continue;
    }
    uint64_t v;
    if (code == fmt::kCstSpec && vals_[0] < kSpecConsts) v = SpecValue(spec_[vals_[0]], cstType_);
    else if (code == fmt::kCstInteger && (cstType_ == kI32 || cstType_ == kI1)) v = (uint32_t)DecodeSigned(vals_[0]);
    else if (code == fmt::kCstFloat && cstType_ == kF32) v = (uint32_t)vals_[0];
    else return false;
    Node *n = NewNode(kConstFlag | kNotAnOp, cstType_);
    if (!n) return false;
    n->val = v;
    MapConst(f_, node_ - 1); // LLVM uniques constants (first definition wins)
    f_.nconst = node_;
  }
}

bool Builder::SymtabBlock(Cursor &c, unsigned width) {
  AbbrevTable t;
  uint32_t nvals;
  // Name interning as LLVM's ValueSymbolTable: a StringMap whose entries
  // (key bytes) live on the thread heap and die with the module.
  StringMap names;
  for (;;) {
    const uint32_t abbrev = c.Read(width);
    if (abbrev == fmt::kEndBlock) {
      c.Align32();
      f_.st.nameRehashes += names.rehashes;
      return true;
    }
    if (abbrev == fmt::kDefineAbbrev) {
      if (!ReadAbbrevDef(c, t)) return false;
      continue;
    }
    if (abbrev == fmt::kEnterSubblock) return false;
    const uint32_t code = ReadRecord(c, abbrev, t, vals_, nvals);
    if (!c.ok_ || code != fmt::kVstEntry || nvals < 2 || vals_[0] >= vid_) return false;
    char name[kMaxVals];
    const uint32_t len = nvals - 1;
    uint64_t h = 0xcbf29ce484222325ull;
    for (uint32_t k = 0; k < len; ++k) {
      name[k] = (char)vals_[k + 1];
      h = (h ^ (unsigned char)name[k]) * 0x100000001b3ull;
    }
    h |= 1;
    bool inserted = false;
    const StringMap::Entry *e = names.Insert(name, len, names.Size(), &inserted);
    if (!inserted) f_.st.internHits++;
    f_.nodes[map_[vals_[0]]].name = e->value; // interned symbol id
    f_.names = Rotl64(f_.names ^ h, 13) + vals_[0];
  }
}

bool Builder::FunctionBlock(Cursor &c, unsigned width) {
  AbbrevTable t;
  uint32_t nvals;
  for (;;) {
    const uint32_t abbrev = c.Read(width);
    if (abbrev == fmt::kEndBlock) {
      c.Align32();
      return true;
    }
    if (abbrev == fmt::kDefineAbbrev) {
      if (!ReadAbbrevDef(c, t)) return false;
      continue;
    }
    if (abbrev == fmt::kEnterSubblock) {
      uint32_t id;
      unsigned w;
      if (!EnterBlock(c, id, w)) return false;
      if (id == fmt::kConstantsBlock) {
        if (!ConstantsBlock(c, w)) return false;
        if (f_.nblocks) f_.blocks[0].first = node_;
      } else if (id == fmt::kValueSymtabBlock) {
        if (!SymtabBlock(c, w)) return false;
      } else {
        return false;
      }
      continue;
    }
    const uint32_t code = ReadRecord(c, abbrev, t, vals_, nvals);
    if (!c.ok_ || !Instruction(code, nvals)) {
      SIMV5_TRACE("decode: record %u (%u operands: %llu %llu %llu %llu %llu) failed at value %u node %u\n", code,
                  nvals, (unsigned long long)vals_[0], (unsigned long long)vals_[1], (unsigned long long)vals_[2],
                  (unsigned long long)vals_[3], (unsigned long long)vals_[4], vid_, node_);
      return false;
    }
  }
}

// One function-block record: decodes it into an instruction node.
bool Builder::Instruction(uint32_t code, uint32_t nvals) {
  uint32_t v[3] = {kNone, kNone, kNone}, op = kNoOp, type = kVoid, imm = 0;
  switch (code) {
  case fmt::kDeclareBlocks:
    return nvals == 1 && vals_[0] == f_.nblocks;
  case fmt::kInstBinop: // [lhs, rhs, opcode]
    if (nvals < 3 || !Value(vals_[0], v[0]) || !Value(vals_[1], v[1]) || vals_[2] >= 16) return false;
    type = TypeOf(v[0]);
    op = (IsFloatTy(type) ? kCodeMaps.floatBinop : kCodeMaps.intBinop)[vals_[2]];
    if (TypeOf(v[1]) != type) return false;
    break;
  case fmt::kInstCast: // [opval, destty, castopc]
    if (nvals != 3 || !Value(vals_[0], v[0]) || vals_[1] >= kTyCount || vals_[2] >= 16) return false;
    op = kCodeMaps.cast[vals_[2]];
    type = (uint32_t)vals_[1];
    break;
  case fmt::kInstCmp2: // [lhs, rhs, predicate]
    if (nvals != 3 || !Value(vals_[0], v[0]) || !Value(vals_[1], v[1]) || vals_[2] >= 64) return false;
    op = kCodeMaps.cmp[vals_[2]];
    type = kI1;
    if (TypeOf(v[1]) != TypeOf(v[0])) {
      SIMV5_TRACE("decode: compare operand types %u (node %u op %08x) vs %u (node %u op %08x)\n", TypeOf(v[0]), v[0],
                  f_.nodes[v[0]].op, TypeOf(v[1]), v[1], f_.nodes[v[1]].op);
      return false;
    }
    break;
  case fmt::kInstVSelect: // [true, false, cond]
    if (nvals != 3 || !Value(vals_[0], v[0]) || !Value(vals_[1], v[1]) || !Value(vals_[2], v[2]))
      return false;
    op = kSelect;
    type = TypeOf(v[0]);
    if (TypeOf(v[1]) != type || TypeOf(v[2]) != kI1) return false;
    break;
  case fmt::kInstExtractVal: { // [aggregate, index]
    if (nvals != 2 || !Value(vals_[0], v[0]) || vals_[1] > 3) return false;
    const uint32_t agg = TypeOf(v[0]);
    if (!IsResRet(agg)) return false;
    op = kExtract;
    type = agg == kResRetF32 ? kF32 : kI32;
    imm = (uint32_t)vals_[1];
    break;
  }
  case fmt::kInstCall: { // [attrs, cc, fnty, callee, dx.op opcode, args...]
    uint32_t opc;
    if (nvals < 6 || !(vals_[1] & fmt::kCallExplicitType) || vals_[2] != fmt::kTypeDxOpFn ||
        vals_[3] < vid_ + fmt::kDxOpCallee || vals_[3] - vid_ - fmt::kDxOpCallee >= kTyCount ||
        !Value(vals_[4], opc))
      return false;
    const Node &oc = f_.nodes[opc];
    if (!IsConst(oc) || oc.type != kI32 || oc.val >= 128) return false;
    op = kCodeMaps.dxop[oc.val]; // the opcode is an i32 constant operand, as in DXIL
    if (op == kNoOp || nvals != 5 + Arity(op)) return false;
    for (uint32_t k = 0; k < Arity(op); ++k)
      if (!Value(vals_[5 + k], v[k])) return false;
    const uint32_t overload = (uint32_t)(vals_[3] - vid_ - fmt::kDxOpCallee);
    const uint32_t ty = Info(op).ty;
    type = ty == kTySame ? TypeOf(v[0]) : ty == kTyExplicit ? overload : ty;
    break;
  }
  case fmt::kInstPhi: { // [ty, val0 (signed rel), bb0, val1, bb1]
    if (nvals != 5 || vals_[0] >= kTyCount || vals_[2] >= f_.nblocks || vals_[4] >= f_.nblocks) return false;
    const int64_t r0 = DecodeSigned(vals_[1]), r1 = DecodeSigned(vals_[3]);
    const int64_t self = vid_, fwd = self - r1; // relative to this phi's own value id
    if (r0 <= 0 || r0 > self || fwd < 0) return false;
    const uint32_t node = node_;
    Node *n = NewNode(kPhiFlag | kNotAnOp, (uint32_t)vals_[0]);
    if (!n) return false;
    n->a = map_[self - r0];
    if (TypeOf(n->a) != n->type) return false;
    f_.phiPred[node] = (uint32_t)vals_[2];
    AddUse(f_, node, 0, n->a);
    if (fwd < self) {
      n->b = map_[fwd];
      if (TypeOf(n->b) != n->type) return false;
      AddUse(f_, node, 1, n->b);
    } else {
      n->b = (uint32_t)fwd; // value id, resolved in Run()
      f_.stack[fixups_++] = node;
    }
    f_.st.phis++;
    return true;
  }
  case fmt::kInstBr: { // [bb] or [bbtrue, bbfalse, cond]
    if (cur_ >= f_.nblocks || (nvals != 1 && nvals != 3) || vals_[0] >= f_.nblocks) return false;
    Block &blk = f_.blocks[cur_];
    blk.succ[0] = (uint32_t)vals_[0];
    if (nvals == 3) {
      if (vals_[1] >= f_.nblocks || !Value(vals_[2], blk.cond) || TypeOf(blk.cond) != kI1) return false;
      blk.succ[1] = (uint32_t)vals_[1];
      f_.nodes[blk.cond].op |= kCondFlag;
    }
    return EndBlock();
  }
  case fmt::kInstRet: // ret void
    return nvals == 0 && cur_ < f_.nblocks && EndBlock();
  default:
    return false;
  }
  if (op == kNoOp) return false;
  const uint32_t node = node_;
  Node *n = NewNode(op, type);
  if (!n) return false;
  n->imm = imm;
  for (uint32_t k = 0; k < Arity(op); ++k) {
    if (v[k] == kNone) return false;
    OperandRef(*n, k) = v[k];
    AddUse(f_, node, k, v[k]);
  }
  return true;
}
} // namespace

bool ReadShader(const Corpus &corpus, const ShaderRef &s, const uint64_t *spec, Arena &ar, Fn &f) {
  f.n = s.values;
  f.cap = s.values + s.values / 2 + 512; // room for lowering / unrolling
  f.nblocks = s.blocks;
  f.nconst = 0; // a fresh function (also when a probe re-reads)
  f.ret = kNone;
  f.names = 0;
  f.freeList = kNone;
  f.ar = &ar;
  f.consts = DenseMap{};
  f.nodes = ar.Take<Node>(f.cap);
  f.phiPred = ar.Take<uint32_t>(f.cap);
  f.stack = ar.Take<uint32_t>(f.cap);
  f.blocks = ar.Take<Block>(f.nblocks);
  uint32_t *valueMap = ar.Take<uint32_t>(f.n);
  if (!f.nodes || !f.phiPred || !f.stack || !f.blocks || !valueMap) return false;
  for (uint32_t b = 0; b < f.nblocks; ++b)
    f.blocks[b] = {0, 0, {kNone, kNone}, kNone, b ? kNone : 0, kNone, kNone, kNone, 0, 0, kNone};
  Cursor c(corpus.words, s.wordOffset);
  Builder builder(f, spec, valueMap);
  if (!builder.Run(c)) return false;
  f.st.bitsRead += (uint64_t)(c.WordPos() - s.wordOffset) * 32;
  f.preds = ar.Take<uint32_t>((size_t)f.nblocks * kMaxSucc);
  if (!f.preds) return false;
  RebuildPreds(f);
  f.st.blocks += f.nblocks;
  return true;
}
} // namespace simv5
