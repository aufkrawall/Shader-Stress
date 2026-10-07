// WorkloadRealisticV5Front.cpp - Realistic V5 front end: LLVM-style bitstream
// reader (as in DXIL loaders: abbreviation tables, VBR fields, generic record
// reader feeding a per-record-code IR builder) and SSA/CFG construction.
#include "workloads/WorkloadRealisticV5.h"
#include "workloads/WorkloadRealisticV5Format.h"

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

struct NameEntry {
  uint64_t hash; // 0 = empty
  uint32_t pos, len;
};

class Builder {
public:
  Builder(Fn &f, const uint64_t *spec, Arena &ar) : f_(f), spec_(spec), ar_(ar) {}
  bool Run(Cursor &c);

private:
  bool FunctionBlock(Cursor &c, unsigned width);
  bool ConstantsBlock(Cursor &c, unsigned width);
  bool SymtabBlock(Cursor &c, unsigned width);
  bool EnterBlock(Cursor &c, uint32_t &id, unsigned &width) {
    id = (uint32_t)c.ReadVBR(8);
    width = (unsigned)c.ReadVBR(4);
    c.Align32();
    c.Read(32); // block length in words (used by readers that skip blocks)
    return width >= 2 && width <= 8;
  }
  // Constants are not instructions: block 0, outside every instruction list.
  Node &NewInst(uint32_t op, uint32_t type) {
    Node &n = f_.nodes[id_];
    const bool inst = !(op & kConstFlag);
    const uint32_t prev = inst && id_ > f_.blocks[cur_].first ? id_ - 1 : kNone;
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
    if (prev != kNone) f_.nodes[prev].next = id_;
    return n;
  }
  uint32_t TypeOf(uint32_t v) const { return f_.nodes[v].type; }
  bool Operand(uint64_t rel, uint32_t &out) const {
    if (rel == 0 || rel > id_) return false;
    out = id_ - (uint32_t)rel;
    return true;
  }
  bool EndBlock() {
    f_.blocks[cur_].last = id_;
    f_.blocks[cur_].head = f_.blocks[cur_].first < id_ ? f_.blocks[cur_].first : kNone;
    if (++cur_ > f_.nblocks) return false;
    if (cur_ < f_.nblocks) f_.blocks[cur_].first = id_;
    return true;
  }

  Fn &f_;
  const uint64_t *spec_;
  Arena &ar_;
  uint32_t id_ = 0, cur_ = 0, fixups_ = 0, cstType_ = 0;
  uint64_t vals_[kMaxVals];
};

bool Builder::Run(Cursor &c) {
  if (c.Read(fmt::kTopWidth) != fmt::kEnterSubblock) return false;
  uint32_t id;
  unsigned width;
  if (!EnterBlock(c, id, width) || id != fmt::kFunctionBlock) return false;
  if (!FunctionBlock(c, width) || !c.ok_) return false;
  // Forward phi operands (loop back edges) are linked once their node exists.
  for (uint32_t k = 0; k < fixups_; ++k) {
    const uint32_t i = f_.stack[k];
    const Node &n = f_.nodes[i];
    if (n.b >= id_) return false;
    AddUse(f_, i, 1, n.b);
  }
  return cur_ == f_.nblocks && id_ == f_.n;
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
    if (!c.ok_) return false;
    if (code == fmt::kCstSetType) {
      if (nvals != 1) return false;
      cstType_ = (uint32_t)vals_[0];
      continue;
    }
    if (id_ >= f_.n || nvals != 1 || (code != fmt::kCstInteger && code != fmt::kCstSpec)) return false;
    uint64_t v;
    if (code == fmt::kCstSpec) {
      if (vals_[0] >= kSpecConsts) return false;
      v = spec_[vals_[0]]; // pipeline-state specialization
    } else {
      v = (uint64_t)DecodeSigned(vals_[0]);
    }
    Node &n = NewInst(kConstFlag | (uint32_t)(Mix(v) & 0xFF), cstType_);
    n.val = v;
    ++id_;
    f_.nconst = id_;
  }
}

bool Builder::SymtabBlock(Cursor &c, unsigned width) {
  AbbrevTable t;
  uint32_t nvals;
  // Name interning: open-addressed table over a text buffer.
  const uint32_t size = std::bit_ceil(std::max(16u, f_.n / 16));
  NameEntry *table = ar_.Take<NameEntry>(size);
  char *text = ar_.Take<char>((size_t)size / 2 * kMaxVals + kMaxVals);
  if (!table || !text) return false;
  std::memset(table, 0, size * sizeof(NameEntry));
  uint32_t textPos = 0, entries = 0;
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
    if (!c.ok_ || code != fmt::kVstEntry || nvals < 2 || vals_[0] >= f_.n) return false;
    char name[kMaxVals];
    const uint32_t len = nvals - 1;
    uint64_t h = 0xcbf29ce484222325ull;
    for (uint32_t k = 0; k < len; ++k) {
      name[k] = (char)vals_[k + 1];
      h = (h ^ (unsigned char)name[k]) * 0x100000001b3ull;
    }
    h |= 1;
    for (uint32_t slot = (uint32_t)h & (size - 1);; slot = (slot + 1) & (size - 1)) {
      NameEntry &e = table[slot];
      if (e.hash == 0) {
        if (entries * 2 >= size) return false; // table sized for the symbol count
        std::memcpy(text + textPos, name, len);
        e = {h, textPos, len};
        textPos += len;
        ++entries;
        break;
      }
      if (e.hash == h && e.len == len && std::memcmp(text + e.pos, name, len) == 0) {
        f_.st.internHits++;
        break;
      }
    }
    f_.nodes[vals_[0]].name = (uint32_t)h & (size - 1); // home slot of the interned name
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
        if (f_.nblocks) f_.blocks[0].first = id_;
      } else if (id == fmt::kValueSymtabBlock) {
        if (!SymtabBlock(c, w)) return false;
      } else {
        return false;
      }
      continue;
    }
    const uint32_t code = ReadRecord(c, abbrev, t, vals_, nvals);
    if (!c.ok_) return false;
    uint32_t a = kNone, b = kNone, cc = kNone, op = 0, type = 0;
    switch (code) {
    case fmt::kDeclareBlocks:
      if (nvals != 1 || vals_[0] != f_.nblocks) return false;
      continue;
    case fmt::kInstCast: // [opval, destty, opcode]
      if (nvals != 3 || !Operand(vals_[0], a)) return false;
      op = (uint32_t)vals_[2];
      type = (uint32_t)vals_[1];
      break;
    case fmt::kInstBinop: // [lhs, rhs, opcode]
      if (nvals != 3 || !Operand(vals_[0], a) || !Operand(vals_[1], b)) return false;
      op = (uint32_t)vals_[2];
      type = TypeOf(a);
      break;
    case fmt::kInstVSelect: // [true, false, cond, opcode]
      if (nvals != 4 || !Operand(vals_[0], a) || !Operand(vals_[1], b) || !Operand(vals_[2], cc))
        return false;
      op = (uint32_t)vals_[3];
      type = TypeOf(a);
      break;
    case fmt::kInstStore: // [ptr, val, align, opcode]
      if (nvals != 4 || !Operand(vals_[0], a) || !Operand(vals_[1], b)) return false;
      op = (uint32_t)vals_[3];
      break;
    case fmt::kInstCall: // [attrs, cc, fnty, callee, dx.op opcode, args...]
      if (nvals < 6 || !(vals_[1] & fmt::kCallExplicitType) || vals_[2] != fmt::kTypeDxOp ||
          vals_[3] != id_ + fmt::kDxOpFunction)
        return false;
      op = (uint32_t)vals_[4];
      if (op >= kOps || nvals != 5 + Arity(op) || !Operand(vals_[5], a) ||
          (nvals == 7 && !Operand(vals_[6], b)))
        return false;
      type = IsStoreOp(op) ? 0 : TypeOf(a);
      break;
    case fmt::kInstPhi: { // [ty, val0 (signed rel), bb0, val1, bb1]
      if (nvals != 5 || id_ >= f_.n || vals_[2] >= f_.nblocks || vals_[4] >= f_.nblocks) return false;
      const int64_t r0 = DecodeSigned(vals_[1]), r1 = DecodeSigned(vals_[3]);
      if (r0 <= 0 || r0 > (int64_t)id_ || (int64_t)id_ - r1 < 0 || (int64_t)id_ - r1 >= (int64_t)f_.n)
        return false;
      Node &n = NewInst(kPhiFlag, (uint32_t)vals_[0]);
      n.a = id_ - (uint32_t)r0;
      n.b = (uint32_t)((int64_t)id_ - r1);
      f_.phiPred[id_] = (uint32_t)vals_[2];
      AddUse(f_, id_, 0, n.a);
      if (n.b < id_) AddUse(f_, id_, 1, n.b);
      else f_.stack[fixups_++] = id_;
      f_.st.phis++;
      ++id_;
      continue;
    }
    case fmt::kInstLoad: { // [slot, ty, align, volatile]
      if (nvals != 4 || id_ >= f_.n) return false;
      Node &n = NewInst(kInputFlag | (uint32_t)(vals_[0] & 0xFF), (uint32_t)vals_[1]);
      n.val = Mix(vals_[0] + 1);
      ++id_;
      continue;
    }
    case fmt::kInstBr: { // [bb] or [bbtrue, bbfalse, cond]
      if (cur_ >= f_.nblocks || (nvals != 1 && nvals != 3) || vals_[0] >= f_.nblocks) return false;
      Block &blk = f_.blocks[cur_];
      blk.succ[0] = (uint32_t)vals_[0];
      if (nvals == 3) {
        if (vals_[1] >= f_.nblocks || !Operand(vals_[2], blk.cond)) return false;
        blk.succ[1] = (uint32_t)vals_[1];
        f_.nodes[blk.cond].op |= kCondFlag;
      }
      if (!EndBlock()) return false;
      continue;
    }
    case fmt::kInstRet:
      if (nvals != 1 || cur_ >= f_.nblocks || !Operand(vals_[0], f_.ret)) return false;
      f_.nodes[f_.ret].op |= kCondFlag;
      if (!EndBlock()) return false;
      continue;
    default:
      return false;
    }
    if (id_ >= f_.n || op >= kOps) return false;
    Node &n = NewInst(op, type);
    n.a = a;
    n.b = b;
    n.c = cc;
    const uint32_t ar = Arity(op);
    if ((ar >= 2) != (b != kNone) || (ar == 3) != (cc != kNone)) return false;
    AddUse(f_, id_, 0, a);
    if (b != kNone) AddUse(f_, id_, 1, b);
    if (cc != kNone) AddUse(f_, id_, 2, cc);
    ++id_;
  }
}
} // namespace

bool ReadShader(const Corpus &corpus, const ShaderRef &s, const uint64_t *spec, Arena &ar, Fn &f) {
  f.n = s.values;
  f.nblocks = s.blocks;
  f.nconst = 0; // a fresh function (also when a probe re-reads)
  f.ret = kNone;
  f.names = 0;
  f.nodes = ar.Take<Node>(f.n);
  f.phiPred = ar.Take<uint32_t>(f.n);
  f.stack = ar.Take<uint32_t>(f.n);
  f.blocks = ar.Take<Block>(f.nblocks);
  if (!f.nodes || !f.phiPred || !f.stack || !f.blocks) return false;
  for (uint32_t b = 0; b < f.nblocks; ++b)
    f.blocks[b] = {0, 0, {kNone, kNone}, kNone, b ? kNone : 0, kNone, kNone, kNone, 0, 0, kNone};
  Cursor c(corpus.words, s.wordOffset);
  Builder builder(f, spec, ar);
  if (!builder.Run(c)) return false;
  f.st.bitsRead += (uint64_t)(c.WordPos() - s.wordOffset) * 32;
  f.preds = ar.Take<uint32_t>((size_t)f.nblocks * kMaxSucc);
  if (!f.preds) return false;
  RebuildPreds(f);
  f.st.blocks += f.nblocks;
  return true;
}
} // namespace simv5
