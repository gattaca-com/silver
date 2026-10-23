import Std

/-!
The x86 SHA/SSE intrinsics and scalar carry used by `sha256/extensions.rs` and
`portable/fp.rs`. These are explicit trusted instruction models, not proofs
about a processor. Lane 0 contains the least significant bits. Byte loads use
x86 little-endian order; word loads/stores preserve the order of `[u32; 4]`.

Sources: Intel's SHA extensions article and SDM volume 2B operation sections
for SHA256RNDS2 and SHA256MSG1/2; Intel's C++ Compiler Classic reference, section
“Intrinsics for Multi-Precision Arithmetic”, and Rust 1.95 stdarch's
`x86/{sse2,sse41,ssse3,sha}.rs` and `x86_64/adx.rs`.
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html
https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf
https://www.intel.com/content/dam/develop/external/us/en/documents/cpp_compiler_classic.pdf
https://github.com/rust-lang/stdarch/tree/master/crates/core_arch/src/x86

Immediate arguments model the valid Rust const-generic range 0 through 255.
-/

namespace LeanBlsSimd

/-- `__m128i`: lane `l` holds bits `32*l` through `32*l+31`. -/
abbrev M128 := Vector UInt32 4

namespace ShaIntrinsics

/-- Byte indices are reduced modulo 16; instruction callers supply indices below 16. -/
def byte (a : M128) (i : Nat) : UInt8 :=
  UInt8.ofNat (a[(⟨i / 4 % 4, Nat.mod_lt _ (by decide)⟩ : Fin 4)].toNat / 2 ^ (8 * (i % 4)))

/-- Four little-endian bytes form each lane. Only indices 0 through 15 are read. -/
def fromBytes (bytes : Nat → UInt8) : M128 := .ofFn fun l =>
  UInt32.ofNat ((bytes (4*l.val)).toNat + 2^8 * (bytes (4*l.val+1)).toNat +
    2^16 * (bytes (4*l.val+2)).toNat + 2^24 * (bytes (4*l.val+3)).toNat)

def loadBytes (bytes : Vector UInt8 16) : M128 :=
  fromBytes fun i => bytes[(⟨i % 16, Nat.mod_lt _ (by decide)⟩ : Fin 16)]

def rotr (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))
def smallSigma0 (x : UInt32) : UInt32 := rotr x 7 ^^^ rotr x 18 ^^^ (x >>> 3)
def smallSigma1 (x : UInt32) : UInt32 := rotr x 17 ^^^ rotr x 19 ^^^ (x >>> 10)
def bigSigma0 (x : UInt32) : UInt32 := rotr x 2 ^^^ rotr x 13 ^^^ rotr x 22
def bigSigma1 (x : UInt32) : UInt32 := rotr x 6 ^^^ rotr x 11 ^^^ rotr x 25
def choose (e f g : UInt32) : UInt32 := (e &&& f) ^^^ (~~~e &&& g)
def majority (a b c : UInt32) : UInt32 := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)

end ShaIntrinsics

def _mm_add_epi32 (a b : M128) : M128 := .ofFn fun l => a[l] + b[l]

def _mm_set_epi64x (hi lo : Int64) : M128 :=
  #v[UInt32.ofNat lo.toUInt64.toNat, UInt32.ofNat (lo.toUInt64.toNat / 2^32),
    UInt32.ofNat hi.toUInt64.toNat, UInt32.ofNat (hi.toUInt64.toNat / 2^32)]

/-- Two immediate bits per output lane select a source lane. -/
def _mm_shuffle_epi32 (imm : Nat) (a : M128) : M128 := .ofFn fun l =>
  a[(⟨(imm / 2^(2*l.val)) % 4, Nat.mod_lt _ (by decide)⟩ : Fin 4)]

/-- Low 128 bits of `(a : b) >> (8 * imm)`, with zero fill. -/
def _mm_alignr_epi8 (imm : Nat) (a b : M128) : M128 :=
  ShaIntrinsics.fromBytes fun i =>
    let j := i + imm
    if j < 16 then ShaIntrinsics.byte b j
    else if j < 32 then ShaIntrinsics.byte a (j - 16)
    else 0

/-- Each immediate bit selects one 16-bit word: set selects `b`. -/
def _mm_blend_epi16 (imm : Nat) (a b : M128) : M128 :=
  ShaIntrinsics.fromBytes fun i =>
    ShaIntrinsics.byte (if imm.testBit (i / 2) then b else a) i

/-- Bit 7 zeroes an output byte; bits 0..3 select a byte; bits 4..6 are ignored. -/
def _mm_shuffle_epi8 (a mask : M128) : M128 :=
  ShaIntrinsics.fromBytes fun i =>
    let m := (ShaIntrinsics.byte mask i).toNat
    if m.testBit 7 then 0 else ShaIntrinsics.byte a (m % 16)

def _mm_sha256msg1_epu32 (a b : M128) : M128 :=
  #v[a[0] + ShaIntrinsics.smallSigma0 a[1], a[1] + ShaIntrinsics.smallSigma0 a[2],
    a[2] + ShaIntrinsics.smallSigma0 a[3], a[3] + ShaIntrinsics.smallSigma0 b[0]]

/-- The last two lanes depend on the newly computed first two lanes. -/
def _mm_sha256msg2_epu32 (a b : M128) : M128 :=
  let w16 := a[0] + ShaIntrinsics.smallSigma1 b[2]
  let w17 := a[1] + ShaIntrinsics.smallSigma1 b[3]
  #v[w16, w17, a[2] + ShaIntrinsics.smallSigma1 w16,
    a[3] + ShaIntrinsics.smallSigma1 w17]

/-- Inputs, high lane first, are CDGH and ABEF; output is ABEF after two rounds.
Only the low two lanes of `wk` are read. All additions are modulo 2^32. -/
def _mm_sha256rnds2_epu32 (cdgh abef wk : M128) : M128 :=
  let a := abef[3]; let b := abef[2]; let c := cdgh[3]; let d := cdgh[2]
  let e := abef[1]; let f := abef[0]; let g := cdgh[1]; let h := cdgh[0]
  let t1 := ShaIntrinsics.choose e f g + ShaIntrinsics.bigSigma1 e + wk[0] + h
  let a1 := t1 + ShaIntrinsics.majority a b c + ShaIntrinsics.bigSigma0 a
  let e1 := t1 + d
  let t2 := ShaIntrinsics.choose e1 e f + ShaIntrinsics.bigSigma1 e1 + wk[1] + g
  let a2 := t2 + ShaIntrinsics.majority a1 a b + ShaIntrinsics.bigSigma0 a1
  let e2 := t2 + c
  #v[e1, e2, a1, a2]

/-- Intel normalizes every nonzero carry input to 1. The pair is (carry, sum). -/
def _addcarry_u64 (carry : UInt8) (a b : UInt64) : UInt8 × UInt64 :=
  let sum := a.toNat + b.toNat + if carry = 0 then 0 else 1
  (UInt8.ofNat (sum / 2^64), UInt64.ofNat sum)

end LeanBlsSimd
