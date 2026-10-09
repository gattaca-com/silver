/-!
# The AVX-512 intrinsics of `fp8.rs`

The trusted model of the twelve intrinsics that `crates/bls_simd/src/fp8.rs` calls.
Each acts on every 64-bit lane alike, so each is a function on one `UInt64` lane, lifted to the
eight lanes of `M512`. Lane numbering matters only in the constructors and the masks.

Sources: the Intel SDM operation sections for `VPMADD52LUQ`, `VPMADD52HUQ`, `VPSRLQ` and `VPSRAQ`,
as mirrored at felixcloutier.com/x86, and Rust's `core::arch` at 1.91.0, the toolchain `silver`
pins. Rust defines the AVX-512F intrinsics through portable `simd_*` operations, which fix the
conventions below.

| Rust intrinsic | Lane `l` of the result |
|---|---|
| `_mm512_madd52lo_epu64(a, b, c)` | `madd52lo`: `a + (lo52 b · lo52 c) mod 2^52`, modulo 2^64 |
| `_mm512_madd52hi_epu64(a, b, c)` | `madd52hi`: `a + ⌊lo52 b · lo52 c / 2^52⌋`, modulo 2^64 |
| `_mm512_add_epi64(a, b)`, `_mm512_sub_epi64(a, b)` | `a + b`, `a - b`, modulo 2^64 |
| `_mm512_and_si512(a, b)` | `a &&& b` |
| `_mm512_srli_epi64::<IMM8>(a)` | `srli`: `a >>> IMM8`, or 0 when `IMM8 ≥ 64` |
| `_mm512_srai_epi64::<IMM8>(a)` | `srai`: arithmetic `a >>> min IMM8 63` |
| `_mm512_set_epi64(e7, …, e0)` | the `l`-th argument from the right |
| `_mm512_set1_epi64(a)`, `_mm512_setzero_si512()` | `a`, `0` |
| `_mm512_cmpeq_epi64_mask(a, b)` | bit `l` of the mask is `a = b` |
| `_mm512_mask_blend_epi64(k, a, b)` | `b` where bit `l` of `k` is set, else `a` |

The IFMA operands are truncated to their low 52 bits before the multiplication; the accumulator is
not. Rust's `_mm512_set_epi64` names its first parameter `e0` but forwards it to lane 7 through
`_mm512_setr_epi64`; the parameter names below follow the lanes. The `as i64` casts in `fp8.rs`
reinterpret bits, which `UInt64.toInt64` and `Int64.toUInt64` model.
-/

namespace LeanBlsSimd

/-- `__m512i`: lane `l` holds bits `64 l` to `64 l + 63`. -/
abbrev M512 := Vector UInt64 8

/-- `__mmask8`, which is `u8`. -/
abbrev Mmask8 := UInt8

/-! ## One lane -/

/-- The low 52 bits of an IFMA operand, which is all the instruction reads of it. -/
def lo52 (x : UInt64) : Nat := x.toNat % 2 ^ 52

def madd52lo (a b c : UInt64) : UInt64 := a + UInt64.ofNat (lo52 b * lo52 c % 2 ^ 52)

def madd52hi (a b c : UInt64) : UInt64 := a + UInt64.ofNat (lo52 b * lo52 c / 2 ^ 52)

def srli (imm : Nat) (a : UInt64) : UInt64 := if imm < 64 then a >>> imm.toUInt64 else 0

def srai (imm : Nat) (a : UInt64) : UInt64 := .ofBitVec (a.toBitVec.sshiftRight (min imm 63))

/-! ## Eight lanes -/

def _mm512_madd52lo_epu64 (a b c : M512) : M512 := .ofFn fun l => madd52lo a[l] b[l] c[l]

def _mm512_madd52hi_epu64 (a b c : M512) : M512 := .ofFn fun l => madd52hi a[l] b[l] c[l]

def _mm512_add_epi64 (a b : M512) : M512 := .ofFn fun l => a[l] + b[l]

def _mm512_sub_epi64 (a b : M512) : M512 := .ofFn fun l => a[l] - b[l]

def _mm512_and_si512 (a b : M512) : M512 := .ofFn fun l => a[l] &&& b[l]

def _mm512_srli_epi64 (IMM8 : Nat) (a : M512) : M512 := .ofFn fun l => srli IMM8 a[l]

def _mm512_srai_epi64 (IMM8 : Nat) (a : M512) : M512 := .ofFn fun l => srai IMM8 a[l]

def _mm512_set_epi64 (e7 e6 e5 e4 e3 e2 e1 e0 : Int64) : M512 :=
  #v[e0, e1, e2, e3, e4, e5, e6, e7].map Int64.toUInt64

def _mm512_set1_epi64 (a : Int64) : M512 := .replicate 8 a.toUInt64

def _mm512_setzero_si512 : M512 := .replicate 8 0

def _mm512_cmpeq_epi64_mask (a b : M512) : Mmask8 :=
  .ofNat ((List.finRange 8).map fun l => if a[l] = b[l] then 2 ^ l.val else 0).sum

def _mm512_mask_blend_epi64 (k : Mmask8) (a b : M512) : M512 :=
  .ofFn fun l => if k.toNat.testBit l then b[l] else a[l]

end LeanBlsSimd
