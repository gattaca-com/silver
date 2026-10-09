import LeanBlsSimd.Constants
import LeanBlsSimd.Model.Intrinsics

/-!
# `fp8.rs`

`crates/bls_simd/src/fp8.rs`, transcribed one statement per Rust statement.

`Fp8::mul` and the operations built only from it are lifted from `Lane`: every intrinsic `mul`
calls is lane-wise, so lane `l` of its result is one computation on lane `l` of its inputs.
`Lane` holds that computation, with each `__m512i` replaced by its lane and each intrinsic by its
lane semantics. `Fp8.ofLanes` lifts it to eight lanes.

The operations that compare, mask or blend are transcribed on whole vectors instead, from the
`_mm512_*` definitions of `Model/Intrinsics.lean`, so that the lane order, the mask bits and the
blend polarity enter their proofs. `Simd` holds the free functions of `fp8.rs` on `__m512i`.

Rust's arrays are `Vector`s, whose index bounds Lean checks statically where Rust checks them at
run time. The exceptions are `pack64`'s `out[word]` and the window and table lookups of
`pow_p_minus_3_over_4`, whose indices are run-time values in Rust too; they use `!`.
-/

namespace LeanBlsSimd

instance : NeZero LIMBS := ⟨by decide⟩

/-- `Limbs` of `fp8.rs`, and one lane of an `Fp8`. -/
abbrev Limbs := Vector UInt64 LIMBS

/-- A table of `Constants`, as the `[u64; LIMBS]` of `constants.rs`. -/
def Limbs.ofList (xs : List ℕ) : Limbs := .ofFn fun j => .ofNat (xs.getD j 0)

/-! ## One lane of `Fp8::mul` -/

namespace Lane

def splat (x : UInt64) : UInt64 := x.toInt64.toUInt64

def zero : UInt64 := 0

def splat_limbs (limbs : Limbs) : Limbs := .ofFn fun j => splat limbs[j]

/-- One lane of the accumulator `[__m512i; 2 * LIMBS + 1]` of `Fp8::mul`. -/
abbrev Acc := Vector UInt64 (2 * LIMBS + 1)

def muladd_row (t : Acc) (a : Limbs) (b_i : UInt64) (i : Fin LIMBS) : Acc :=
  (List.finRange LIMBS).foldl (init := t) fun t (j : Fin LIMBS) =>
    let t := t.set (i.val + j.val) (madd52lo t[i.val + j.val] a[j] b_i)
    t.set (i.val + j.val + 1) (madd52hi t[i.val + j.val + 1] a[j] b_i)

def reduce_row (t : Acc) (p : Limbs) (pinv : UInt64) (i : Fin LIMBS) : Acc :=
  let q := madd52lo zero t[i.val] pinv
  let t := (List.finRange LIMBS).foldl (init := t) fun t (j : Fin LIMBS) =>
    let t := t.set (i.val + j.val) (madd52lo t[i.val + j.val] q p[j])
    t.set (i.val + j.val + 1) (madd52hi t[i.val + j.val + 1] q p[j])
  t.set (i.val + 1) (t[i.val + 1] + srli 52 t[i.val])

def mul (self rhs : Limbs) : Limbs :=
  let p := splat_limbs (.ofList P)
  let pinv := splat (.ofNat P_INV52)
  let t : Acc := .replicate _ zero
  let t := muladd_row t self rhs[0] 0
  let t := muladd_row t self rhs[1] 1
  let t := muladd_row t self rhs[2] 2
  let t := muladd_row t self rhs[3] 3
  let t := muladd_row t self rhs[4] 4
  let t := muladd_row t self rhs[5] 5
  let t := muladd_row t self rhs[6] 6
  let t := muladd_row t self rhs[7] 7
  let t := reduce_row t p pinv 0
  let t := reduce_row t p pinv 1
  let t := reduce_row t p pinv 2
  let t := reduce_row t p pinv 3
  let t := reduce_row t p pinv 4
  let t := reduce_row t p pinv 5
  let t := reduce_row t p pinv 6
  let t := reduce_row t p pinv 7

  let mask := splat (.ofNat MASK52)
  let r : Limbs := .replicate _ zero
  let r := r.set 0 t[LIMBS]
  (List.finRange (LIMBS - 1)).foldl (init := r) fun r (j : Fin (LIMBS - 1)) =>
    let r := r.set (j.val + 1) (t[LIMBS + j.val + 1] + srli 52 r[j.val])
    r.set j.val (r[j.val] &&& mask)

end Lane

/-! ## The free functions on `__m512i` -/

namespace Simd

def splat (x : UInt64) : M512 := _mm512_set1_epi64 x.toInt64

def zero : M512 := _mm512_setzero_si512

def splat_limbs (limbs : Limbs) : Vector M512 LIMBS := .ofFn fun j => splat limbs[j]

/-- The `transmute` of `lanes`: element `l` of `[u64; 8]` is lane `l`, as `M512` lays it out. -/
def lanes (v : M512) : Vector UInt64 8 := v

def sub_limbs (a b : Vector M512 LIMBS) : Vector M512 LIMBS × M512 :=
  let mask := splat (.ofNat MASK52)
  (List.finRange LIMBS).foldl (init := (.replicate _ zero, zero)) fun (d, borrow) (j : Fin LIMBS) =>
    let s := _mm512_add_epi64 (_mm512_sub_epi64 a[j] b[j]) borrow
    let borrow := _mm512_srai_epi64 63 s
    (d.set j (_mm512_and_si512 s mask), borrow)

def add_limbs (a b : Vector M512 LIMBS) : Vector M512 LIMBS :=
  let mask := splat (.ofNat MASK52)
  let (s, _) := (List.finRange LIMBS).foldl (init := (.replicate _ zero, zero))
    fun (s, carry) (j : Fin LIMBS) =>
      let t := _mm512_add_epi64 (_mm512_add_epi64 a[j] b[j]) carry
      let carry := _mm512_srli_epi64 52 t
      (s.set j (_mm512_and_si512 t mask), carry)
  s

def blend (k : Mmask8) (a b : Vector M512 LIMBS) : Vector M512 LIMBS :=
  .ofFn fun j => _mm512_mask_blend_epi64 k a[j] b[j]

def borrowed (borrow : M512) : Mmask8 :=
  _mm512_cmpeq_epi64_mask borrow (splat 0xffffffffffffffff)

def two_p : Vector M512 LIMBS := add_limbs (splat_limbs (.ofList P)) (splat_limbs (.ofList P))

end Simd

/-! ## Conversions between 64-bit words and 52-bit limbs -/

def unpack52 (x : Vector UInt64 6) : Limbs :=
  .ofFn fun j =>
    let bit := j.val * LIMB_BITS
    let word := bit / 64
    let shift := bit % 64
    have hword : word < 6 := by
      show j.val * LIMB_BITS / 64 < 6
      have := j.isLt
      simp only [LIMBS, LIMB_BITS] at this ⊢
      omega
    let v := x[word] >>> shift.toUInt64
    let v :=
      if h : shift > 12 ∧ word + 1 < 6 then v ||| x[word + 1]'h.2 <<< (64 - shift).toUInt64
      else v
    v &&& .ofNat MASK52

/-- `u128` is `BitVec 128`; `as u128` zero-extends and `as u64` truncates. -/
def pack64 (x : Limbs) : Vector UInt64 6 :=
  let (out, acc, _, word) := (List.finRange LIMBS).foldl
    (init := (Vector.replicate 6 (0 : UInt64), (0 : BitVec 128), (0 : ℕ), (0 : ℕ)))
    fun (out, acc, acc_bits, word) (j : Fin LIMBS) =>
      let acc := acc ||| x[j].toBitVec.setWidth 128 <<< acc_bits
      let acc_bits := acc_bits + LIMB_BITS
      if acc_bits ≥ 64 then
        (out.set! word (.ofBitVec (acc.setWidth 64)), acc >>> 64, acc_bits - 64, word + 1)
      else (out, acc, acc_bits, word)
  if h : word < 6 then out.set word (.ofBitVec (acc.setWidth 64)) h else out

/-- `Fp8` of `fp8.rs`. -/
structure Fp8 where
  limbs : Vector M512 LIMBS
deriving Inhabited

namespace Fp8

def lane (x : Fp8) (l : Fin 8) : Limbs := x.limbs.map (·[l])

def ofLanes (lanes : Vector Limbs 8) : Fp8 := ⟨.ofFn fun j => .ofFn fun l => lanes[l][j]⟩

def splat_limbs (limbs : Limbs) : Fp8 := ⟨Simd.splat_limbs limbs⟩

def zero : Fp8 := ⟨.replicate _ Simd.zero⟩

def one : Fp8 := splat_limbs (.ofList R_MOD_P)

def load (values : Vector Limbs 8) : Fp8 :=
  ⟨.ofFn fun j => _mm512_set_epi64 values[7][j].toInt64 values[6][j].toInt64
    values[5][j].toInt64 values[4][j].toInt64 values[3][j].toInt64 values[2][j].toInt64
    values[1][j].toInt64 values[0][j].toInt64⟩

def store (self : Fp8) : Vector Limbs 8 :=
  (List.finRange LIMBS).foldl (init := .replicate 8 (.replicate LIMBS 0)) fun out (j : Fin LIMBS) =>
    let l := Simd.lanes self.limbs[j]
    (List.finRange 8).foldl (init := out) fun out (lane : Fin 8) => out.set lane (out[lane].set j l[lane])

def mul (self rhs : Fp8) : Fp8 := ofLanes (.ofFn fun l => Lane.mul (self.lane l) (rhs.lane l))

def square (self : Fp8) : Fp8 := self.mul self

def from_plain (values : Vector Limbs 8) : Fp8 := (load values).mul (splat_limbs (.ofList R2_MOD_P))

def canonical (self : Fp8) : Fp8 :=
  let (d, borrow) := Simd.sub_limbs self.limbs (Simd.splat_limbs (.ofList P))
  ⟨Simd.blend (Simd.borrowed borrow) d self.limbs⟩

def to_plain (self : Fp8) : Vector Limbs 8 :=
  (self.mul (splat_limbs (.ofList ONE_PLAIN))).canonical.store

def to_blst_limbs (self : Fp8) : Vector (Vector UInt64 6) 8 :=
  let t := (self.mul (splat_limbs (.ofList TWO_POW_384_MOD_P))).canonical.store
  .ofFn fun lane => pack64 t[lane]

def add (self rhs : Fp8) : Fp8 :=
  let s := Simd.add_limbs self.limbs rhs.limbs
  let (d, borrow) := Simd.sub_limbs s Simd.two_p
  ⟨Simd.blend (Simd.borrowed borrow) d s⟩

def sub (self rhs : Fp8) : Fp8 :=
  let (d, borrow) := Simd.sub_limbs self.limbs rhs.limbs
  let wrapped := Simd.add_limbs d Simd.two_p
  ⟨Simd.blend (Simd.borrowed borrow) d wrapped⟩

def neg (self : Fp8) : Fp8 := Fp8.zero.sub self

def double (self : Fp8) : Fp8 := self.add self

def half (self : Fp8) : Fp8 := self.mul (splat_limbs (.ofList HALF_MONT))

def eq_mask (self rhs : Fp8) : Mmask8 :=
  let a := self.canonical
  let b := rhs.canonical
  (List.finRange LIMBS).foldl (init := 0xff) fun k (j : Fin LIMBS) =>
    k &&& _mm512_cmpeq_epi64_mask a.limbs[j] b.limbs[j]

def is_zero_mask (self : Fp8) : Mmask8 :=
  let a := self.canonical
  (List.finRange LIMBS).foldl (init := 0xff) fun k (j : Fin LIMBS) =>
    k &&& _mm512_cmpeq_epi64_mask a.limbs[j] Simd.zero

def select (k : Mmask8) (a b : Fp8) : Fp8 := ⟨Simd.blend k a.limbs b.limbs⟩

def pow_p_minus_3_over_4 (self : Fp8) : Fp8 :=
  let table : Vector Fp8 16 := .replicate 16 one
  let table := table.set 1 self
  let table := ((List.finRange 16).drop 2).foldl (init := table) fun table (k : Fin 16) =>
    table.set k (table[k.val - 1].mul self)
  let r := table[P_MINUS_3_OVER_4_WINDOWS[94]!]!
  (List.range 94).reverse.foldl (init := r) fun r w =>
    let r := r.square.square.square.square
    let digit := P_MINUS_3_OVER_4_WINDOWS[w]!
    if digit ≠ 0 then r.mul table[digit]! else r

def sqrt_candidate (self : Fp8) : Fp8 := self.pow_p_minus_3_over_4.mul self

def is_larger_root_mask (self : Fp8) : Mmask8 :=
  let plain := load self.to_plain
  let (_, borrow) := Simd.sub_limbs (Simd.splat_limbs (.ofList HALF_P_MINUS_1)) plain.limbs
  Simd.borrowed borrow

end Fp8

end LeanBlsSimd
