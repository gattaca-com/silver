import LeanBlsSimd.Model.Intrinsics
import LeanBlsSimd.Constants

/-! Five-limb lane and vector models of the Fr arithmetic in `kzg/fr8.rs`.
The intrinsic operations retain their UInt64 wrapping semantics. -/

namespace LeanBlsSimd.FrModel

def LIMBS : Nat := 5
def LIMB_BITS : Nat := 52
def MASK52 : Nat := 2 ^ 52 - 1
def P : List Nat := [0xfffff00000001, 0x2fffe5bfefff, 0x9a1d80553bda4,
  0x7d483339d8080, 0x73eda753299d]
def P_INV52 : Nat := 0xffffeffffffff
def R : Nat := 2 ^ (LIMBS * LIMB_BITS)

instance : NeZero LIMBS := ⟨by decide⟩

/-- `Limbs` of `fr8.rs`, and one lane of an `Fr8`. -/
abbrev Limbs := Vector UInt64 LIMBS

/-- A table of `Constants`, as the `[u64; LIMBS]` of `constants.rs`. -/
def Limbs.ofList (xs : List ℕ) : Limbs := .ofFn fun j => .ofNat (xs.getD j 0)

/-! ## One lane of `Fr8::mul` -/

namespace Lane

def splat (x : UInt64) : UInt64 := x.toInt64.toUInt64

def zero : UInt64 := 0

def splat_limbs (limbs : Limbs) : Limbs := .ofFn fun j => splat limbs[j]

/-- One lane of the accumulator `[__m512i; 2 * LIMBS + 1]` of `Fr8::mul`. -/
abbrev Acc := Vector UInt64 (2 * LIMBS + 1)

def muladd_row (t : Acc) (a : Limbs) (b_i : UInt64) (i : Fin LIMBS) : Acc :=
  (List.finRange LIMBS).foldl (init := t) fun t (j : Fin LIMBS) =>
    let t := t.set (i.val + j.val) (madd52lo t[i.val + j.val] a[j] b_i)
    t.set (i.val + j.val + 1) (madd52hi t[i.val + j.val + 1] a[j] b_i)

def reduce_row (t : Acc) (p : Limbs) (pinv : UInt64) (i : Fin LIMBS) : Acc :=
  let q := madd52lo zero t[i.val] pinv
  let t := muladd_row t p q i
  t.set (i.val + 1) (t[i.val + 1] + srli 52 t[i.val])

/-- The accumulator `t` of `Fr8::mul` after its ten rows. -/
def mulAcc (self rhs : Limbs) : Acc :=
  let p := splat_limbs (.ofList P)
  let pinv := splat (.ofNat P_INV52)
  let t : Acc := .replicate _ zero
  let t := muladd_row t self rhs[0] 0
  let t := muladd_row t self rhs[1] 1
  let t := muladd_row t self rhs[2] 2
  let t := muladd_row t self rhs[3] 3
  let t := muladd_row t self rhs[4] 4
  let t := reduce_row t p pinv 0
  let t := reduce_row t p pinv 1
  let t := reduce_row t p pinv 2
  let t := reduce_row t p pinv 3
  reduce_row t p pinv 4

/-- The body of the carry loop that ends `Fr8::mul`. -/
def carryStep (t : Acc) (mask : UInt64) (r : Limbs) (j : Fin (LIMBS - 1)) : Limbs :=
  let r := r.set (j.val + 1) (t[LIMBS + j.val + 1] + srli 52 r[j.val])
  r.set j.val (r[j.val] &&& mask)

def mul (self rhs : Limbs) : Limbs :=
  let t := mulAcc self rhs
  let mask := splat (.ofNat MASK52)
  let r : Limbs := .replicate _ zero
  let r := r.set 0 t[LIMBS]
  (List.finRange (LIMBS - 1)).foldl (carryStep t mask) r

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

/-- `Fr8` of `fr8.rs`. -/
structure Fr8 where
  limbs : Vector M512 LIMBS
deriving Inhabited

namespace Fr8

def lane (x : Fr8) (l : Fin 8) : Limbs := x.limbs.map (·[l])

def ofLanes (lanes : Vector Limbs 8) : Fr8 := ⟨.ofFn fun j => .ofFn fun l => lanes[l][j]⟩

def splat_limbs (limbs : Limbs) : Fr8 := ⟨Simd.splat_limbs limbs⟩

def zero : Fr8 := ⟨.replicate _ Simd.zero⟩

def mul (self rhs : Fr8) : Fr8 := ofLanes (.ofFn fun l => Lane.mul (self.lane l) (rhs.lane l))

def canonical (self : Fr8) : Fr8 :=
  let (d, borrow) := Simd.sub_limbs self.limbs (Simd.splat_limbs (.ofList P))
  ⟨Simd.blend (Simd.borrowed borrow) d self.limbs⟩

def add (self rhs : Fr8) : Fr8 :=
  let s := Simd.add_limbs self.limbs rhs.limbs
  let (d, borrow) := Simd.sub_limbs s Simd.two_p
  ⟨Simd.blend (Simd.borrowed borrow) d s⟩

def sub (self rhs : Fr8) : Fr8 :=
  let (d, borrow) := Simd.sub_limbs self.limbs rhs.limbs
  let wrapped := Simd.add_limbs d Simd.two_p
  ⟨Simd.blend (Simd.borrowed borrow) d wrapped⟩


end Fr8

end LeanBlsSimd.FrModel
