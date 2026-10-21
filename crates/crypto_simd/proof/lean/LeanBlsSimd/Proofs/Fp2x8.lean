import LeanBlsSimd.Model.Fp2x8
import LeanBlsSimd.Proofs.Fp8Lazy

/-!
# `Fp2x8`, lane by lane

`Fp8.Holds x l a` says that lane `l` of `x` holds the field element `a`: its limbs meet `Fp8Inv`,
and they decode to `a`. `Fp2x8.Holds x l v` says the same of both components, read as
`v : Fp2Field`. Raw operations track component bounds through `LazyRep` and `BoundRep`;
multiplication and squaring return `Holds`. Each mask has bit `l` set exactly when the field-level
test holds. These statements speak of lane `l` alone, so they hold whatever the other lanes hold.

`Fp2x8.Holds.sqrt` lands on `Kernel.sqrt`, the kernel's root over the field, so `Kernel.sqrt_agrees`
and `Kernel.sqrt_fails` apply to the model. `Fp2x8.Holds.testBit_is_larger_root_mask` lands on
`Kernel.isLargerRoot`, which `Kernel.isLargerRoot_toField` identifies with the spec's
`Fp2.signBit`.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

/-! ## `Fp2x8` -/

namespace Fp2x8

/-- Lane `l` of `x` holds `v`: `c0` holds its real part and `c1` its coefficient of i. -/
structure Holds (x : Fp2x8) (l : Fin 8) (v : Fp2Field) : Prop where
  re : x.c0.Holds l v.re
  im : x.c1.Holds l v.im

variable {x y : Fp2x8} {l : Fin 8} {v w : Fp2Field}

theorem Holds.of_eq (h : x.Holds l v) (hvw : v = w) : x.Holds l w := hvw ▸ h

structure LazyRep (k m : ℕ) (x : Fp2x8) (l : Fin 8) (v : Fp2Field) : Prop where
  re : Fp8.LazyRep k m x.c0 l v.re
  im : Fp8.LazyRep k m x.c1 l v.im

structure BoundRep (k : ℕ) (x : Fp2x8) (l : Fin 8) (v : Fp2Field) : Prop where
  re : Fp8.BoundRep k x.c0 l v.re
  im : Fp8.BoundRep k x.c1 l v.im

variable {k m k' m' c : ℕ} {offset : Fp8}

theorem Holds.boundRep (h : x.Holds l v) : BoundRep 2 x l v :=
  ⟨h.re.boundRep, h.im.boundRep⟩

theorem BoundRep.mono (h : BoundRep k x l v) (hk : k ≤ k') : BoundRep k' x l v :=
  ⟨h.re.mono hk, h.im.mono hk⟩

theorem BoundRep.lazyRep (h : BoundRep k x l v) : LazyRep k 1 x l v :=
  ⟨h.re.lazyRep, h.im.lazyRep⟩

theorem Holds.lazyRep (h : x.Holds l v) : LazyRep 2 1 x l v := h.boundRep.lazyRep

theorem BoundRep.holds (h : BoundRep k x l v) (hk : k ≤ 2) : x.Holds l v :=
  ⟨h.re.holds hk, h.im.holds hk⟩

theorem LazyRep.add_raw (hx : LazyRep k m x l v) (hy : LazyRep k' m' y l w)
    (hm : m + m' ≤ 1024) : LazyRep (k + k') (m + m') (x.add_raw y) l (v + w) :=
  ⟨hx.re.add_raw hy.re hm, hx.im.add_raw hy.im hm⟩

theorem LazyRep.sub_raw (hx : LazyRep k m x l v) (hy : LazyRep k' m' y l w)
    (ho : Fp8.Offset c offset l) (hc : k' ≤ c) (hm : m + m' + 1 ≤ 1024) :
    LazyRep (k + c) (m + m' + 1) (x.sub_raw y offset) l (v - w) :=
  ⟨hx.re.sub_raw hy.re ho hc hm, hx.im.sub_raw hy.im ho hc hm⟩

theorem LazyRep.normalise (h : LazyRep k m x l v) (hk : k ≤ 1024) (hm : m ≤ 1024) :
    BoundRep k x.normalise l v :=
  ⟨h.re.normalise hk hm, h.im.normalise hk hm⟩

theorem BoundRep.cond_sub (hx : BoundRep k x l v) (ho : Fp8.Offset c offset l)
    (hk : k ≤ 2 * c) : BoundRep c (x.cond_sub offset) l v :=
  ⟨hx.re.cond_sub ho hk, hx.im.cond_sub ho hk⟩

theorem LazyRep.reduced_from_4p (h : LazyRep k m x l v)
    (hk : k ≤ 4) (hm : m ≤ 1024) :
    (x.normalise.cond_sub (Fp8.multiple_of_p 2)).Holds l v :=
  ⟨h.re.reduced_from_4p hk hm, h.im.reduced_from_4p hk hm⟩

theorem LazyRep.reduced_from_8p (h : LazyRep k m x l v)
    (hk : k ≤ 8) (hm : m ≤ 1024) :
    ((x.normalise.cond_sub (Fp8.multiple_of_p 4)).cond_sub (Fp8.multiple_of_p 2)).Holds l v :=
  ⟨h.re.reduced_from_8p hk hm, h.im.reduced_from_8p hk hm⟩

theorem BoundRep.mul (hx : BoundRep k x l v) (hy : BoundRep k' y l w)
    (hk : k ≤ 16) (hk' : k' ≤ 16) : (x.mul y).Holds l (v * w) := by
  have hx := hx.mono hk
  have hy := hy.mono hk'
  have h0 := hx.re.mul hy.re (by decide)
  have h1 := hx.im.mul hy.im (by decide)
  have hs := (hx.re.lazyRep.add_raw hx.im.lazyRep (by decide)).normalise (by decide) (by decide)
  have ht := (hy.re.lazyRep.add_raw hy.im.lazyRep (by decide)).normalise (by decide) (by decide)
  exact ⟨(h0.sub h1).of_eq (by simp only [QuadraticAlgebra.re_mul]; ring),
    (((hs.mul ht (by decide)).sub h0).sub h1).of_eq (by
      simp only [QuadraticAlgebra.im_mul]; ring)⟩

theorem BoundRep.square (hx : BoundRep k x l v) (hk : k ≤ 8) :
    x.square.Holds l (v ^ 2) := by
  have hx := hx.mono hk
  have hs := (hx.re.lazyRep.add_raw hx.im.lazyRep (by decide)).normalise (by decide) (by decide)
  have hd := (hx.re.lazyRep.sub_raw hx.im.lazyRep (Fp8.offset_eight l)
    (by decide) (by decide)).normalise (by decide) (by decide)
  have ht := (hx.im.lazyRep.add_raw hx.im.lazyRep (by decide)).normalise (by decide) (by decide)
  exact ⟨(hs.mul hd (by decide)).of_eq (by simp only [sq, QuadraticAlgebra.re_mul]; ring),
    (hx.re.mul ht (by decide)).of_eq (by simp only [sq, QuadraticAlgebra.im_mul]; ring)⟩

theorem Holds.mul (hx : x.Holds l v) (hy : y.Holds l w) : (x.mul y).Holds l (v * w) :=
  hx.boundRep.mul hy.boundRep (by decide) (by decide)

theorem Holds.square (hx : x.Holds l v) : x.square.Holds l (v ^ 2) :=
  hx.boundRep.square (by decide)

theorem Holds.add (hx : x.Holds l v) (hy : y.Holds l w) : (x.add y).Holds l (v + w) :=
  ⟨hx.re.add hy.re, hx.im.add hy.im⟩

theorem Holds.sub (hx : x.Holds l v) (hy : y.Holds l w) : (x.sub y).Holds l (v - w) :=
  ⟨hx.re.sub hy.re, hx.im.sub hy.im⟩

theorem Holds.neg (hx : x.Holds l v) : x.neg.Holds l (-v) := ⟨hx.re.neg, hx.im.neg⟩

theorem Holds.conjugate (hx : x.Holds l v) : x.conjugate.Holds l (star v) :=
  ⟨hx.re.of_eq (by simp), hx.im.neg⟩

theorem Holds.mul_by_i (hx : x.Holds l v) : x.mul_by_i.Holds l (v * QuadraticAlgebra.omega) :=
  ⟨hx.im.neg.of_eq (by simp), hx.re.of_eq (by simp)⟩

theorem Holds.select (k : Mmask8) (hx : x.Holds l v) (hy : y.Holds l w) :
    (select k x y).Holds l (if k.toNat.testBit l then w else v) := by
  constructor
  · exact (hx.re.select k hy.re).of_eq (by split <;> rfl)
  · exact (hx.im.select k hy.im).of_eq (by split <;> rfl)

theorem Holds.testBit_eq_mask (hx : x.Holds l v) (hy : y.Holds l w) :
    (x.eq_mask y).toNat.testBit l = decide (v = w) := by
  rw [eq_mask, Mmask8.testBit_and, hx.re.testBit_eq_mask hy.re, hx.im.testBit_eq_mask hy.im,
    ← Bool.decide_and]
  exact decide_eq_decide.mpr QuadraticAlgebra.ext_iff.symm

theorem Holds.testBit_is_zero_mask (hx : x.Holds l v) :
    x.is_zero_mask.toNat.testBit l = decide (v = 0) := by
  rw [is_zero_mask, Mmask8.testBit_and, hx.re.testBit_is_zero_mask, hx.im.testBit_is_zero_mask,
    ← Bool.decide_and]
  exact decide_eq_decide.mpr ⟨fun h => QuadraticAlgebra.ext h.1 h.2, fun h => by simp [h]⟩

theorem Holds.testBit_is_larger_root_mask (hx : x.Holds l v) :
    x.is_larger_root_mask.toNat.testBit l = Kernel.isLargerRoot v := by
  rw [is_larger_root_mask, Mmask8.testBit_or, Mmask8.testBit_and,
    hx.im.testBit_is_larger_root_mask, hx.re.testBit_is_larger_root_mask,
    hx.im.testBit_is_zero_mask, Kernel.isLargerRoot]

theorem holds_one (l : Fin 8) : one.Holds l 1 := ⟨Fp8.holds_one l, Fp8.holds_zero l⟩

/-- The model's root is the kernel's root over the field, `Kernel.sqrt`, on every lane. -/
theorem Holds.sqrt (hx : x.Holds l v) :
    x.sqrt.1.Holds l (Kernel.sqrt v).1 ∧ x.sqrt.2.toNat.testBit l = (Kernel.sqrt v).2 := by
  have hn := (hx.re.square.add hx.im.square).sqrt_candidate
  have hplus := hx.re.add hn
  set t := (Fp8.select (x.c0.add (x.c0.square.add x.c1.square).sqrt_candidate).is_zero_mask
    (x.c0.add (x.c0.square.add x.c1.square).sqrt_candidate)
    (x.c0.sub (x.c0.square.add x.c1.square).sqrt_candidate)).half
  have ht : t.Holds l (Kernel.sqrtT v) := ((Fp8.Holds.select _ hplus (hx.re.sub hn)).half).of_eq (by
      rw [hplus.testBit_is_zero_mask]
      simp only [Kernel.sqrtT, decide_eq_true_eq])
  have hr := ht.pow_p_minus_3_over_4
  have hc : Holds ⟨t.mul t.pow_p_minus_3_over_4, x.c1.half.mul t.pow_p_minus_3_over_4⟩ l
      (Kernel.rootCandidate v) := ⟨ht.mul hr, hx.im.half.mul hr⟩
  have hsq := hc.square
  have hself := hsq.testBit_eq_mask hx
  have hneg := hsq.testBit_eq_mask hx.neg
  refine ⟨(hc.select _ hc.mul_by_i).of_eq ?_, ?_⟩
  · rw [hneg]
    simp only [Kernel.sqrt, decide_eq_true_eq]
  · rw [Fp2x8.sqrt, Mmask8.testBit_or, hself, hneg]
    simp only [Kernel.sqrt]

end Fp2x8

end LeanBlsSimd
