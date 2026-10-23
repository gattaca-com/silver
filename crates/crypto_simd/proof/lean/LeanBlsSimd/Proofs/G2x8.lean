import LeanBlsSimd.Model.G2x8
import LeanBlsSimd.Proofs.Fp2x8
import LeanBlsSimd.Spec.Membership

/-!
# `G2x8`, lane by lane

`G2x8.Holds P l t` says that lane `l` of `P` holds the field triple `t`. Each operation of
`g2x8.rs` maps it to the triple and the undecided bit of its field restatement in `Kernel`:
`G2x8.double` to `Kernel.double`, `add_affine` to `Kernel.addAffine`, `times_minus_z` to
`Kernel.timesMinusZ` and `scott_membership` to `Kernel.scottMembership`. `Spec/Membership.lean`
proves what those compute.
-/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls WeierstrassCurve Jacobian

theorem List.foldl_rel {α β γ : Type*} (R : α → β → Prop) (f : α → γ → α) (g : β → γ → β)
    (hstep : ∀ a b c, R a b → R (f a c) (g b c)) :
    ∀ (l : List γ) (a : α) (b : β), R a b → R (l.foldl f a) (l.foldl g b)
  | [], _, _, h => h
  | c :: l, a, b, h => List.foldl_rel R f g hstep l (f a c) (g b c) (hstep a b c h)

theorem Fp2x8.holds_splat_PSI_Y (l : Fin 8) :
    (Fp2x8.splat #v[.ofList PSI_Y_MONT[0]!, .ofList PSI_Y_MONT[1]!]).Holds l ⟨psiY.1, psiY.2⟩ :=
  ⟨(Fp8.holds_splat_limbs inv_ofList_PSI_Y_MONT_0 l).of_eq decode_ofList_PSI_Y_MONT_0,
    (Fp8.holds_splat_limbs inv_ofList_PSI_Y_MONT_1 l).of_eq decode_ofList_PSI_Y_MONT_1⟩

namespace G2x8

/-- Lane `l` of `P` holds the triple `t`. -/
structure Holds (P : G2x8) (l : Fin 8) (t : Fin 3 → Fp2Field) : Prop where
  x : P.x.Holds l (t 0)
  y : P.y.Holds l (t 1)
  z : P.z.Holds l (t 2)

variable {P : G2x8} {l : Fin 8} {t : Fin 3 → Fp2Field}

private theorem reduced_from_4p_holds {k m : ℕ} {v : Fp2x8} {l : Fin 8}
    {a : Fp2Field} (h : Fp2x8.LazyRep k m v l a)
    (hk : k ≤ 4) (hm : m ≤ 1024) : (Offsets.new.reduced_from_4p v).Holds l a := by
  exact h.reduced_from_4p hk hm

private theorem reduced_from_8p_holds {k m : ℕ} {v : Fp2x8} {l : Fin 8}
    {a : Fp2Field} (h : Fp2x8.LazyRep k m v l a)
    (hk : k ≤ 8) (hm : m ≤ 1024) : (Offsets.new.reduced_from_8p v).Holds l a := by
  exact h.reduced_from_8p hk hm

theorem Holds.double (hP : P.Holds l t) :
    P.double.1.Holds l (Kernel.double t).1 ∧
      P.double.2.toNat.testBit l = (Kernel.double t).2 := by
  have ha := hP.x.square
  have hb := hP.y.square
  have he := ((ha.lazyRep.add_raw ha.lazyRep (by decide)).add_raw ha.lazyRep
    (by decide)).normalise (by decide) (by decide)
  have hf := he.square (by decide)
  have hc := hb.square
  have hxb := (hP.x.lazyRep.add_raw hb.lazyRep (by decide)).normalise
    (by decide) (by decide)
  have hxb2 := hxb.square (by decide)
  have hyz := hP.y.mul hP.z
  have hd0 := reduced_from_8p_holds
    ((hxb2.lazyRep.sub_raw ha.lazyRep (Fp8.offset_two l) (by decide) (by decide)).sub_raw
      hc.lazyRep (Fp8.offset_two l) (by decide) (by decide)) (by decide) (by decide)
  have hd := reduced_from_4p_holds (hd0.lazyRep.add_raw hd0.lazyRep (by decide))
    (by decide) (by decide)
  have hx3' := (hf.lazyRep.sub_raw (hd.lazyRep.add_raw hd.lazyRep (by decide))
    (Fp8.offset_four l) (by decide) (by decide)).normalise (by decide) (by decide)
  have hdx := (hd.lazyRep.sub_raw hx3'.lazyRep (Fp8.offset_eight l)
    (by decide) (by decide)).normalise (by decide) (by decide)
  have hc8 := reduced_from_8p_holds
    (((hc.lazyRep.add_raw hc.lazyRep (by decide)).add_raw hc.lazyRep (by decide)).add_raw
      hc.lazyRep (by decide)) (by decide) (by decide)
  have hy3 := reduced_from_8p_holds
    ((he.mul hdx (by decide) (by decide)).lazyRep.sub_raw (hc8.lazyRep.add_raw hc8.lazyRep (by decide))
      (Fp8.offset_four l) (by decide) (by decide)) (by decide) (by decide)
  have hz3 := reduced_from_4p_holds (hyz.lazyRep.add_raw hyz.lazyRep (by decide))
    (by decide) (by decide)
  have hx3 := ((hx3'.cond_sub (Fp8.offset_four l) (by decide)).cond_sub
    (Fp8.offset_two l) (by decide)).holds (by decide)
  refine ⟨⟨hx3.of_eq ?_, hy3.of_eq ?_, hz3.of_eq ?_⟩, ?_⟩
  rotate_left 3
  · rw [G2x8.double, Mmask8.testBit_or, hP.y.testBit_is_zero_mask, hP.z.testBit_is_zero_mask]
    rfl
  all_goals
    simp only [Kernel.double, dblXYZ, dblX, dblY, dblZ, negDblY, dblU_eq, negY,
      Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons,
      Matrix.tail_cons, E'.a₁_eq, E'.a₂_eq, E'.a₃_eq, E'.a₄_eq]
    ring1

theorem Holds.add_affine (hP : P.Holds l t) {qx qy : Fp2x8} {vx vy : Fp2Field}
    (hqx : qx.Holds l vx) (hqy : qy.Holds l vy) :
    (P.add_affine qx qy).1.Holds l (Kernel.addAffine t vx vy).1 ∧
      (P.add_affine qx qy).2.toNat.testBit l = (Kernel.addAffine t vx vy).2 := by
  have hz1z1 := hP.z.square
  have hs2 := (hqy.mul hP.z).mul hz1z1
  have hh := (hqx.mul hz1z1).sub hP.x
  have hhh := hh.square
  have hzh := (hP.z.lazyRep.add_raw hh.lazyRep (by decide)).normalise
    (by decide) (by decide)
  have hzh2 := hzh.square (by decide)
  have hi := (((hhh.lazyRep.add_raw hhh.lazyRep (by decide)).add_raw hhh.lazyRep
    (by decide)).add_raw hhh.lazyRep (by decide)).normalise (by decide) (by decide)
  have hj := hh.boundRep.mul hi (by decide) (by decide)
  have hv := hP.x.boundRep.mul hi (by decide) (by decide)
  have hr0 := hs2.lazyRep.sub_raw hP.y.lazyRep (Fp8.offset_two l)
    (by decide) (by decide)
  have hr := (hr0.add_raw hr0 (by decide)).normalise (by decide) (by decide)
  have hrr := hr.square (by decide)
  have hyj := hP.y.mul hj
  have hx3 := reduced_from_8p_holds
    ((hrr.lazyRep.sub_raw hj.lazyRep (Fp8.offset_two l) (by decide) (by decide)).sub_raw
      (hv.lazyRep.add_raw hv.lazyRep (by decide)) (Fp8.offset_four l)
      (by decide) (by decide)) (by decide) (by decide)
  have hvx := (hv.lazyRep.sub_raw hx3.lazyRep (Fp8.offset_two l) (by decide)
    (by decide)).normalise (by decide) (by decide)
  have hy3 := reduced_from_8p_holds
    ((hr.mul hvx (by decide) (by decide)).lazyRep.sub_raw (hyj.lazyRep.add_raw hyj.lazyRep (by decide))
      (Fp8.offset_four l) (by decide) (by decide)) (by decide) (by decide)
  have hz3 := reduced_from_8p_holds
    ((hzh2.lazyRep.sub_raw hz1z1.lazyRep (Fp8.offset_two l) (by decide) (by decide)).sub_raw
      hhh.lazyRep (Fp8.offset_two l) (by decide) (by decide)) (by decide) (by decide)
  refine ⟨⟨hx3.of_eq ?_, hy3.of_eq ?_, hz3.of_eq ?_⟩, ?_⟩
  rotate_left 3
  · rw [G2x8.add_affine, Mmask8.testBit_or, hh.testBit_is_zero_mask, hP.z.testBit_is_zero_mask]
    rfl
  all_goals
    simp only [Kernel.addAffine, G2.addBL, Matrix.cons_val_zero, Matrix.cons_val_one,
      Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons]
    ring1

theorem holds_times_minus_z {px py : Fp2x8} {vx vy : Fp2Field} (hx : px.Holds l vx)
    (hy : py.Holds l vy) :
    (times_minus_z px py).1.Holds l (Kernel.timesMinusZ vx vy).1 ∧
      (times_minus_z px py).2.toNat.testBit l = (Kernel.timesMinusZ vx vy).2 := by
  unfold times_minus_z Kernel.timesMinusZ
  refine List.foldl_rel (fun (s : G2x8 × Mmask8) (σ : (Fin 3 → Fp2Field) × Bool) =>
    s.1.Holds l σ.1 ∧ s.2.toNat.testBit l = σ.2) _ _ ?_ _ _ _
    ⟨⟨hx, hy, Fp2x8.holds_one l⟩, Mmask8.testBit_zero l⟩
  rintro ⟨r, u⟩ ⟨σ, b⟩ bit ⟨hr, hu⟩
  obtain ⟨hd, hdu⟩ := hr.double
  obtain ⟨ha, hau⟩ := hd.add_affine hx hy
  simp only [chainStep, Kernel.chainStep]
  split
  · exact ⟨ha, by rw [Mmask8.testBit_or, Mmask8.testBit_or, hu, hdu, hau]⟩
  · exact ⟨hd, by rw [Mmask8.testBit_or, hu, hdu]⟩

theorem holds_scott_membership {px py : Fp2x8} {vx vy : Fp2Field} (hx : px.Holds l vx)
    (hy : py.Holds l vy) :
    (scott_membership px py).members.toNat.testBit l = (Kernel.scottMembership vx vy).1 ∧
      (scott_membership px py).undecided.toNat.testBit l = (Kernel.scottMembership vx vy).2 := by
  obtain ⟨hm, hu⟩ := holds_times_minus_z hx hy
  have hscale := Fp8.holds_splat_limbs inv_ofList_PSI_X_MONT l
  rw [decode_ofList_PSI_X_MONT] at hscale
  have hpsix : Fp2x8.Holds ⟨px.c1.mul (Fp8.splat_limbs (.ofList PSI_X_MONT)),
      px.c0.mul (Fp8.splat_limbs (.ofList PSI_X_MONT))⟩ l ⟨psiX * vx.im, psiX * vx.re⟩ :=
    ⟨(hx.im.mul hscale).of_eq (mul_comm _ _), (hx.re.mul hscale).of_eq (mul_comm _ _)⟩
  have hpsiy := hy.conjugate.mul (Fp2x8.holds_splat_PSI_Y l)
  unfold scott_membership Kernel.scottMembership
  generalize times_minus_z px py = res at hm hu ⊢
  obtain ⟨mzp, cu⟩ := res
  have hzz := hm.z.square
  have hx_matches := hm.x.testBit_eq_mask (hpsix.mul hzz)
  have hy_matches := hm.y.neg.testBit_eq_mask (hpsiy.mul (hzz.mul hm.z))
  have hund := hm.z.testBit_is_zero_mask
  simp only at hm hu ⊢
  refine ⟨?_, ?_⟩
  · rw [Mmask8.testBit_and, Mmask8.testBit_and, Mmask8.testBit_not, Mmask8.testBit_or, hu,
      hx_matches, hy_matches, hund]
  · rw [Mmask8.testBit_or, hu, hund]

end G2x8

end LeanBlsSimd
