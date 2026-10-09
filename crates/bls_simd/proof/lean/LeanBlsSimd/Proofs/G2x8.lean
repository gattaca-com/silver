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

open EthCryptographySpecs.Bls WeierstrassCurve Jacobian

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

theorem Holds.double (hP : P.Holds l t) :
    P.double.1.Holds l (Kernel.double t).1 ∧
      P.double.2.toNat.testBit l = (Kernel.double t).2 := by
  have ha := hP.x.square
  have hb := hP.y.square
  have hc := hb.square
  have hd := (((hP.x.add hb).square.sub ha).sub hc).double
  have he := ha.double.add ha
  have hx3 := he.square.sub hd.double
  have hy3 := (he.mul (hd.sub hx3)).sub hc.double.double.double
  have hz3 := (hP.y.mul hP.z).double
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
  have hi := hhh.double.double
  have hj := hh.mul hi
  have hr := (hs2.sub hP.y).double
  have hv := hP.x.mul hi
  have hx3 := (hr.square.sub hj).sub hv.double
  have hy3 := (hr.mul (hv.sub hx3)).sub (hP.y.mul hj).double
  have hz3 := ((hP.z.add hh).square.sub hz1z1).sub hhh
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
  simp only [Kernel.chainStep]
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
