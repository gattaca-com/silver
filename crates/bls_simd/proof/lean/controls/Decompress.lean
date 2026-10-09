import LeanBlsSimd.Proofs.DecompressG2

/-! Negative controls for `Proofs/Fp2x8.lean`, `Spec/Membership.lean`, `Proofs/G2x8.lean`,
`Proofs/Decode.lean` and `Proofs/DecompressG2.lean`. Each `fail_if_success` wraps a claim that
must fail; each plain `example` must pass.

Each control runs a library proof against a mutant. A mutant is a copy of a model or `Kernel`
definition, or of a constant's index. Where the copy takes the mutated part as a parameter, `rfl`
pins its unmutated instance to the original. A plain example shows the mutation on concrete
values. -/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls DecompressG2 Kernel

-- A mutated proof stops at its first failing step, so the linters flag the steps after it.
set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! ## The final comparison: the sign of −Y

`G2x8::scott_membership` compares −Y with ψ_y·Z³: ψ(P) = −[|z|]P = [z]P. Comparing Y instead
tests ψ(P) = [|z|]P = [−z]P, which no affine point of G2 passes. The proof of
`scottMembership_spec` then fails at the y-coordinate. -/

noncomputable def scottMembershipWith (negY : Fp2Field → Fp2Field) (px py : Fp2Field) :
    Bool × Bool :=
  let mzp := (timesMinusZ px py).1
  let undecided := (timesMinusZ px py).2 || decide (mzp 2 = 0)
  let psiX' : Fp2Field := ⟨psiX * px.im, psiX * px.re⟩
  let psiY' : Fp2Field := star py * ⟨psiY.1, psiY.2⟩
  let xMatches := decide (mzp 0 = psiX' * mzp 2 ^ 2)
  let yMatches := decide (negY (mzp 1) = psiY' * (mzp 2 ^ 2 * mzp 2))
  (xMatches && yMatches && !undecided, undecided)

example : scottMembershipWith (fun y => -y) = scottMembership := rfl

example : True := by
  fail_if_success
    have : ∀ {px py : Fp2Field} (h : E'.Nonsingular px py),
        (scottMembershipWith id px py).2 = false →
        (scottMembershipWith id px py).1 = decide (psi (.some px py h) = z • .some px py h) := by
      intro px py h hu
      simp only [scottMembershipWith, Bool.or_eq_false_iff, decide_eq_false_iff_not] at hu ⊢
      obtain ⟨hc, hz⟩ := hu
      have hr := timesMinusZ_spec h hc
      rw [hc, decide_eq_false hz, Bool.false_or, Bool.not_false, Bool.and_true,
        ← Bool.decide_and, psiX_mk_eq, psiY_mk_eq]
      refine decide_eq_decide.mpr ?_
      generalize (timesMinusZ px py).1 = t at hr hz
      have hpsi : psi (.some px py h) = .some (cx * star px) (cy * star py) (nonsingular_psi h) :=
        rfl
      rw [hpsi, z, neg_smul, natCast_zsmul, ← hr.toAffine_eq,
        WeierstrassCurve.Jacobian.Point.toAffine_of_Z_ne_zero hr.nonsingular hr.z_ne_zero,
        WeierstrassCurve.Affine.Point.neg_some, WeierstrassCurve.Affine.Point.some.injEq,
        E'.negY_eq, eq_div_iff (pow_ne_zero 2 hz), ← neg_div, eq_div_iff (pow_ne_zero 3 hz),
        pow_succ (t 2) 2]
      constructor
      · rintro ⟨h1, h2⟩
        exact ⟨h1.symm, h2.symm⟩
      · rintro ⟨h1, h2⟩
        exact ⟨h1.symm, h2.symm⟩
  trivial

/-- The two y-tests differ wherever Y ≠ 0: −Y = Y forces Y = 0 in odd characteristic. -/
example : ∀ y : Fp2Field, -y = y → y = 0 := fun y h => by
  have h2 : (2 : Fp2Field) * y = 0 := by linear_combination -h
  exact (mul_eq_zero.mp h2).resolve_left (by decide +kernel)

/-! ## ψ's x multiplier: the coordinate swap

`G2x8::scott_membership` computes ψ_x as (x1·s, x0·s), which is c_x · x̄ with c_x = s·i. Without
the swap, (x0·s, x1·s) is s·x, and `psiX_mk_eq` fails. -/

example : True := by
  fail_if_success
    have : ∀ v : Fp2Field, (⟨psiX * v.re, psiX * v.im⟩ : Fp2Field) = cx * star v := by
      intro v
      ext <;> simp [cx]
  trivial

example : (⟨psiX * 1, psiX * 0⟩ : Fp2Field) ≠ cx * star 1 := by decide +kernel

/-! ## ψ's y multiplier: its two limb tables swapped

The model splats `PSI_Y_MONT[0]` as c0 and `PSI_Y_MONT[1]` as c1. The proof that c0 holds the
real part of c_y fails for `PSI_Y_MONT[1]`. -/

example : True := by
  fail_if_success
    have : decode (.ofList PSI_Y_MONT[1]!) = psiY.1 := by
      have h : val (.ofList PSI_Y_MONT[1]!) = psiY.1 * R % Fp.modulus := by decide +kernel
      rw [decode_of_val h]
  trivial

example : val (.ofList PSI_Y_MONT[1]!) ≠ psiY.1 * R % Fp.modulus := by decide +kernel

/-! ## Mask polarity: `decodable` without its negation

`decompress` marks a lane decodable when it is neither invalid nor undecided. Without the `~~~`,
an invalid lane is decodable, and the proof that `on_curve` is `laneOnCurve` fails. -/

def tailWith (decodableOf : Mmask8 → Mmask8 → Mmask8) (D : Decoded) (X root : Fp2x8)
    (has : Mmask8) : Batch :=
  let batch : Batch := {
    points := .replicate 8 default,
    on_curve := 0,
    valid := 0,
    undecided := D.undecided }
  let decodable := decodableOf D.invalid D.undecided
  if decodable = 0 then batch else
  let batch := { batch with on_curve := has &&& decodable }
  if batch.on_curve = 0 then batch else
  tailFull D X root has

example : tailWith (fun i u => ~~~(i ||| u)) = tail := rfl

example : True := by
  fail_if_success
    have : ∀ {D : Decoded} {X root : Fp2x8} {has : Mmask8} {b : Vector UInt8 G2_COMPRESSED_LEN}
        {l : Fin 8}, (decodeLane b).Holds D l → X.Holds l (laneX b) →
        root.Holds l (sqrt (rhs (laneX b))).1 → has.toNat.testBit l = (sqrt (rhs (laneX b))).2 →
        LaneVerdicts (tailWith (fun i u => i ||| u) D X root has) b l := by
      intro D X root has b l hd hx hroot hhas
      have hdec : (D.invalid ||| D.undecided).toNat.testBit l =
          !((decodeLane b).invalid || (decodeLane b).undecided) := by
        simp only [Mmask8.testBit_not, Mmask8.testBit_or, hd.invalid, hd.undecided]
      have honc : (has &&& (D.invalid ||| D.undecided)).toNat.testBit l = laneOnCurve b := by
        rw [Mmask8.testBit_and, hhas, hdec, laneOnCurve]
      unfold tailWith
      dsimp only
      split_ifs with h1 h2
      · have hon : laneOnCurve b = false := by
          rw [laneOnCurve, ← hdec, Mmask8.testBit_of_eq_zero h1, Bool.and_false]
        refine ⟨?_, ?_, ?_, fun h => absurd h (by rw [hon]; decide)⟩
        · rw [laneUndecided, hon, Bool.and_false, Bool.or_false, hd.undecided]
        · rw [hon, Mmask8.testBit_zero]
        · rw [laneValid, hon, Bool.and_false, Bool.false_and, Mmask8.testBit_zero]
      · have hon : laneOnCurve b = false := by
          rw [← honc, Mmask8.testBit_of_eq_zero h2]
        refine ⟨?_, ?_, ?_, fun h => absurd h (by rw [hon]; decide)⟩
        · rw [laneUndecided, hon, Bool.and_false, Bool.or_false, hd.undecided]
        · exact honc
        · rw [laneValid, hon, Bool.and_false, Bool.false_and, Mmask8.testBit_zero]
      · exact tailFull_lane hd hx hroot hhas
  trivial

/-- An invalid lane 0 is not decodable with the negation, and is decodable without it. -/
example : (~~~((1 : Mmask8) ||| 0)).toNat.testBit 0 = false ∧
    ((1 : Mmask8) ||| 0).toNat.testBit 0 = true := by decide

/-! ## An early return that drops a lane

`decompress` returns early when no lane is decodable. Testing `decodable &&& 0x7f` instead
returns early when lane 7 alone is decodable, and drops that lane's verdicts. The proof that the
early return keeps every lane's verdict fails. -/

def tailDrop (D : Decoded) (X root : Fp2x8) (has : Mmask8) : Batch :=
  let batch : Batch := {
    points := .replicate 8 default,
    on_curve := 0,
    valid := 0,
    undecided := D.undecided }
  let decodable := ~~~(D.invalid ||| D.undecided)
  if decodable &&& 0x7f = 0 then batch else
  let batch := { batch with on_curve := has &&& decodable }
  if batch.on_curve = 0 then batch else
  tailFull D X root has

example : True := by
  fail_if_success
    have : ∀ {D : Decoded} {X root : Fp2x8} {has : Mmask8} {b : Vector UInt8 G2_COMPRESSED_LEN}
        {l : Fin 8}, (decodeLane b).Holds D l → X.Holds l (laneX b) →
        root.Holds l (sqrt (rhs (laneX b))).1 → has.toNat.testBit l = (sqrt (rhs (laneX b))).2 →
        LaneVerdicts (tailDrop D X root has) b l := by
      intro D X root has b l hd hx hroot hhas
      have hdec : (~~~(D.invalid ||| D.undecided)).toNat.testBit l =
          !((decodeLane b).invalid || (decodeLane b).undecided) := by
        rw [Mmask8.testBit_not, Mmask8.testBit_or, hd.invalid, hd.undecided]
      have honc : (has &&& ~~~(D.invalid ||| D.undecided)).toNat.testBit l = laneOnCurve b := by
        rw [Mmask8.testBit_and, hhas, hdec, laneOnCurve]
      unfold tailDrop
      dsimp only
      split_ifs with h1 h2
      · have hon : laneOnCurve b = false := by
          rw [laneOnCurve, ← hdec, Mmask8.testBit_of_eq_zero h1, Bool.and_false]
        refine ⟨?_, ?_, ?_, fun h => absurd h (by rw [hon]; decide)⟩
        · rw [laneUndecided, hon, Bool.and_false, Bool.or_false, hd.undecided]
        · rw [hon, Mmask8.testBit_zero]
        · rw [laneValid, hon, Bool.and_false, Bool.false_and, Mmask8.testBit_zero]
      · have hon : laneOnCurve b = false := by
          rw [← honc, Mmask8.testBit_of_eq_zero h2]
        refine ⟨?_, ?_, ?_, fun h => absurd h (by rw [hon]; decide)⟩
        · rw [laneUndecided, hon, Bool.and_false, Bool.or_false, hd.undecided]
        · exact honc
        · rw [laneValid, hon, Bool.and_false, Bool.false_and, Mmask8.testBit_zero]
      · exact tailFull_lane hd hx hroot hhas
  trivial

/-- Lane 7 alone decodable: the mutant's test sees no decodable lane. -/
example : ((0x80 : Mmask8) &&& 0x7f) = 0 ∧ (0x80 : Mmask8).toNat.testBit 7 = true := by decide

/-! ## A wrong flag bit in decoding

`decode` reads the infinity flag from bit 6 of byte 0 (`FLAG_INFINITY`, 0x40). Reading it from
bit 5, the sign flag, sends every encoding of the larger root to the undecided lanes. The proof
that each lane records `decodeLane` fails. -/

def decodeStepWith (flagInf : UInt8) (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8)
    (d : Decoded) (lane : Fin 8) : Decoded :=
  let bytes := inputs[lane]
  let bit : Mmask8 := 1 <<< lane.val.toUInt8
  let flags := bytes[0]'(by simp [G2_COMPRESSED_LEN]) &&& 0xe0
  if flags &&& FLAG_COMPRESSED = 0 then { d with invalid := d.invalid ||| bit }
  else if flags &&& flagInf ≠ 0 then { d with undecided := d.undecided ||| bit }
  else
    let d := if flags &&& FLAG_LARGER_ROOT ≠ 0 then
      { d with larger_root := d.larger_root ||| bit } else d
    let (x1_bytes, x0_bytes) := split_at bytes
    let x1 := fp_words x1_bytes
    let x1 := x1.set 5 (x1[5] &&& 0x1fffffffffffffff)
    let x0 := fp_words x0_bytes
    if !less_than_p x1 || !less_than_p x0 then { d with invalid := d.invalid ||| bit }
    else { d with x0 := d.x0.set lane (unpack52 x0), x1 := d.x1.set lane (unpack52 x1) }

example : decodeStepWith FLAG_INFINITY = decodeStep := rfl

example : True := by
  fail_if_success
    have : ∀ (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (d : Decoded) (i : Fin 8),
        d.lane i = initLane →
        (decodeLane inputs[i]).Holds (decodeStepWith FLAG_LARGER_ROOT inputs d i) i := by
      intro inputs d i h0
      simp only [Decoded.lane, initLane, Prod.mk.injEq] at h0
      obtain ⟨hx0, hx1, hlr, hinv, hund⟩ := h0
      have hb (k : Mmask8) : (k ||| (1 <<< i.val.toUInt8)).toNat.testBit i = true := by
        rw [Mmask8.testBit_or, Mmask8.testBit_one_shiftLeft, decide_eq_true rfl, Bool.or_true]
      unfold decodeStepWith decodeLane
      dsimp only
      simp only [flag_compressed, flag_infinity, flag_larger_root]
      generalize split_at inputs[i] = sp
      obtain ⟨x1b, x0b⟩ := sp
      dsimp only
      rw [fp_words_clear_flags, less_than_p_iff, less_than_p_iff, val64_fp_words, val64_fp_words]
      have hz0 : Fp8Inv d.x0[i] ∧ val d.x0[i] = 0 :=
        ⟨hx0 ▸ inv_replicate_zero, by rw [hx0]; exact val_replicate_zero⟩
      have hz1 : Fp8Inv d.x1[i] ∧ val d.x1[i] = 0 :=
        ⟨hx1 ▸ inv_replicate_zero, by rw [hx1]; exact val_replicate_zero⟩
      have hcond : ∀ a b : Prop, [Decidable a] → [Decidable b] →
          ((!decide a || !decide b) = true) = ¬(a ∧ b) := by
        intro a b _ _
        by_cases ha : a <;> by_cases hb : b <;> simp [ha, hb]
      simp only [hcond, ite_not]
      generalize inputs[i][0]'zero_lt_G2_COMPRESSED_LEN = head
      have hok {v : Vector UInt8 FP_BYTES} (h : bytesVal v.toList < Fp.modulus) :
          Fp8Inv (unpack52 (fp_words v)) ∧ val (unpack52 (fp_words v)) = bytesVal v.toList := by
        rw [← val64_fp_words] at h ⊢
        exact ⟨inv_unpack52 h, (unpack52_spec _).2⟩
      have hs (v : Vector Limbs 8) (x : Limbs) : (v.set i x)[i] = x := Vector.getElem_set_self ..
      split_ifs with h1 h2 h3 h4
      · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, hlr, hb _, hund⟩
      · refine ⟨?_, ?_, ?_, ?_, ?_, hinv, hund⟩
        · rw [hs]; exact (hok h3.2).1
        · rw [hs]; exact (hok h3.2).2
        · rw [hs]; exact (hok h3.1).1
        · rw [hs]; exact (hok h3.1).2
        · rw [hlr, decide_eq_false (not_not.mpr h4)]
      · refine ⟨?_, ?_, ?_, ?_, ?_, hinv, hund⟩
        · rw [hs]; exact (hok h3.2).1
        · rw [hs]; exact (hok h3.2).2
        · rw [hs]; exact (hok h3.1).1
        · rw [hs]; exact (hok h3.1).2
        · rw [hb, decide_eq_true h4]
      · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, by rw [hlr, decide_eq_false (not_not.mpr ‹_›)], hb _,
          hund⟩
      · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, by rw [hb, decide_eq_true ‹_›], hb _, hund⟩
      · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, hlr, hinv, hb _⟩
  trivial

/-- Byte 0 is 0xa0 and every other byte 0: the compressed encoding of x = 0, larger root. -/
def signOnly : Vector UInt8 G2_COMPRESSED_LEN := (Vector.replicate _ 0).set 0 0xa0 (by decide)

def decodeWith (flagInf : UInt8) (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) : Decoded :=
  (List.finRange 8).foldl (decodeStepWith flagInf inputs) decodeInit

example : decodeWith FLAG_INFINITY = DecompressG2.decode := rfl

example : (decodeLane signOnly).undecided = false ∧ (decodeLane signOnly).largerRoot = true := by
  decide +kernel

example :
    (decodeWith FLAG_INFINITY (.replicate 8 signOnly)).undecided.toNat.testBit 0 = false := by
  decide +kernel

example :
    (decodeWith FLAG_LARGER_ROOT (.replicate 8 signOnly)).undecided.toNat.testBit 0 = true := by
  decide +kernel

end LeanBlsSimd
