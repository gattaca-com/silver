import LeanBlsSimd.PairingProduct.MillerModel
import LeanBlsSimd.Pairing.ProjectiveLine
import LeanBlsSimd.Spec.PairingProduct

open EthLib.Cryptography Bls
open LeanBlsSimd.Pairing

namespace LeanBlsSimd.PairingProduct.Miller

noncomputable section

theorem step_spec (s : State) (i : Input) (add : Bool) (f : Fp12)
    (hv : s.value ^ finalExpExponent = Fp12.toField f ^ finalExpExponent)
    (hc : (s.step i add).flagged = false) :
    untwist (Step.affine (s.step i add).point) =
        (action i.base i.evaluation add (untwist (Step.affine s.point), f)).1 ∧
      (s.step i add).value ^ finalExpExponent =
        Fp12.toField (action i.base i.evaluation add
          (untwist (Step.affine s.point), f)).2 ^ finalExpExponent := by
  have hz := (step_clear s i add hc).2
  cases add with
  | false =>
    change (Step.double s.point).point 2 ≠ 0 at hz
    constructor
    · exact Step.double_next s.point hz
    · change ((s.value * s.value) * Step.evaluatedLine (Step.double s.point) i.xp i.yp) ^
        finalExpExponent = Fp12.toField (f * f * Line.evalAt
          (untwist (Step.affine s.point)).x (untwist (Step.affine s.point)).y
          (Line.tangentSlope (untwist (Step.affine s.point)).x
            (untwist (Step.affine s.point)).y)
          (includeFp2 (Fp2.toField.symm i.xp)) (includeFp2 (Fp2.toField.symm i.yp))) ^ _
      simp only [map_mul, mul_pow]
      rw [Step.double_line_final_power _ _ _ hz, hv]
  | true =>
    change (Step.add s.point i.q).point 2 ≠ 0 at hz
    constructor
    · exact Step.add_next s.point i.q hz
    · change (s.value * Step.evaluatedLine (Step.add s.point i.q) i.xp i.yp) ^
        finalExpExponent = Fp12.toField (f * Line.evalAt
          (untwist (Step.affine s.point)).x (untwist (Step.affine s.point)).y
          (Line.addSlope (untwist (Step.affine s.point)).x
            (untwist (Step.affine s.point)).y i.base.x i.base.y)
          (includeFp2 (Fp2.toField.symm i.xp)) (includeFp2 (Fp2.toField.symm i.yp))) ^ _
      simp only [map_mul, mul_pow]
      rw [Step.add_line_final_power _ _ _ _ hz, hv]
      rfl

theorem run_spec (kinds : List Bool) (s : State) (i : Input) (t : Embedded.Point) (f : Fp12)
    (ht : untwist (Step.affine s.point) = t)
    (hv : s.value ^ finalExpExponent = Fp12.toField f ^ finalExpExponent)
    (hc : (s.run i kinds).flagged = false) :
    (s.run i kinds).value ^ finalExpExponent =
      Fp12.toField (kinds.foldl (fun state add => action i.base i.evaluation add state)
        (t, f)).2 ^ finalExpExponent := by
  induction kinds generalizing s t f with
  | nil => exact hv
  | cons add kinds ih =>
    subst t
    have hs := step_spec s i add f hv (run_clear (s.step i add) i kinds hc)
    exact ih (s.step i add) _ _ hs.1 hs.2 hc

theorem miller_spec (i : Input) (hc : i.miller.flagged = false) :
    i.miller.value ^ finalExpExponent =
      Fp12.toField (millerLoop blsX i.base i.evaluation) ^ finalExpExponent := by
  have h := run_spec (lineKinds 63) i.initial i i.base Fp12.one
    (by rw [initial_affine]; rfl) (by simp [Input.initial]) hc
  rw [actions_steps] at h
  rw [SpecPairing.millerLoop_eq,
    show blsX.log2 = 63 from by decide +kernel]
  exact h

theorem factor_spec (i : Input) (hc : i.miller.flagged = false) :
    i.factor ^ finalExpExponent =
      Fp12.toField (millerLoop blsX i.base i.evaluation).conjugate ^ finalExpExponent := by
  rw [Input.factor, Cyclotomic.spec_conjugate, ← pow_mul, ← pow_mul,
    Nat.mul_comm (Fp.modulus ^ 6) finalExpExponent, pow_mul, miller_spec i hc,
    ← pow_mul, Nat.mul_comm]

def Input.ofPoints (p : G1) (q : G2) : Input :=
  ⟨Fp2.toField (Fp2.ofFp p.toAffine.1), Fp2.toField (Fp2.ofFp p.toAffine.2),
    Fp2.toField q.toAffine.1, Fp2.toField q.toAffine.2⟩

theorem ofPoints_base (p : G1) (q : G2) (hq : q.isInfinity = false) :
    (Input.ofPoints p q).base = Embedded.ofG2 q := by
  simp only [Input.base, Input.ofPoints, Step.encodeAffine, RingEquiv.symm_apply_apply,
    Embedded.ofG2, hq, Bool.false_eq_true, if_false]
  rfl

theorem ofPoints_evaluation (p : G1) (q : G2) (hp : p.isInfinity = false) :
    (Input.ofPoints p q).evaluation = Embedded.ofG1 p := by
  rw [ofG1_evaluationPoint p hp]
  simp only [Input.evaluation, Input.ofPoints, RingEquiv.symm_apply_apply]

theorem finite_factor_spec (p : G1) (q : G2)
    (hp : p.isInfinity = false) (hq : q.isInfinity = false)
    (hc : (Input.ofPoints p q).miller.flagged = false) :
    (Input.ofPoints p q).factor ^ finalExpExponent =
      Fp12.toField (pairingFactor (p, q)) ^ finalExpExponent := by
  rw [factor_spec _ hc, ofPoints_base _ _ hq, ofPoints_evaluation _ _ hp]
  simp only [pairingFactor, hp, hq, Bool.or_self, Bool.false_eq_true, if_false]

end

end LeanBlsSimd.PairingProduct.Miller
