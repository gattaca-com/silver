import LeanBlsSimd.PairingProduct.StepSpec
import LeanBlsSimd.Pairing.MillerSpec

open EthLib.Cryptography Bls
open LeanBlsSimd.Pairing

namespace LeanBlsSimd.PairingProduct.Miller

noncomputable section

structure Input where
  xp : Fp2Field
  yp : Fp2Field
  q : Fp2Field × Fp2Field

structure State where
  point : Step.Point
  value : Fp12Field
  flagged : Bool

def Input.initial (i : Input) : State := ⟨![i.q.1, i.q.2, 1], 1, false⟩

def Input.evaluation (i : Input) : Embedded.Point :=
  evaluationPoint (Fp2.toField.symm i.xp) (Fp2.toField.symm i.yp)

def Input.base (i : Input) : Embedded.Point := untwist (Step.encodeAffine i.q)

def State.output (s : State) (i : Input) (add : Bool) : Step.Output :=
  if add then Step.add s.point i.q else Step.double s.point

def State.step (s : State) (i : Input) (add : Bool) : State :=
  let o := s.output i add
  ⟨o.point, (if add then s.value else s.value * s.value) *
    Step.evaluatedLine o i.xp i.yp, s.flagged || decide (o.point 2 = 0)⟩

def State.run (s : State) (i : Input) (kinds : List Bool) : State :=
  kinds.foldl (fun s add => s.step i add) s

def Input.miller (i : Input) : State := i.initial.run i (lineKinds 63)

def Input.factor (i : Input) : Fp12Field := i.miller.value ^ (Fp.modulus ^ 6)

theorem step_clear (s : State) (i : Input) (add : Bool)
    (h : (s.step i add).flagged = false) :
    s.flagged = false ∧ (s.output i add).point 2 ≠ 0 := by
  simpa only [State.step, Bool.or_eq_false_iff, decide_eq_false_iff_not] using h

theorem run_clear (s : State) (i : Input) (kinds : List Bool)
    (h : (s.run i kinds).flagged = false) : s.flagged = false := by
  induction kinds generalizing s with
  | nil => exact h
  | cons add kinds ih =>
    exact (step_clear s i add (ih (s.step i add) h)).1

theorem initial_affine (i : Input) : Step.affine i.initial.point = Step.encodeAffine i.q := by
  simp [Input.initial, Step.affine, Step.affineField]

end

end LeanBlsSimd.PairingProduct.Miller
