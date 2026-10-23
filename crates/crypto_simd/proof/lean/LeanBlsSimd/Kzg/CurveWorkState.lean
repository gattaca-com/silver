import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.CurveWork

/-- The arithmetic route chosen by the stored curve workspace. -/
def isLanes : verify.CurveWork → Bool
  | .Lanes _ _ => true
  | .Portable _ _ _ => false

/-- The portable pairing table is persistent state, separate from MSM scratch. -/
def pairingLines : verify.CurveWork → Option portable.pairing.PairingLines
  | .Lanes _ _ => none
  | .Portable _ lines _ => some lines

private theorem bind_success {α β : Type} (r : Result α) (f : α → Result β) (v : β) :
    (do let x ← r; f x) = ok v ↔ ∃ x, r = ok x ∧ f x = ok v := by
  cases r <;> simp

/-- Every successful MSM preserves both the route and the exact stored table. -/
theorem sum_frame [RuntimeFeatures]
    (self next : verify.CurveWork) (ps : Slice blst.blst_p1_affine)
    (fs : Slice blst.blst_fr) (point : blst.blst_p1)
    (hcall : self.sum ps fs = ok (point, next)) :
    isLanes next = isLanes self ∧ pairingLines next = pairingLines self := by
  cases self with
  | Lanes msm words =>
    simp only [verify.CurveWork.sum, bind_success, Function.uncurry] at hcall
    obtain ⟨words', _, ⟨point', msm'⟩, _, he⟩ := hcall
    obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj he)
    exact ⟨rfl, rfl⟩
  | Portable msm lines words =>
    simp only [verify.CurveWork.sum, bind_success, Function.uncurry] at hcall
    obtain ⟨words', _, words'', _, ⟨point', msm'⟩, _, he⟩ := hcall
    obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj he)
    exact ⟨rfl, rfl⟩

end LeanBlsSimd.Kzg.CurveWork
