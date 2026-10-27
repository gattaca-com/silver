import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.CurveWork

/-- The arithmetic route chosen by the stored curve workspace. -/
def isLanes : verify.CurveWork → Bool
  | .Lanes _ _ => true
  | .Scalar _ _ => false

private theorem bind_success {α β : Type} (r : Result α) (f : α → Result β) (v : β) :
    (do let x ← r; f x) = ok v ↔ ∃ x, r = ok x ∧ f x = ok v := by
  cases r <;> simp

/-- Every successful MSM preserves the stored arithmetic route. -/
theorem sum_frame [RuntimeFeatures]
    (self next : verify.CurveWork) (ps : Slice blst.blst_p1_affine)
    (fs : Slice blst.blst_fr) (point : blst.blst_p1)
    (hcall : self.sum ps fs = ok (point, next)) :
    isLanes next = isLanes self := by
  cases self with
  | Lanes msm words =>
    simp only [verify.CurveWork.sum, bind_success, Function.uncurry] at hcall
    obtain ⟨words', _, ⟨point', msm'⟩, _, he⟩ := hcall
    obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj he)
    rfl
  | Scalar msm words =>
    simp only [verify.CurveWork.sum, bind_success, Function.uncurry] at hcall
    obtain ⟨words', _, words'', _, ⟨point', msm'⟩, _, he⟩ := hcall
    obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj he)
    rfl

end LeanBlsSimd.Kzg.CurveWork
