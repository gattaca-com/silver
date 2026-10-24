import LeanBlsSimd.LaneTower.Mul
import LeanBlsSimd.Spec.Cyclotomic.Field

open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

noncomputable def embed (x : Fp2Field) : Fp12Field :=
  algebraMap Fp6Field Fp12Field (Fp6Field.of x)

def single (h : Fin 2) (k : Fin 3) (x : Fp2Field) : P F :=
  (fun l => if l.val = 3 * h.val + k.val then x.re else 0,
   fun l => if l.val = 3 * h.val + k.val then x.im else 0)

/-- Lane `3h+k` is the coefficient of `w^(2k+h)` in the shared field tower. -/
theorem lane_basis (h : Fin 2) (k : Fin 3) (x : Fp2Field) :
    Fp12.toField (value (single h k x)) = embed x * Fp12Field.w ^ (2 * k.val + h.val) := by
  fin_cases h <;> fin_cases k
  all_goals
    apply QuadraticAlgebra.ext
    all_goals
      norm_num [value, single, embed, Fp12.toField, Fp6.toField, Fp2.toField,
        Fp6Field.assemble, Fp12Field.w, pow_succ, QuadraticAlgebra.omega]
      simp [show (⟨0, 0⟩ : Fp2Field) = 0 from rfl]

end LeanBlsSimd.LaneTower
