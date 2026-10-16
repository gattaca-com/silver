import Init.Control.Lawful
import Init.System.IO

namespace LeanBlsSimd.Kzg

instance estLawful {ε σ : Type} : LawfulMonad (EST ε σ) := LawfulMonad.mk'
  (id_map := by
    intro α x; funext s
    show EST.bind x (EST.pure ∘ id) s = x s
    unfold EST.bind EST.pure
    cases x s <;> rfl)
  (pure_bind := by intros; rfl)
  (bind_assoc := by
    intro α β γ x f g; funext s
    show EST.bind (EST.bind x f) g s = EST.bind x (fun a => EST.bind (f a) g) s
    unfold EST.bind
    cases x s <;> rfl)

instance ioLawful : LawfulMonad IO := estLawful (ε := IO.Error) (σ := IO.RealWorld)

end LeanBlsSimd.Kzg
