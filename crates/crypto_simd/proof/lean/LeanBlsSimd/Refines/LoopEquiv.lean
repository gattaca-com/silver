import LeanBlsSimd.Refines.Loop

open Aeneas Aeneas.Std Result ControlFlow

namespace LeanBlsSimd

def mapLoopState {α β γ : Type} (f : α → γ) :
    Result (ControlFlow α β) → Result (ControlFlow γ β)
  | ok (cont s) => ok (cont (f s))
  | ok (done r) => ok (done r)
  | fail e => fail e
  | div => div

@[simp] theorem mapLoopState_cont {α β γ : Type} (f : α → γ) (s : α) :
    mapLoopState (β := β) f (ok (cont s)) = ok (cont (f s)) := rfl

@[simp] theorem mapLoopState_done {α β γ : Type} (f : α → γ) (r : β) :
    mapLoopState f (ok (done r)) = ok (done r) := rfl

@[simp] theorem mapLoopState_bind {α β γ δ : Type} (f : α → γ)
    (r : Result δ) (k : δ → Result (ControlFlow α β)) :
    mapLoopState f (r >>= k) = r >>= fun x => mapLoopState f (k x) := by
  cases r <;> rfl

private theorem loop_transfer_le {α β γ : Type}
    (first : α → Result (ControlFlow α β))
    (second : γ → Result (ControlFlow γ β)) (f : α → γ)
    (h : ∀ s, second (f s) = mapLoopState f (first s)) :
    ∀ s, Lean.Order.PartialOrder.rel (loop first s) (loop second (f s)) := by
  apply loop.fixpoint_induct first
    (fun approx => ∀ s, Lean.Order.PartialOrder.rel (approx s) (loop second (f s)))
  · apply Lean.Order.admissible_pi_apply
      (fun (s : α) (r : Result β) => Lean.Order.PartialOrder.rel r (loop second (f s)))
    intro s
    apply Lean.Order.admissible_flatOrder
    exact Lean.Order.FlatOrder.rel.bot
  · intro approx ih s
    rw [loop.eq_1,h]
    dsimp only
    cases hs : first s with
    | ok flow =>
      cases flow with
      | cont next => simpa only [hs, mapLoopState] using ih next
      | done result => simp only [mapLoopState]; exact Lean.Order.FlatOrder.rel.refl
    | fail error => simp only [mapLoopState]; exact Lean.Order.FlatOrder.rel.refl
    | div => simp only [mapLoopState]; exact Lean.Order.FlatOrder.rel.bot

/-- Renaming loop state preserves failure and divergence as well as successful results. -/
theorem loop_equiv {α β γ : Type}
    (first : α → Result (ControlFlow α β))
    (second : γ → Result (ControlFlow γ β)) (e : α ≃ γ)
    (h : ∀ s, second (e s) = mapLoopState e (first s)) (s : α) :
    loop second (e s) = loop first s := by
  apply Lean.Order.PartialOrder.rel_antisymm
  · have hback : ∀ t, first (e.symm t) = mapLoopState e.symm (second t) := by
      intro t
      have hf := h (e.symm t)
      simp only [e.apply_symm_apply] at hf
      rw [hf]
      cases first (e.symm t) with
      | ok flow => cases flow <;> simp [mapLoopState]
      | fail error => rfl
      | div => rfl
    simpa only [e.symm_apply_apply] using loop_transfer_le second first e.symm hback (e s)
  · exact loop_transfer_le first second e h s

end LeanBlsSimd
