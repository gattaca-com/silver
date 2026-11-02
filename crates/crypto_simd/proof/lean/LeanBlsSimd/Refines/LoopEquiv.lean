import LeanBlsSimd.Refines.Loop

open Aeneas Aeneas.Std Result ControlFlow

namespace LeanBlsSimd

def mapLoopState {α β γ : Type} (f : α → γ) (r : Result (ControlFlow α β)) :
    Result (ControlFlow γ β) :=
  r >>= fun
    | cont s => ok (cont (f s))
    | done x => ok (done x)

@[simp] theorem mapLoopState_cont {α β γ : Type} (f : α → γ) (s : α) :
    mapLoopState (β := β) f (ok (cont s)) = ok (cont (f s)) := by
  simp only [mapLoopState, bind_tc_ok]

@[simp] theorem mapLoopState_done {α β γ : Type} (f : α → γ) (r : β) :
    mapLoopState f (ok (done r)) = ok (done r) := by
  simp only [mapLoopState, bind_tc_ok]

@[simp] theorem mapLoopState_bind {α β γ δ : Type} (f : α → γ)
    (r : Result δ) (k : δ → Result (ControlFlow α β)) :
    mapLoopState f (r >>= k) = r >>= fun x => mapLoopState f (k x) := by
  simp only [mapLoopState, bind_assoc_eq]

private theorem mapLoopState_cancel {α β γ : Type} (f : α → γ) (g : γ → α)
    (hgf : ∀ s, g (f s) = s) (r : Result (ControlFlow α β)) :
    mapLoopState g (mapLoopState f r) = r := by
  conv_rhs => rw [← Aeneas.Std.bind_pure r]
  rw [mapLoopState, mapLoopState, bind_assoc_eq]
  change (r >>= _) = (r >>= _)
  congr 1
  funext x
  cases x <;> simp [hgf]

private theorem loop_transfer_le {α β γ : Type}
    (first : α → Result (ControlFlow α β))
    (second : γ → Result (ControlFlow γ β)) (f : α → γ)
    (h : ∀ s, second (f s) = mapLoopState f (first s)) :
    ∀ s, Lean.Order.PartialOrder.rel (loop first s) (loop second (f s)) := by
  apply loop.fixpoint_induct first
    (fun approx => ∀ s, Lean.Order.PartialOrder.rel (approx s) (loop second (f s)))
  · apply Lean.Order.admissible_pi_apply
      (fun (s : α) (r : Result β) => Lean.Order.PartialOrder.rel r (loop second (f s)))
    intro s c hc hall
    exact Lean.Order.csup_le hc hall
  · intro approx ih s
    rw [loop.eq_1 second, h, mapLoopState]
    change Lean.Order.PartialOrder.rel (first s >>= _) ((first s >>= _) >>= _)
    rw [bind_assoc_eq]
    apply Lean.Order.MonoBind.bind_mono_right
    intro flow
    cases flow with
    | cont next => simpa only [bind_tc_ok, bind_ok] using ih next
    | done result =>
      simp only [bind_tc_ok]
      exact Lean.Order.PartialOrder.rel_refl

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
      rw [hf, mapLoopState_cancel _ _ e.symm_apply_apply]
    simpa only [e.symm_apply_apply] using loop_transfer_le second first e.symm hback (e s)
  · exact loop_transfer_le first second e h s

end LeanBlsSimd
