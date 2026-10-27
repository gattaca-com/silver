import LeanBlsSimd.Kzg.CurveWorkState
import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls silver_crypto_simd.kzg
noncomputable section
namespace LeanBlsSimd.Kzg.Routes

theorem lincomb_sum_route [RuntimeFeatures] (self next : verify.CurveWork)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr) (point : blst.blst_p1)
    (hcall : self.sum ps fs = ok (point, next)) :
    CurveWork.isLanes next = CurveWork.isLanes self :=
  (CurveWork.sum_frame self next ps fs point hcall)

private theorem bind_success {α β : Type} (r : Result α) (f : α → Result β) (v : β) :
    (do let x ← r; f x) = ok v ↔ ∃ x, r = ok x ∧ f x = ok v := by
  cases r <;> simp

private theorem loop_success_invariant {α β : Type} (body : α → Result (ControlFlow α β))
    (P : α → Prop) (Q : β → Prop)
    (hbody : ∀ x r, body x = ok r → P x → match r with
      | .cont x' => P x'
      | .done y => Q y) :
    ∀ x y, loop body x = ok y → P x → Q y := by
  apply loop.fixpoint_induct body (fun f => ∀ x y, f x = ok y → P x → Q y)
  · apply Lean.Order.admissible_pi_apply (fun x r => ∀ y, r = ok y → P x → Q y)
    intro x
    apply Lean.Order.admissible_flatOrder
    intro y h
    contradiction
  · intro approx ih x y h hx
    cases hb : body x with
    | fail e => simp only [hb] at h; contradiction
    | div => simp only [hb] at h; contradiction
    | ok r =>
      cases r with
      | done z =>
        simp only [hb, Result.ok.injEq] at h
        subst z
        exact hbody x (.done y) hb hx
      | cont z =>
        simp only [hb] at h
        exact ih z y h (hbody x (.cont z) hb hx)

def route (self : verify.CellBatchVerifier) : Bool × Bool :=
  (self.kernel.isSome, CurveWork.isLanes self.curve_work)

theorem interpolation_commitment_route [RuntimeFeatures] (self next : verify.CellBatchVerifier)
    (indices : Slice U64) (cells : Slice (Array U8 2048#usize)) (point : blst.blst_p1)
    (h : self.interpolation_commitment indices cells = ok (point, next)) :
    route next = route self := by
  simp only [verify.CellBatchVerifier.interpolation_commitment, bind_success] at h
  cases hk : self.kernel with
  | none =>
    simp only [hk, bind_success, Function.uncurry] at h
    repeat obtain ⟨x, hx, h⟩ := h
    have hr := lincomb_sum_route self.curve_work x.2 _ _ x.1 hx
    simp only [route, hk, Option.isSome_none, hr]
  | some kernel =>
    simp only [hk, bind_success, Function.uncurry] at h
    repeat obtain ⟨x, hx, h⟩ := h
    have hr := lincomb_sum_route self.curve_work x.2 _ _ x.1 hx
    simp only [route, hk, Option.isSome_some, hr]

theorem pairing_holds_route [RuntimeFeatures] [KzgExternals] (self next : verify.CellBatchVerifier)
    (r : blst.blst_fr) (indices : Slice U64) (cells : Slice (Array U8 2048#usize)) (b : Bool)
    (h : self.pairing_holds r indices cells = ok (b, next)) : route next = route self := by
  simp only [verify.CellBatchVerifier.pairing_holds, bind_success, Function.uncurry] at h
  obtain ⟨v, _, powers, _, ll, hll, v2, _, v3, _, scalars, _,
    rlc, hrlc, mid, hmid, v5, _, cv6, _, rlp, hrlp, result, _, h⟩ := h
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
  have h1 := lincomb_sum_route self.curve_work ll.2 _ _ ll.1 hll
  have h2 := lincomb_sum_route ll.2 rlc.2 _ _ rlc.1 hrlc
  have hi := interpolation_commitment_route _ mid.2 _ _ mid.1 hmid
  have h3 := lincomb_sum_route mid.2.curve_work rlp.2 _ _ rlp.1 hrlp
  change (mid.2.kernel.isSome, CurveWork.isLanes rlp.2) = route self
  rw [h3]
  change route mid.2 = route self
  rw [hi]
  simp only [route, h2, h1]

private def flowRoute (r : ControlFlow (verify.CellBatchVerifier × Usize)
    (verify.CellBatchVerifier × Usize)) : Bool × Bool :=
  match r with
  | .cont x => route x.1
  | .done x => route x.1

private theorem decode_cell_body_route [RuntimeFeatures] (self : verify.CellBatchVerifier)
    (cell : Array U8 2048#usize) (j : Usize) (r : ControlFlow _ _)
    (h : verify.CellBatchVerifier.decode_cell_loop.body cell self j = ok r) :
    flowRoute r = route self := by
  unfold verify.CellBatchVerifier.decode_cell_loop.body at h
  split at h
  · simp only [bind_success, Function.uncurry] at h
    repeat obtain ⟨x, hx, h⟩ := h
    cases x <;> simp only [bind_success] at h
    all_goals repeat obtain ⟨x, hx, h⟩ := h
    all_goals rfl
  · cases h
    rfl

private theorem decode_cell_loop_route [RuntimeFeatures] (self next : verify.CellBatchVerifier)
    (cell : Array U8 2048#usize) (j k : Usize)
    (h : verify.CellBatchVerifier.decode_cell_loop self cell j = ok (next, k)) :
    route next = route self := by
  apply loop_success_invariant
    (fun x : verify.CellBatchVerifier × Usize => verify.CellBatchVerifier.decode_cell_loop.body cell x.1 x.2)
    (fun x => route x.1 = route self) (fun y => route y.1 = route self) ?_ (self, j) (next, k) h rfl
  intro x r hr hx
  have he := decode_cell_body_route x.1 cell x.2 r hr
  cases r <;> exact he.trans hx

theorem decode_cell_route [RuntimeFeatures] (self next : verify.CellBatchVerifier)
    (cell : Array U8 2048#usize) (b : Bool)
    (h : self.decode_cell cell = ok (b, next)) : route next = route self := by
  simp only [verify.CellBatchVerifier.decode_cell, bind_success, Function.uncurry] at h
  obtain ⟨x, hx, h⟩ := h
  obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
  exact decode_cell_loop_route self x.1 cell 0#usize x.2 hx

private theorem decode_cells_body_route [RuntimeFeatures] (self : verify.CellBatchVerifier)
    (cells : Slice (Array U8 2048#usize)) (j : Usize) (r : ControlFlow _ _)
    (h : verify.CellBatchVerifier.decode_cells_loop.body cells self j = ok r) :
    flowRoute r = route self := by
  simp only [verify.CellBatchVerifier.decode_cells_loop.body] at h
  split at h
  · simp only [bind_success, Function.uncurry] at h
    obtain ⟨cell, _, x, hx, h⟩ := h
    have hr := decode_cell_route self x.2 cell x.1 hx
    split at h
    · simp only [bind_success] at h
      obtain ⟨k, _, h⟩ := h
      cases h
      exact hr
    · cases h
      exact hr
  · cases h
    rfl

private theorem decode_cells_loop_route [RuntimeFeatures] (self next : verify.CellBatchVerifier)
    (cells : Slice (Array U8 2048#usize)) (j k : Usize)
    (h : verify.CellBatchVerifier.decode_cells_loop self cells j = ok (next, k)) :
    route next = route self := by
  apply loop_success_invariant
    (fun x : verify.CellBatchVerifier × Usize => verify.CellBatchVerifier.decode_cells_loop.body cells x.1 x.2)
    (fun x => route x.1 = route self) (fun y => route y.1 = route self) ?_ (self, j) (next, k) h rfl
  intro x r hr hx
  have he := decode_cells_body_route x.1 cells x.2 r hr
  cases r <;> exact he.trans hx

theorem decode_cells_route [RuntimeFeatures] (self next : verify.CellBatchVerifier)
    (cells : Slice (Array U8 2048#usize)) (b : Bool)
    (h : self.decode_cells cells = ok (b, next)) : route next = route self := by
  cases hk : self.kernel with
  | none =>
    simp only [verify.CellBatchVerifier.decode_cells, hk, bind_success, Function.uncurry] at h
    obtain ⟨v, _, x, hx, h⟩ := h
    obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
    simpa only [route, hk] using
      decode_cells_loop_route {self with evaluations := v, kernel := none} x.1 cells 0#usize x.2 hx
  | some kernel =>
    simp only [verify.CellBatchVerifier.decode_cells, hk, bind_success] at h
    obtain ⟨_, _, h⟩ := h
    obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
    rfl

theorem decode_proofs_route [RuntimeFeatures] [KzgExternals] (self next : verify.CellBatchVerifier)
    (proofs : Slice (Array U8 48#usize)) (b : Bool)
    (h : self.decode_proofs proofs = ok (b, next)) : route next = route self := by
  simp only [verify.CellBatchVerifier.decode_proofs, bind_success, Function.uncurry] at h
  obtain ⟨_, _, h⟩ := h
  obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
  rfl

theorem decode_commitments_route [RuntimeFeatures] [KzgExternals] (self next : verify.CellBatchVerifier) (b : Bool)
    (h : self.decode_commitments = ok (b, next)) : route next = route self := by
  simp only [verify.CellBatchVerifier.decode_commitments, bind_success, Function.uncurry] at h
  obtain ⟨_, _, h⟩ := h
  obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
  rfl

theorem verify_route [RuntimeFeatures] [KzgExternals] (self next : verify.CellBatchVerifier)
    (commitments : Slice (Array U8 48#usize)) (indices : Slice U64)
    (cells : Slice (Array U8 2048#usize)) (proofs : Slice (Array U8 48#usize)) (b : Bool)
    (h : self.verify commitments indices cells proofs = ok (b, next)) : route next = route self := by
  simp only [verify.CellBatchVerifier.verify] at h
  split at h
  · cases h
    rfl
  · split at h
    · cases h
      rfl
    · split at h
      · cases h
        rfl
      · simp only [bind_success] at h
        obtain ⟨k, _, h⟩ := h
        split at h
        · cases h
          rfl
        · simp only [bind_success, Function.uncurry] at h
          obtain ⟨d, _, first, hfirst, h⟩ := h
          have h1 : route first.2 = route self := decode_commitments_route {self with commitments := d} first.2 first.1 hfirst
          split at h
          · simp only [bind_success, Function.uncurry] at h
            obtain ⟨second, hsecond, h⟩ := h
            have h2 := (decode_cells_route first.2 second.2 cells second.1 hsecond).trans h1
            split at h
            · simp only [bind_success, Function.uncurry] at h
              obtain ⟨third, hthird, h⟩ := h
              have h3 := (decode_proofs_route second.2 third.2 proofs third.1 hthird).trans h2
              split at h
              · simp only [bind_success, Function.uncurry] at h
                obtain ⟨challenge, _, h⟩ := h
                exact (pairing_holds_route _ next challenge indices cells b h).trans h3
              · obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
                exact h3
            · obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
              exact h2
          · obtain ⟨_, rfl⟩ := Prod.mk.inj (Result.ok.inj h)
            exact h1

theorem verify_preserves_routes [RuntimeFeatures] [KzgExternals] (self next : verify.CellBatchVerifier)
    (commitments : Slice (Array U8 48#usize)) (indices : Slice U64)
    (cells : Slice (Array U8 2048#usize)) (proofs : Slice (Array U8 48#usize)) (b : Bool)
    (h : self.verify commitments indices cells proofs = ok (b, next)) :
    next.kernel.isSome = self.kernel.isSome ∧ CurveWork.isLanes next.curve_work = CurveWork.isLanes self.curve_work := by
  exact Prod.mk.inj (verify_route self next commitments indices cells proofs b h)

end LeanBlsSimd.Kzg.Routes
