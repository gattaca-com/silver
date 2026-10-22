import LeanBlsSimd.Msm8.Batch
import LeanBlsSimd.Msm8.PointRowsRep
import LeanBlsSimd.Msm8.Queue

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls
open Msm8
section
attribute [local irreducible] Msm8.affineAdd

theorem affineAdd_point (xa ya xb yb inverse : Fp8) (lane : Fin 8)
    (x₁ y₁ x₂ y₂ : ChainField)
    (hxa : xa.Holds lane x₁) (hya : ya.Holds lane y₁)
    (hxb : xb.Holds lane x₂) (hyb : yb.Holds lane y₂)
    (hinv : inverse.Holds lane ((x₂ : ChainField) - x₁)⁻¹)
    (hv₁ : G1.Valid ⟨x₁, y₁, Fp.one⟩) (hv₂ : G1.Valid ⟨x₂, y₂, Fp.one⟩)
    (hne : (x₁ : ChainField) ≠ x₂) :
    ∃ x₃ y₃ : Fp, (affineAdd xa ya xb yb inverse).1.Holds lane x₃ ∧
      (affineAdd xa ya xb yb inverse).2.Holds lane y₃ ∧
      G1.Valid ⟨x₃, y₃, Fp.one⟩ ∧
      G1.toPoint ⟨x₃, y₃, Fp.one⟩ = G1.toPoint ⟨x₁, y₁, Fp.one⟩ + G1.toPoint ⟨x₂, y₂, Fp.one⟩ := by
  let slope : ChainField := ((y₂ : ChainField) - (y₁ : ChainField)) * ((x₂ : ChainField) - (x₁ : ChainField))⁻¹
  let x₃ : ChainField := slope ^ 2 - (x₁ : ChainField) - (x₂ : ChainField)
  let y₃ : ChainField := slope * ((x₁ : ChainField) - x₃) - (y₁ : ChainField)
  have h₁ : G1Spec.E.Nonsingular x₁ y₁ :=
    (WeierstrassCurve.Jacobian.nonsingular_some (W' := G1.curve) (x₁ : ChainField) (y₁ : ChainField)).mp hv₁
  have h₂ : G1Spec.E.Nonsingular x₂ y₂ :=
    (WeierstrassCurve.Jacobian.nonsingular_some (W' := G1.curve) (x₂ : ChainField) (y₂ : ChainField)).mp hv₂
  have h₃ : G1Spec.E.Nonsingular x₃ y₃ := affine_sum_nonsingular h₁ h₂ hne
  have hv₃ : G1.Valid ⟨x₃, y₃, Fp.one⟩ :=
    (WeierstrassCurve.Jacobian.nonsingular_some (W' := G1.curve) x₃ y₃).mpr h₃
  obtain ⟨hx, hy⟩ := affineAdd_correct xa ya xb yb inverse lane x₁ y₁ x₂ y₂ hxa hya hxb hyb hinv
  refine ⟨x₃, y₃, hx, hy, hv₃, ?_⟩
  change WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![x₃, y₃, 1] =
    WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![x₁, y₁, 1] +
      WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![x₂, y₂, 1]
  rw [WeierstrassCurve.Jacobian.Point.toAffine_some hv₃,
    WeierstrassCurve.Jacobian.Point.toAffine_some hv₁,
    WeierstrassCurve.Jacobian.Point.toAffine_some hv₂]
  exact (affine_sum_point h₁ h₂ hne).symm

theorem RowRep.frame {rows rows' : List Limbs} {p : ℕ} {P : G1Spec.E.Point}
    (h : RowRep rows p P)
    (hx : rows'[2 * p]! = rows[2 * p]!) (hy : rows'[2 * p + 1]! = rows[2 * p + 1]!) : RowRep rows' p P := by
  obtain ⟨x, y, hr, hv, hp⟩ := h
  refine ⟨x, y, ?_, hv, hp⟩
  simpa only [readPoint, hx, hy] using hr

end
end LeanBlsSimd.BatchedRefines

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls
open Msm8

def AffineLaneRep (x y : Fp8) (lane : Fin 8) (P : G1Spec.E.Point) : Prop :=
  ∃ a b : Fp, x.Holds lane a ∧ y.Holds lane b ∧
    G1.Valid ⟨a, b, Fp.one⟩ ∧ G1.toPoint ⟨a, b, Fp.one⟩ = P

theorem transposeToFp8_lane (x : Fp8) (lane : Fin 8) :
    (transpose8 (ofArray id (toFp8 x)))[lane] = x.lane lane := by
  apply Vector.ext
  intro i hi
  simp [toFp8, transpose8, Fp8.lane, Fin.getElem_fin]
  exact (Vector.getElem_map (fun row : M512 => row[lane]) (xs := x.limbs) hi).symm

theorem storeLane_rep (store : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (j : Fin 8) (P : G1Spec.E.Point)
    (hb : 2 * indices[j] + 1 < store.rows.val.length)
    (hrep : ∃x y : Fp, PointRowsHold (xs[j], ys[j]) x y ∧
      G1.Valid ⟨x, y, Fp.one⟩ ∧ G1.toPoint ⟨x, y, Fp.one⟩ = P) :
    RowRep (pointRows (storeLane store indices xs ys j)) indices[j] P := by
  obtain ⟨x, y, hr, hv, hp⟩ := hrep
  refine ⟨x, y, ?_, hv, hp⟩
  have hx := storeLane_row_self store indices xs ys j 0 hb
  have hy := storeLane_row_self store indices xs ys j 1 hb
  change (pointRows (storeLane store indices xs ys j))[2 * indices[j] + 0]! = xs[j] at hx
  change (pointRows (storeLane store indices xs ys j))[2 * indices[j] + 1]! = ys[j] at hy
  simp only [Nat.add_zero] at hx
  simpa only [readPoint, hx, hy] using hr

theorem storeLane_fold_rep (store : msm8.store.PointStore) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) (lanes : List (Fin 8)) (p : ℕ) (P : G1Spec.E.Point)
    (hb : 2 * p + 1 < store.rows.val.length)
    (hsame : ∀j : Fin 8, indices[j] = p → ∃x y : Fp, PointRowsHold (xs[j], ys[j]) x y ∧
      G1.Valid ⟨x, y, Fp.one⟩ ∧ G1.toPoint ⟨x, y, Fp.one⟩ = P)
    (hstart : RowRep (pointRows store) p P ∨ ∃j ∈ lanes, indices[j] = p) :
    RowRep (pointRows (lanes.foldl (fun current j => storeLane current indices xs ys j) store)) p P := by
  induction lanes generalizing store with
  | nil =>
    rcases hstart with h|⟨j, hj, _⟩
    · exact h
    · simp only [List.not_mem_nil] at hj
  | cons j lanes ih =>
    simp only [List.foldl_cons]
    apply ih _ (by simpa only [storeLane_length] using hb) hsame
    by_cases hj : indices[j] = p
    · left
      exact hj ▸ storeLane_rep store indices xs ys j P (by simpa only [hj] using hb) (hsame j hj)
    · rcases hstart with h|⟨k, hk, hkp⟩
      · left
        exact RowRep.frame h (storeLane_frame store indices xs ys j p 0 (Ne.symm hj))
          (storeLane_frame store indices xs ys j p 1 (Ne.symm hj))
      · right
        refine ⟨k, ?_, hkp⟩
        simp only [List.mem_cons] at hk
        rcases hk with rfl|hk
        · exact False.elim (hj hkp)
        · exact hk

theorem writeCoordinates_rep (store : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) (p : ℕ) (P : G1Spec.E.Point) (hb : 2 * p + 1 < store.rows.val.length)
    (hsame : ∀lane : Fin 8, (pointIndices indices)[lane] = p → AffineLaneRep x y lane P)
    (hwritten : ∃lane : Fin 8, (pointIndices indices)[lane] = p) :
    RowRep (pointRows (writeCoordinates store indices x y)) p P := by
  apply storeLane_fold_rep store _ _ _ _ p P hb
  · intro lane hlane
    obtain ⟨a, b, hx, hy, hv, hp⟩ := hsame lane hlane
    refine ⟨a, b, ?_, hv, hp⟩
    simp only [transposeToFp8_lane, PointRowsHold]
    exact ⟨hx.inv, hx.eq, hy.inv, hy.eq⟩
  · right
    obtain ⟨lane, hlane⟩ := hwritten
    exact ⟨lane, List.mem_finRange lane, hlane⟩

theorem writeCoordinates_rep_frame (store : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) (p : ℕ) (P : G1Spec.E.Point) (hr : RowRep (pointRows store) p P)
    (hne : ∀lane : Fin 8, p ≠ (pointIndices indices)[lane]) :
    RowRep (pointRows (writeCoordinates store indices x y)) p P :=
  RowRep.frame hr (writeCoordinates_frame store indices x y p 0 hne)
    (writeCoordinates_frame store indices x y p 1 hne)

section
attribute [local irreducible] writeCoordinates pairResult

theorem finishPair_rep (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) (p : ℕ) (P : G1Spec.E.Point)
    (hb : 2 * p + 1 < store.rows.val.length)
    (hsame : ∀ (j : Fin 2) (lane : Fin 8),
      (pointIndices (referencesAt self.out.val (g + j.val)).1)[lane] = p →
      AffineLaneRep (pairResult self store g inv j).1 (pairResult self store g inv j).2 lane P)
    (hwritten : ∃ (j : Fin 2) (lane : Fin 8),
      (pointIndices (referencesAt self.out.val (g + j.val)).1)[lane] = p) :
    RowRep (pointRows (finishPair self store g inv)) p P := by
  rw [finishPair_eq]
  by_cases hlast : ∃lane : Fin 8, (pointIndices (referencesAt self.out.val (g + 1)).1)[lane] = p
  · exact writeCoordinates_rep _ _ _ _ p P
      (by simpa only [writeCoordinates_length] using hb) (hsame 1) hlast
  · have hfirst : ∃lane : Fin 8, (pointIndices (referencesAt self.out.val g).1)[lane] = p := by
      obtain ⟨j, lane, hj⟩ := hwritten
      fin_cases j
      · exact ⟨lane, hj⟩
      · exact False.elim (hlast ⟨lane, hj⟩)
    exact writeCoordinates_rep_frame _ _ _ _ p P
      (writeCoordinates_rep _ _ _ _ p P hb (hsame 0) hfirst)
      (fun lane h => hlast ⟨lane, h.symm⟩)

theorem finishPair_rep_frame (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) (p : ℕ) (P : G1Spec.E.Point)
    (hr : RowRep (pointRows store) p P)
    (hne : ∀ (j : Fin 2) (lane : Fin 8),
      p ≠ (pointIndices (referencesAt self.out.val (g + j.val)).1)[lane]) :
    RowRep (pointRows (finishPair self store g inv)) p P :=
  RowRep.frame hr (finishPair_frame self store g inv p 0 hne) (finishPair_frame self store g inv p 1 hne)

end
end LeanBlsSimd.BatchedRefines

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls
open Msm8

def signedValue (values : ℕ → G1Spec.E.Point) (refs : Array U32 8#usize × U8) (lane : Fin 8) : G1Spec.E.Point :=
  if (ofU8 refs.2).toNat.testBit lane then -values (pointIndices refs.1)[lane]
  else values (pointIndices refs.1)[lane]

def sumValue (self : msm8.pairs.BatchedAdds) (values : ℕ → G1Spec.E.Point) (g : ℕ) (lane : Fin 8) : G1Spec.E.Point :=
  signedValue values (referencesAt self.a.val g) lane + signedValue values (referencesAt self.b.val g) lane

def delta (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore) (g : ℕ) (lane : Fin 8) : ChainField :=
  decode ((loadedCoordinate store (referencesAt self.b.val g).1 0).lane lane)-
    decode ((loadedCoordinate store (referencesAt self.a.val g).1 0).lane lane)

def InputsRep (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (groups : ℕ) : Prop :=
  ∀ g < groups, ∀lane : Fin 8,
    RowRep (pointRows store) (pointIndices (referencesAt self.a.val g).1)[lane]
      (values (pointIndices (referencesAt self.a.val g).1)[lane]) ∧
    RowRep (pointRows store) (pointIndices (referencesAt self.b.val g).1)[lane]
      (values (pointIndices (referencesAt self.b.val g).1)[lane])

section
attribute [local irreducible] Msm8.affineAdd pairResult

theorem pairResult_rep (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (groups g : ℕ) (inv : Vector Fp8 2) (j : Fin 2) (lane : Fin 8)
    (hinputs : InputsRep self store values groups) (hg : g + j.val < groups)
    (hinv : inv[j].Holds lane (delta self store (g + j.val) lane)⁻¹)
    (hne : delta self store (g + j.val) lane ≠ 0) :
    AffineLaneRep (pairResult self store g inv j).1 (pairResult self store g inv j).2 lane
      (sumValue self values (g + j.val) lane) := by
  obtain ⟨ha, hb⟩ := hinputs (g + j.val) hg lane
  obtain ⟨xa, ya, hxa, hya, hva, hpa⟩ := load_signed_point store _ (ofU8 (referencesAt self.a.val (g + j.val)).2) lane _ ha
  obtain ⟨xb, yb, hxb, hyb, hvb, hpb⟩ := load_signed_point store _ (ofU8 (referencesAt self.b.val (g + j.val)).2) lane _ hb
  let xaf : ChainField := xa
  let xbf : ChainField := xb
  have hd : delta self store (g + j.val) lane = xbf - xaf := by
    simp only [delta, hxa.eq, hxb.eq, xaf, xbf]
  have hxab : xaf ≠ xbf := by
    intro he
    apply hne
    rw [hd, he, sub_self]
  rw [hd] at hinv
  obtain ⟨x, y, hx, hy, hv, hp⟩ := affineAdd_point _ _ _ _ _ lane xaf ya xbf yb
    hxa hya hxb hyb hinv hva hvb hxab
  refine ⟨x, y, ?_, ?_, hv, ?_⟩
  · simpa only [pairResult, signedCoordinates] using hx
  · simpa only [pairResult, signedCoordinates] using hy
  · simpa only [xaf, xbf, sumValue, signedValue, hpa, hpb] using hp

end
end LeanBlsSimd.BatchedRefines

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls
open Msm8

structure BatchGeometry (adds : msm8.pairs.BatchedAdds) (values : ℕ → G1Spec.E.Point) (groups : ℕ) : Prop where
  sources : ∀ g h, g < groups → h < groups → g / 2 ≠ h / 2 → ∀l m : Fin 8,
    (pointIndices (referencesAt adds.a.val g).1)[l] ≠ (pointIndices (referencesAt adds.out.val h).1)[m] ∧
    (pointIndices (referencesAt adds.b.val g).1)[l] ≠ (pointIndices (referencesAt adds.out.val h).1)[m]
  outputs : ∀ g h, g < groups → h < groups → g / 2 ≠ h / 2 → ∀l m : Fin 8,
    (pointIndices (referencesAt adds.out.val g).1)[l] ≠ (pointIndices (referencesAt adds.out.val h).1)[m]
  collisions : ∀ g h, g < groups → h < groups → g / 2 = h / 2 → ∀l m : Fin 8,
    (pointIndices (referencesAt adds.out.val g).1)[l] = (pointIndices (referencesAt adds.out.val h).1)[m] →
    sumValue adds values g l = sumValue adds values h m

def PendingReads (self : msm8.pairs.BatchedAdds) (initial current : msm8.store.PointStore) (groups : ℕ) : Prop :=
  ∀g < groups, signedCoordinates current (referencesAt self.a.val g) = signedCoordinates initial (referencesAt self.a.val g) ∧
    signedCoordinates current (referencesAt self.b.val g) = signedCoordinates initial (referencesAt self.b.val g)

def OutputsRep (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (groups lower : ℕ) : Prop :=
  ∀g, lower ≤ g → g < groups → ∀lane : Fin 8,
    RowRep (pointRows store) (pointIndices (referencesAt self.out.val g).1)[lane] (sumValue self values g lane)

section
attribute [local irreducible] pairResult finishPair Msm8.affineAdd signedCoordinates

theorem pairResult_of_reads (self : msm8.pairs.BatchedAdds) (initial current : msm8.store.PointStore)
    (g : ℕ) (inv : Vector Fp8 2) (j : Fin 2)
    (ha : signedCoordinates current (referencesAt self.a.val (g + j.val)) =
      signedCoordinates initial (referencesAt self.a.val (g + j.val)))
    (hb : signedCoordinates current (referencesAt self.b.val (g + j.val)) =
      signedCoordinates initial (referencesAt self.b.val (g + j.val))) :
    pairResult self current g inv j = pairResult self initial g inv j := by
  simp only [pairResult, ha, hb]

theorem executeFrom_rows_correct (self : msm8.pairs.BatchedAdds) (initial : msm8.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (n : ℕ) (products inv : Vector Fp8 4)
    (hinputs : InputsRep self initial values (2 * n))
    (hgeom : BatchGeometry self values (2 * n))
    (hb : ExecutionBounds self initial (2 * n))
    (hchain : ∀lane, ChainInvariant self products (fun g => delta self initial g lane) (2 * n) lane)
    (hinv : ∀lane (k : Fin 4), inv[k].Holds lane (chainValues (fun g => delta self initial g lane) (2 * n) k)⁻¹) :
    OutputsRep self (executeFrom self n initial inv) values (2 * n) 0 := by
  let P := fun (m : ℕ) (current : msm8.store.PointStore) =>
    current.rows.val.length = initial.rows.val.length ∧ PendingReads self initial current (2 * m) ∧
      OutputsRep self current values (2 * n) (2 * m)
  have hp : P n initial := by
    refine ⟨rfl, ?_, ?_⟩
    · intro g hg; exact ⟨rfl, rfl⟩
    · intro g hg hgn; omega
  have hstep (m : ℕ) (current : msm8.store.PointStore) (recovered : Vector Fp8 2)
      (hcap : 2 * (m + 1) ≤ 2 * n) (hcurrent : P (m + 1) current)
      (hrecovered : ∀lane (j : Fin 2), recovered[j].Holds lane (delta self initial (2 * m + j.val) lane)⁻¹) :
      P m (finishPair self current (2 * m) recovered) := by
    obtain ⟨hlen, hreads, houtputs⟩ := hcurrent
    have hnew (j : Fin 2) (lane : Fin 8) :
        RowRep (pointRows (finishPair self current (2 * m) recovered))
          (pointIndices (referencesAt self.out.val (2 * m + j.val)).1)[lane]
          (sumValue self values (2 * m + j.val) lane) := by
      apply finishPair_rep self current (2 * m) recovered _ _
      · rw [hlen]
        exact hb.outBounds (2 * m + j.val) (by omega) lane
      · intro k l hindex
        rw [pairResult_of_reads self initial current (2 * m) recovered k
          (hreads _ (by omega)).1 (hreads _ (by omega)).2]
        have hrep := pairResult_rep self initial values (2 * n) (2 * m) recovered k l
          hinputs (by omega) (hrecovered l k) ((hchain l).nonzero _ (by omega))
        rw [hgeom.collisions _ _ (by omega) (by omega) (by omega) l lane hindex] at hrep
        exact hrep
      · exact ⟨j, lane, rfl⟩
    refine ⟨(finishPair_length _ _ _ _).trans hlen, ?_, ?_⟩
    · intro g hg
      constructor
      · exact (finishPair_signedCoordinates_frame self current (2 * m) recovered (referencesAt self.a.val g)
          (fun l j k => (hgeom.sources g (2 * m + j.val) (by omega) (by omega) (by omega) l k).1)).trans
          (hreads g (by omega)).1
      · exact (finishPair_signedCoordinates_frame self current (2 * m) recovered (referencesAt self.b.val g)
          (fun l j k => (hgeom.sources g (2 * m + j.val) (by omega) (by omega) (by omega) l k).2)).trans
          (hreads g (by omega)).2
    · intro g hlow hg lane
      by_cases hnewgroup : g < 2 * (m + 1)
      · let j : Fin 2 := ⟨g - 2 * m, by omega⟩
        have hj : 2 * m + j.val = g := by dsimp only [j]; omega
        simpa only [hj] using hnew j lane
      · exact finishPair_rep_frame self current (2 * m) recovered _ _ (houtputs g (by omega) hg lane)
          (fun j k => hgeom.outputs g (2 * m + j.val) hg (by omega) (by omega) lane k)
  have hresult := executeFrom_invariant self products (fun lane g => delta self initial g lane)
    (2 * n) hchain P hstep n initial inv (by omega) hp hinv
  exact hresult.2.2

end
end LeanBlsSimd.BatchedRefines

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls
open Msm8

theorem InputsRep.delta_holds (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (groups : ℕ) (hinputs : InputsRep self store values groups)
    (g : ℕ) (hg : g < groups) (lane : Fin 8) :
    (difference self store g).Holds lane (delta self store g lane) := by
  obtain ⟨ha, hb⟩ := hinputs g hg lane
  obtain ⟨xa, ya, hra, _, _⟩ := ha
  obtain ⟨xb, yb, hrb, _, _⟩ := hb
  have hxa := (loadedCoordinate_holds store _ lane xa ya hra).1
  have hxb := (loadedCoordinate_holds store _ lane xb yb hrb).1
  simpa only [difference, delta, hxa.eq, hxb.eq] using hxb.sub hxa

theorem runModel_success_rows (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (groups n : ℕ) (heven : groups = 2 * n)
    (hinputs : InputsRep self store values groups) (hgeom : BatchGeometry self values groups)
    (hb : ExecutionBounds self store groups) (hsuccess : (runModel self store groups).1 = true) :
    OutputsRep self (runModel self store groups).2.2 values groups 0 := by
  let prepared := prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0
  have hstop : ¬prepared.2.2 < groups := by
    intro h
    simp only [runModel, show (prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups from h,
      if_true, Bool.false_eq_true] at hsuccess
  have hcomplete : prepared.2.2 = groups := by
    have hr := (prepareFrom_range store groups self (Vector.replicate 4 Fp8.one) 0).2
    change prepared.2.2 ≤ 0 + groups at hr
    omega
  obtain ⟨ha, hbrefs, ho⟩ := prepareFrom_references store groups self (Vector.replicate 4 Fp8.one) 0
  change prepared.1.a = self.a at ha
  change prepared.1.b = self.b at hbrefs
  change prepared.1.out = self.out at ho
  have hd (g : ℕ) (lane : Fin 8) : delta prepared.1 store g lane = delta self store g lane := by
    simp only [delta, ha, hbrefs]
  have hins : InputsRep prepared.1 store values (2 * n) := by
    simpa only [InputsRep, ha, hbrefs, heven] using hinputs
  have hgeo : BatchGeometry prepared.1 values (2 * n) := by
    refine ⟨?_, ?_, ?_⟩
    · simpa only [ha, hbrefs, ho, heven] using hgeom.sources
    · simpa only [ho, heven] using hgeom.outputs
    · simpa only [ho, sumValue, ha, hbrefs, heven] using hgeom.collisions
  have hbounds : ExecutionBounds prepared.1 store (2 * n) := by
    rw [← heven]
    exact prepareFrom_bounds store groups self (Vector.replicate 4 Fp8.one) 0 groups hb
  have hchain (lane : Fin 8) : ChainInvariant prepared.1 prepared.2.1
      (fun g => delta prepared.1 store g lane) (2 * n) lane := by
    have h := prepareFrom_chainInvariant store groups self (Vector.replicate 4 Fp8.one) 0 groups
      (fun g => delta self store g lane) lane (by omega) hb.prep
      (ChainInvariant.initial self _ lane) (fun g hg => InputsRep.delta_holds self store values groups hinputs g hg lane)
    change ChainInvariant prepared.1 prepared.2.1 _ prepared.2.2 lane at h
    simpa only [hcomplete, heven, hd] using h
  have hinv (lane : Fin 8) (k : Fin 4) :
      (Msm8.batchInverse prepared.2.1)[k].Holds lane
        (chainValues (fun g => delta prepared.1 store g lane) (2 * n) k)⁻¹ :=
    Msm8.batchInverse_correct prepared.2.1 _ lane (hchain lane).product
      (chainValues_nonzero _ _ (hchain lane).nonzero) k
  have hout := executeFrom_rows_correct prepared.1 store values n prepared.2.1
    (Msm8.batchInverse prepared.2.1) hins hgeo hbounds hchain hinv
  simp only [runModel, show ¬(prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups from hstop,
    if_false, show groups / 2 = n by omega]
  intro g hlow hg lane
  have h := hout g hlow (by omega) lane
  simpa only [ho, sumValue, ha, hbrefs] using h

theorem executeFrom_rep_frame (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (n : ℕ) (inv : Vector Fp8 4) (p : ℕ) (P : G1Spec.E.Point)
    (hrep : RowRep (pointRows store) p P)
    (hne : ∀g < 2 * n, ∀lane : Fin 8, p ≠ (pointIndices (referencesAt self.out.val g).1)[lane]) :
    RowRep (pointRows (executeFrom self n store inv)) p P := by
  induction n generalizing store inv with
  | zero => exact hrep
  | succ n ih =>
    exact ih _ _ (finishPair_rep_frame self store (2 * n) (unwindChains self (2 * n) inv).1 p P hrep
      (fun j lane => hne _ (by omega) lane)) (fun g hg => hne g (by omega))

theorem runModel_rep_frame (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups p : ℕ) (P : G1Spec.E.Point) (hrep : RowRep (pointRows store) p P)
    (hne : ∀g < groups, ∀lane : Fin 8, p ≠ (pointIndices (referencesAt self.out.val g).1)[lane]) :
    RowRep (pointRows (runModel self store groups).2.2) p P := by
  let prepared := prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0
  have ho := (prepareFrom_references store groups self (Vector.replicate 4 Fp8.one) 0).2.2
  change prepared.1.out = self.out at ho
  by_cases hstop : prepared.2.2 < groups
  · simpa only [runModel, show (prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups from hstop, if_true] using hrep
  · simp only [runModel, show ¬(prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups from hstop, if_false]
    apply executeFrom_rep_frame prepared.1 store (groups / 2) _ p P hrep
    intro g hg lane
    rw [ho]
    exact hne g (by omega) lane

theorem executeFrom_metadata (self : msm8.pairs.BatchedAdds) (n : ℕ)
    (store : msm8.store.PointStore) (inv : Vector Fp8 4) :
    (executeFrom self n store inv).len = store.len ∧
    (executeFrom self n store inv).rows.val.length = store.rows.val.length := by
  induction n generalizing store inv with
  | zero => exact ⟨rfl, rfl⟩
  | succ n ih =>
    simpa only [executeFrom, finishPair_len, finishPair_length] using
      ih (finishPair self store (2 * n) (unwindChains self (2 * n) inv).1)
        (unwindChains self (2 * n) inv).2

theorem runModel_metadata (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (groups : ℕ) :
    (runModel self store groups).2.2.len = store.len ∧
    (runModel self store groups).2.2.rows.val.length = store.rows.val.length ∧
    (runModel self store groups).2.1.a = self.a ∧
    (runModel self store groups).2.1.b = self.b ∧
    (runModel self store groups).2.1.out = self.out := by
  have href := prepareFrom_references store groups self (Vector.replicate 4 Fp8.one) 0
  by_cases h : (prepareFrom store groups self (Vector.replicate 4 Fp8.one) 0).2.2 < groups
  · simp only [runModel, h, if_true]
    exact ⟨trivial, trivial, href⟩
  · simp only [runModel, h, if_false]
    exact ⟨(executeFrom_metadata _ _ _ _).1, (executeFrom_metadata _ _ _ _).2, href⟩

theorem run_rows_correct (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (groups entries : Usize)
    (ha : 0 < self.a.val.length) (hb : self.a.val.length ≤ self.b.val.length)
    (ho : self.a.val.length ≤ self.out.val.length)
    (hg : groups.val = ((self.a.val.length - 1) / 16 + 1) * 2)
    (he : entries.val = groups.val * 8) (hsize : entries.val < 2 ^ 32)
    (hbound : ExecutionBounds (paddedAdds self groups entries) store groups.val)
    (hinputs : InputsRep (paddedAdds self groups entries) store values groups.val)
    (hgeom : BatchGeometry (paddedAdds self groups entries) values groups.val) :
    let result := runModel (paddedAdds self groups entries) store groups.val
    self.run store = ok result ∧
    (result.1 = true → OutputsRep (paddedAdds self groups entries) result.2.2 values groups.val 0) ∧
    (result.1 = false → result.2.2 = store) ∧
    (∀p P, RowRep (pointRows store) p P →
      (∀g < groups.val, ∀lane : Fin 8, p ≠ (pointIndices
        (referencesAt (paddedAdds self groups entries).out.val g).1)[lane]) →
      RowRep (pointRows result.2.2) p P) := by
  refine ⟨run_refines self store groups entries ha hb ho hg he hsize hbound, ?_, ?_, ?_⟩
  · exact runModel_success_rows _ store values groups.val ((self.a.val.length - 1) / 16 + 1)
      (by omega) hinputs hgeom hbound
  · intro h
    exact (runModel_rejected _ store groups.val h).1
  · exact runModel_rep_frame _ store groups.val

end LeanBlsSimd.BatchedRefines

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls Msm8

theorem referencesAt_index (refs : List U32) (g : ℕ) (lane : Fin 8) :
    (pointIndices (referencesAt refs g).1)[lane] = refs[g * 8 + lane]!.val % 2 ^ 31 := by
  simp [referencesAt, pointIndices, referenceBatch_indices, referenceIndex_val]

theorem signedValue_reference (values : ℕ → G1Spec.E.Point) (refs : List U32)
    (g : ℕ) (lane : Fin 8) :
    signedValue values (referencesAt refs g) lane =
      if refs[g * 8 + lane]!.bv.getLsbD 31 then -values (refs[g * 8 + lane]!.val % 2 ^ 31)
      else values (refs[g * 8 + lane]!.val % 2 ^ 31) := by
  rw [signedValue, referencesAt_index]
  have hmask : (ofU8 (referencesAt refs g).2).toNat.testBit lane = refs[g * 8 + lane]!.bv.getLsbD 31 :=
    referenceBatch_sign refs g lane
  rw [hmask]

theorem resize_last_get (refs : List U32) (n i : ℕ) (hpos : 0 < refs.length) (hi : i < n) :
    (refs.resize n refs[refs.length - 1]!)[i]! = refs[min i (refs.length - 1)]! := by
  rw [getElem!_pos (refs.resize n refs[refs.length - 1]!) i (by simpa only [List.resize_length] using hi)]
  by_cases hl : i < refs.length
  · have hm : min i (refs.length - 1) = i := Nat.min_eq_left (by omega)
    simp [List.resize, hm, hi, hl]
  · have hm : min i (refs.length - 1) = refs.length - 1 := Nat.min_eq_right (by omega)
    simp [List.resize, hm, List.getElem_append, hi, hl]

def paddedIndex (length g : ℕ) (lane : Fin 8) : ℕ := min (g * 8 + lane.val) (length - 1)

theorem paddedIndex_lt (length g : ℕ) (lane : Fin 8) (hpos : 0 < length) :
    paddedIndex length g lane < length := by
  unfold paddedIndex
  omega

theorem paddedIndex_block (length g : ℕ) (lane : Fin 8) (_hpos : 0 < length)
    (hg : g < ((length - 1) / 16 + 1) * 2) :
    paddedIndex length g lane / 16 = g / 2 := by
  unfold paddedIndex
  have hl := lane.isLt
  omega

theorem paddedIndex_ne (length g h : ℕ) (l m : Fin 8) (hpos : 0 < length)
    (hg : g < ((length - 1) / 16 + 1) * 2) (hh : h < ((length - 1) / 16 + 1) * 2)
    (hne : g / 2 ≠ h / 2) : paddedIndex length g l ≠ paddedIndex length h m := by
  intro he
  have ha := paddedIndex_block length g l hpos hg
  have hb := paddedIndex_block length h m hpos hh
  omega

theorem resize_map_get {α : Type} (jobs : List α) (f : α → U32) (n i : ℕ)
    (hpos : 0 < jobs.length) (hi : i < n) :
    ((jobs.map f).resize n (jobs.map f)[jobs.length - 1]!)[i]! =
      f (jobs[min i (jobs.length - 1)]'(by omega)) := by
  have h := resize_last_get (jobs.map f) n i (by simpa only [List.length_map] using hpos) hi
  simp only [List.length_map] at h
  rw [h, getElem!_pos _ _ (by simp only [List.length_map]; omega), List.getElem_map]

open QueueRefines

theorem JobIndependent.symm {a b : Job} (h : JobIndependent a b) : JobIndependent b a :=
  ⟨Ne.symm h.1, h.2.2.2.1, h.2.2.2.2, h.2.1, h.2.2.1⟩

theorem jobs_independent_get (jobs : List Job) (hi : jobs.Pairwise JobIndependent)
    (i j : ℕ) (hib : i < jobs.length) (hjb : j < jobs.length) (hne : i ≠ j) :
    JobIndependent jobs[i] jobs[j] := by
  by_cases hlt : i < j
  · exact List.pairwise_iff_getElem.mp hi i j hib hjb hlt
  · exact JobIndependent.symm (List.pairwise_iff_getElem.mp hi j i hjb hib (by omega))

def paddedJob (jobs : List Job) (hpos : 0 < jobs.length) (g : ℕ) (lane : Fin 8) : Job :=
  jobs[paddedIndex jobs.length g lane]'(paddedIndex_lt _ _ _ hpos)

theorem paddedAdds_job (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output) (he : entries.val = groups.val * 8)
    (g : ℕ) (hg : g < groups.val) (lane : Fin 8) :
    (paddedAdds self groups entries).a.val[g * 8 + lane]! = (paddedJob jobs hpos g lane).first ∧
    (paddedAdds self groups entries).b.val[g * 8 + lane]! = (paddedJob jobs hpos g lane).second ∧
    (paddedAdds self groups entries).out.val[g * 8 + lane]! = (paddedJob jobs hpos g lane).output := by
  have hindex : g * 8 + lane.val < entries.val := by have := lane.isLt; omega
  simp only [paddedAdds, resizeVec, ha, hb, ho, List.length_map]
  exact ⟨resize_map_get jobs Job.first _ _ hpos hindex,
    resize_map_get jobs Job.second _ _ hpos hindex,
    resize_map_get jobs Job.output _ _ hpos hindex⟩

theorem pointIndex_mod (r : U32) : pointIndex r = r.val % 2 ^ 31 :=
  referenceIndex_val r

def signedReferenceValue (values : ℕ → G1Spec.E.Point) (r : U32) : G1Spec.E.Point :=
  if r.bv.getLsbD 31 then -values (pointIndex r) else values (pointIndex r)

theorem paddedJob_mem (jobs : List Job) (hpos : 0 < jobs.length) (g : ℕ) (lane : Fin 8) :
    paddedJob jobs hpos g lane ∈ jobs := List.getElem_mem _

theorem paddedAdds_indices (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output) (he : entries.val = groups.val * 8)
    (hout : ∀job ∈ jobs, job.output.val < 2 ^ 31)
    (g : ℕ) (hg : g < groups.val) (lane : Fin 8) :
    (pointIndices (referencesAt (paddedAdds self groups entries).a.val g).1)[lane] =
      pointIndex (paddedJob jobs hpos g lane).first ∧
    (pointIndices (referencesAt (paddedAdds self groups entries).b.val g).1)[lane] =
      pointIndex (paddedJob jobs hpos g lane).second ∧
    (pointIndices (referencesAt (paddedAdds self groups entries).out.val g).1)[lane] =
      (paddedJob jobs hpos g lane).output.val := by
  obtain ⟨h1, h2, h3⟩ := paddedAdds_job self jobs groups entries hpos ha hb ho he g hg lane
  simp only [referencesAt_index, h1, h2, h3, pointIndex_mod]
  exact ⟨trivial, trivial, Nat.mod_eq_of_lt (hout _ (paddedJob_mem jobs hpos g lane))⟩

theorem paddedAdds_sum (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output) (he : entries.val = groups.val * 8)
    (values : ℕ → G1Spec.E.Point) (g : ℕ) (hg : g < groups.val) (lane : Fin 8) :
    sumValue (paddedAdds self groups entries) values g lane =
      signedReferenceValue values (paddedJob jobs hpos g lane).first +
      signedReferenceValue values (paddedJob jobs hpos g lane).second := by
  obtain ⟨h1, h2, _⟩ := paddedAdds_job self jobs groups entries hpos ha hb ho he g hg lane
  simp only [sumValue, signedValue_reference, h1, h2, signedReferenceValue, pointIndex_mod]

theorem paddedAdds_geometry (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output)
    (hg : groups.val = ((jobs.length - 1) / 16 + 1) * 2) (he : entries.val = groups.val * 8)
    (hind : jobs.Pairwise JobIndependent) (hout : ∀job ∈ jobs, job.output.val < 2 ^ 31)
    (values : ℕ → G1Spec.E.Point) :
    BatchGeometry (paddedAdds self groups entries) values groups.val := by
  have hidx := paddedAdds_indices self jobs groups entries hpos ha hb ho he hout
  have hneq (g h : ℕ) (hlg : g < groups.val) (hlh : h < groups.val) (hd : g / 2 ≠ h / 2)
      (l m : Fin 8) : JobIndependent (paddedJob jobs hpos g l) (paddedJob jobs hpos h m) :=
    jobs_independent_get jobs hind _ _ (paddedIndex_lt _ _ _ hpos) (paddedIndex_lt _ _ _ hpos)
      (paddedIndex_ne _ _ _ _ _ hpos (by omega) (by omega) hd)
  refine ⟨?_, ?_, ?_⟩
  · intro g h hlg hlh hd l m
    rw [(hidx g hlg l).1, (hidx g hlg l).2.1, (hidx h hlh m).2.2]
    exact ⟨Ne.symm (hneq g h hlg hlh hd l m).2.2.2.1,
      Ne.symm (hneq g h hlg hlh hd l m).2.2.2.2⟩
  · intro g h hlg hlh hd l m
    rw [(hidx g hlg l).2.2, (hidx h hlh m).2.2]
    exact (hneq g h hlg hlh hd l m).1
  · intro g h hlg hlh _ l m heq
    rw [(hidx g hlg l).2.2, (hidx h hlh m).2.2] at heq
    have hp : paddedIndex jobs.length g l = paddedIndex jobs.length h m := by
      by_contra hn
      exact (jobs_independent_get jobs hind _ _ (paddedIndex_lt _ _ _ hpos)
        (paddedIndex_lt _ _ _ hpos) hn).1 heq
    have hj : paddedJob jobs hpos g l = paddedJob jobs hpos h m := by unfold paddedJob; simp only [hp]
    rw [paddedAdds_sum self jobs groups entries hpos ha hb ho he values g hlg l,
      paddedAdds_sum self jobs groups entries hpos ha hb ho he values h hlh m, hj]

theorem paddedAdds_inputs (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output) (he : entries.val = groups.val * 8)
    (hout : ∀job ∈ jobs, job.output.val < 2 ^ 31)
    (store : msm8.store.PointStore) (values : ℕ → G1Spec.E.Point)
    (hinputs : ∀job ∈ jobs, RowRep (pointRows store) (pointIndex job.first) (values (pointIndex job.first)) ∧
      RowRep (pointRows store) (pointIndex job.second) (values (pointIndex job.second))) :
    InputsRep (paddedAdds self groups entries) store values groups.val := by
  intro g hg lane
  obtain ⟨h1, h2, _⟩ := paddedAdds_indices self jobs groups entries hpos ha hb ho he hout g hg lane
  rw [h1, h2]
  exact hinputs _ (paddedJob_mem jobs hpos g lane)

theorem paddedAdds_bounds (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output) (he : entries.val = groups.val * 8)
    (hout : ∀job ∈ jobs, job.output.val < 2 ^ 31) (store : msm8.store.PointStore)
    (hrows : ∀job ∈ jobs, 2 * pointIndex job.first + 1 < store.rows.val.length ∧
      2 * pointIndex job.second + 1 < store.rows.val.length ∧ 2 * job.output.val + 1 < store.rows.val.length) :
    ExecutionBounds (paddedAdds self groups entries) store groups.val := by
  have haLen : groups.val * 8 ≤ (paddedAdds self groups entries).a.val.length := by
    simp only [paddedAdds, resizeVec, List.resize_length, he, le_refl]
  have hbLen : groups.val * 8 ≤ (paddedAdds self groups entries).b.val.length := by
    simp only [paddedAdds, resizeVec, List.resize_length, he, le_refl]
  have hoLen : groups.val * 8 ≤ (paddedAdds self groups entries).out.val.length := by
    simp only [paddedAdds, resizeVec, List.resize_length, he, le_refl]
  have hdx : groups.val ≤ (paddedAdds self groups entries).dx.val.length := by
    simp only [paddedAdds, resizeVec, List.resize_length, le_refl]
  have hprefix : groups.val ≤ (paddedAdds self groups entries).prefix.val.length := by
    simp only [paddedAdds, resizeVec, List.resize_length, le_refl]
  refine ⟨⟨haLen, hbLen, hdx, hprefix, ?_, ?_⟩, hoLen, ?_⟩
  · intro g hg lane
    rw [(paddedAdds_indices self jobs groups entries hpos ha hb ho he hout g hg lane).1]
    exact (hrows _ (paddedJob_mem jobs hpos g lane)).1
  · intro g hg lane
    rw [(paddedAdds_indices self jobs groups entries hpos ha hb ho he hout g hg lane).2.1]
    exact (hrows _ (paddedJob_mem jobs hpos g lane)).2.1
  · intro g hg lane
    rw [(paddedAdds_indices self jobs groups entries hpos ha hb ho he hout g hg lane).2.2]
    exact (hrows _ (paddedJob_mem jobs hpos g lane)).2.2

end LeanBlsSimd.BatchedRefines

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls Msm8 QueueRefines

theorem paddedJob_original (jobs : List Job) (hpos : 0 < jobs.length)
    (i : ℕ) (hi : i < jobs.length) :
    paddedJob jobs hpos (i / 8) ⟨i % 8, Nat.mod_lt _ (by decide)⟩ = jobs[i] := by
  have he : paddedIndex jobs.length (i / 8) ⟨i % 8, Nat.mod_lt _ (by decide)⟩ = i := by
    unfold paddedIndex
    dsimp only
    omega
  simp only [paddedJob, he]

theorem OutputsRep.jobs (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output)
    (hg : groups.val = ((jobs.length - 1) / 16 + 1) * 2) (he : entries.val = groups.val * 8)
    (hout : ∀job ∈ jobs, job.output.val < 2 ^ 31)
    (store : msm8.store.PointStore) (values : ℕ → G1Spec.E.Point)
    (hreps : OutputsRep (paddedAdds self groups entries) store values groups.val 0) :
    ∀job ∈ jobs, RowRep (pointRows store) job.output.val
      (signedReferenceValue values job.first + signedReferenceValue values job.second) := by
  intro job hjob
  obtain ⟨i, hi, rfl⟩ := List.mem_iff_getElem.mp hjob
  let lane : Fin 8 := ⟨i % 8, Nat.mod_lt _ (by decide)⟩
  have hig : i / 8 < groups.val := by omega
  have h := hreps (i / 8) (by omega) hig lane
  rw [(paddedAdds_indices self jobs groups entries hpos ha hb ho he hout _ hig lane).2.2,
    paddedAdds_sum self jobs groups entries hpos ha hb ho he values _ hig lane,
    paddedJob_original jobs hpos i hi] at h
  exact h

theorem run_jobs_correct (self : msm8.pairs.BatchedAdds) (jobs : List Job)
    (groups entries : Usize) (hpos : 0 < jobs.length)
    (ha : self.a.val = jobs.map Job.first) (hb : self.b.val = jobs.map Job.second)
    (ho : self.out.val = jobs.map Job.output)
    (hg : groups.val = ((jobs.length - 1) / 16 + 1) * 2) (he : entries.val = groups.val * 8)
    (hsize : entries.val < 2 ^ 32) (hind : jobs.Pairwise JobIndependent)
    (hout : ∀job ∈ jobs, job.output.val < 2 ^ 31)
    (store : msm8.store.PointStore) (values : ℕ → G1Spec.E.Point)
    (hrows : ∀job ∈ jobs, 2 * pointIndex job.first + 1 < store.rows.val.length ∧
      2 * pointIndex job.second + 1 < store.rows.val.length ∧ 2 * job.output.val + 1 < store.rows.val.length)
    (hinputs : ∀job ∈ jobs, RowRep (pointRows store) (pointIndex job.first) (values (pointIndex job.first)) ∧
      RowRep (pointRows store) (pointIndex job.second) (values (pointIndex job.second))) :
    let result := runModel (paddedAdds self groups entries) store groups.val
    self.run store = ok result ∧
    (result.1 = true → ∀job ∈ jobs, RowRep (pointRows result.2.2) job.output.val
      (signedReferenceValue values job.first + signedReferenceValue values job.second)) ∧
    (result.1 = false → result.2.2 = store) ∧
    result.2.2.len = store.len ∧ result.2.2.rows.val.length = store.rows.val.length ∧
    result.2.1.a.val.length = entries.val ∧
    (∀p P, RowRep (pointRows store) p P → (∀job ∈ jobs, p ≠ job.output.val) →
      RowRep (pointRows result.2.2) p P) := by
  have hbound := paddedAdds_bounds self jobs groups entries hpos ha hb ho he hout store hrows
  have hins := paddedAdds_inputs self jobs groups entries hpos ha hb ho he hout store values hinputs
  have hgeo := paddedAdds_geometry self jobs groups entries hpos ha hb ho hg he hind hout values
  have hrun := run_rows_correct self store values groups entries
    (by simpa only [ha, List.length_map] using hpos)
    (by simp only [ha, hb, List.length_map, le_refl])
    (by simp only [ha, ho, List.length_map, le_refl])
    (by simpa only [ha, List.length_map] using hg) he hsize hbound hins hgeo
  have hmeta := runModel_metadata (paddedAdds self groups entries) store groups.val
  refine ⟨hrun.1, ?_, hrun.2.2.1, hmeta.1, hmeta.2.1, ?_, ?_⟩
  · intro hs
    exact OutputsRep.jobs self jobs groups entries hpos ha hb ho hg he hout _ values (hrun.2.1 hs)
  · rw [hmeta.2.2.1]
    simp only [paddedAdds, resizeVec, List.resize_length]
  · intro p P hrep hne
    apply hrun.2.2.2 p P hrep
    intro g hlg lane
    rw [(paddedAdds_indices self jobs groups entries hpos ha hb ho he hout g hlg lane).2.2]
    exact hne _ (paddedJob_mem jobs hpos g lane)

end LeanBlsSimd.BatchedRefines
