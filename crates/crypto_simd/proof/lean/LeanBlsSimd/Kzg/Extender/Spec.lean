import LeanBlsSimd.Kzg.Extender.SpecMath
import LeanBlsSimd.Kzg.ByteSerialization
import LeanBlsSimd.Kzg.SpecBridge

open EthCryptographySpecs Bls Kzg Kzg.BitReversal

namespace LeanBlsSimd.Kzg.Extender

private theorem foldl_congr_mem {α β : Type} (xs : List α) (f g : β → α → β)
    (hf : ∀ x ∈ xs, ∀ acc, f acc x = g acc x) (init : β) :
    xs.foldl f init = xs.foldl g init := by
  induction xs generalizing init with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.foldl_cons, hf x (by simp)]
    exact ih (fun x hx => hf x (by simp [hx])) _

private theorem join_chunks (blob : ByteArray) (start n : Nat) :
    (List.range n).foldl
      (fun b i => b ++ blob.extract (32 * (start + i)) (32 * (start + i + 1)))
        ByteArray.empty = blob.extract (32 * start) (32 * (start + n)) := by
  induction n with
  | zero => simp
  | succ n ih =>
    simp only [List.range_succ, List.foldl_append, ih, List.foldl_cons, List.foldl_nil]
    rw [ByteArray.extract_append_extract]
    rw [Nat.min_eq_left (by omega), Nat.max_eq_right (by omega)]
    rfl

theorem original_cell_eq (blob : ByteArray) (a : Array Fr)
    (hdecode : blobToPolynomial blob = .ok a) (c : Nat) (hc : c < 64) :
    cosetEvalsToCell (Array.ofFn (fun j : Fin 64 => a[64 * c + j.val]!)) =
      blob.extract (c * 2048) ((c + 1) * 2048) := by
  have ha : a.size = 4096 := size_blobToPolynomial blob a hdecode
  unfold cosetEvalsToCell
  rw [← Array.foldl_toList]
  simp only [Array.toList_range, Constants.FIELD_ELEMENTS_PER_CELL]
  trans (List.range 64).foldl
    (fun b i => b ++ blob.extract (32 * (64 * c + i)) (32 * (64 * c + i + 1)))
      ByteArray.empty
  · apply foldl_congr_mem
    intro i hi b
    have hi' : i < 64 := List.mem_range.mp hi
    rw [getElem!_pos _ i (by simpa only [Array.size_ofFn] using hi'), Array.getElem_ofFn]
    have hij : 64 * c + i < a.size := by omega
    have hd := getElem_blobToPolynomial blob a hdecode (64 * c + i) hij
    rw [← getElem!_pos a (64 * c + i) hij] at hd
    have he := blsFieldToBytes_of_decode _ _ hd
    simp only [Constants.BYTES_PER_FIELD_ELEMENT] at he
    rw [he]
    rw [Nat.mul_comm (64 * c + i) 32, Nat.mul_comm (64 * c + i + 1) 32]
  · rw [join_chunks]
    rw [show 32 * (64 * c) = c * 2048 by omega,
      show 32 * (64 * c + 64) = (c + 1) * 2048 by omega]

private def specCell (a : Array Fr) (c : Nat) : Cell :=
  cosetEvalsToCell ((Array.ofFn (fun j : Fin 64 =>
    (rootsOfUnityBrp 8192)[64 * c + j.val]!)).map
      (evaluatePolynomialcoeff (polynomialEvalToCoeff a)))

private theorem specCell_original (blob : ByteArray) (a : Array Fr)
    (hdecode : blobToPolynomial blob = .ok a) (c : Nat) (hc : c < 64) :
    specCell a c = blob.extract (c * 2048) ((c + 1) * 2048) := by
  have ha : a.size = 4096 := size_blobToPolynomial blob a hdecode
  rw [← original_cell_eq blob a hdecode c hc]
  unfold specCell
  apply congrArg cosetEvalsToCell
  apply Array.ext
  · simp
  · intro i hi hi'
    have hi64 : i < 64 := by simpa only [Array.size_ofFn] using hi'
    simp only [Array.getElem_map, Array.getElem_ofFn]
    exact coeff_eval_original a ha (64 * c + i) (by omega)

private theorem specCell_extension (a : Array Fr) (ha : a.size = 4096)
    (c : Nat) (hc : 64 ≤ c) (hc' : c < 128) :
    specCell a c = cosetEvalsToCell
      ((bitReversalPermutation (Model.extension a)).extract
        ((c - 64) * 64) ((c - 64) * 64 + 64)) := by
  unfold specCell
  apply congrArg cosetEvalsToCell
  apply Array.ext
  · simp only [Array.size_map, Array.size_ofFn, Array.size_extract,
      size_bitReversalPermutation, extension_size a ha]
    omega
  · intro i hi hi'
    have hi64 : i < 64 := by simpa only [Array.size_map, Array.size_ofFn] using hi
    simp only [Array.getElem_map, Array.getElem_ofFn, Array.getElem_extract]
    have hn : 64 * c + i = 4096 + ((c - 64) * 64 + i) := by omega
    rw [hn, coeff_eval_extension a ha ((c - 64) * 64 + i) (by omega)]
    rw [getElem!_pos _ _ (by
      simp only [size_bitReversalPermutation, extension_size a ha]
      omega)]

private theorem list_mapM_pure_of {α β : Type} (xs : List α)
    (f : α → KzgM β) (g : α → β) (h : ∀ x ∈ xs, f x = pure (g x)) :
    xs.mapM f = pure (xs.map g) := by
  induction xs with
  | nil => simp
  | cons x xs ih =>
    rw [List.mapM_cons, h x (by simp), pure_bind,
      ih (fun y hy => h y (by simp [hy]))]
    simp

private theorem spec_cells_eq (a : Array Fr) :
    (Array.range 128).mapM (fun i => do
      let coset ← (cosetForCell i : Except KzgError Coset)
      pure (cosetEvalsToCell (coset.map (evaluatePolynomialcoeff (polynomialEvalToCoeff a)))))
        = (pure (Array.ofFn (fun i : Fin 128 => specCell a i.val)) : KzgM (Array Cell)) := by
  rw [Array.mapM_eq_mapM_toList]
  rw [list_mapM_pure_of _ _ (specCell a)]
  · simp only [map_pure]
    apply congrArg (pure : Array Cell → KzgM (Array Cell))
    apply Array.ext
    · simp
    · intro i hi hi'
      simp
  · intro i hi
    have hi128 : i < 128 := by simpa only [Array.toList_range, List.mem_range] using hi
    rw [cosetForCell_eq i hi128]
    rfl

theorem model_spec (blob : ByteArray) :
    (EthCryptographySpecs.Kzg.computeCells blob).run = pure (Model.extend blob) := by
  suffices h : computeCells blob = liftE (Model.extend blob) by
    exact congrArg ExceptT.run h
  by_cases hs : blob.size = Constants.BYTES_PER_BLOB
  · cases hd : blobToPolynomial blob with
    | error e =>
      simp only [computeCells, hs, ne_eq, not_true_eq_false, ↓reduceIte,
        pure_bind, hd, liftM_eq_liftE]
      change ((throw e : KzgM (Array Fr)) >>= _) = liftE (Model.extend blob)
      rw [ExceptT.bind_throw]
      simp only [Model.extend, hd, bind, Except.bind]
      rfl
    | ok a =>
      have hout : Array.ofFn (fun i : Fin 128 => specCell a i.val) =
          Array.ofFn (fun i : Fin 128 => if i.val < 64 then
            blob.extract (i.val * 2048) ((i.val + 1) * 2048)
          else cosetEvalsToCell ((bitReversalPermutation (Model.extension a)).extract
            ((i.val - 64) * 64) ((i.val - 64) * 64 + 64))) := by
        apply congrArg (Array.ofFn : (Fin 128 → Cell) → Array Cell)
        funext i
        by_cases hi : i.val < 64
        · rw [if_pos hi, specCell_original blob a hd i.val hi]
        · rw [if_neg hi]
          exact specCell_extension a (size_blobToPolynomial blob a hd)
            i.val (by omega) i.isLt
      simp only [computeCells, hs, ne_eq, not_true_eq_false, ↓reduceIte,
        pure_bind, hd, liftM_eq_liftE]
      change ((pure a : KzgM (Array Fr)) >>= _) = liftE (Model.extend blob)
      rw [pure_bind]
      change (Array.range 128).mapM _ = liftE (Model.extend blob)
      have hcells := spec_cells_eq a
      simp only [liftM_eq_liftE] at hcells
      rw [hcells, hout]
      simp only [Model.extend, hd, bind, Except.bind, pure, Except.pure]
      rfl
  · have hd : blobToPolynomial blob = .error (.badBlobSize blob.size) := by
      simp [blobToPolynomial, hs]
      rfl
    simp [computeCells, Model.extend, hs, hd, liftE]
    rfl

end LeanBlsSimd.Kzg.Extender
