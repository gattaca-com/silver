import LeanBlsSimd.Kzg.InterpolationKernel.AddCell
import LeanBlsSimd.Kzg.InterpolationKernel.Check
import LeanBlsSimd.Kzg.InterpolationKernel.Column

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.InterpolationKernel.Controls

open Extender.Kernel

private theorem coefficient_zero_scale : shiftFactor 0 0 = (Fr.ofNat 64).inverse := by
  unfold shiftFactor
  rw [pow_zero]
  apply Fin.ext
  change ((Fr.ofNat 64).inverse.val * 1) % Fr.modulus = (Fr.ofNat 64).inverse.val
  simp only [Nat.mul_one, Nat.mod_eq_of_lt (Fr.ofNat 64).inverse.isLt]

theorem omitting_inverse_size_rejects_multiplier :
    ∃ weight,
      fr8.Fr8.splat (frEncode (shiftFactor 0 0 * Fr.ofNat 16)) = ok weight ∧
      MultiplierRep weight (fun _ => shiftFactor 0 0) ∧
      ¬ MultiplierRep weight (fun _ => 1) := by
  obtain ⟨weight, hcall, hrep⟩ := splat_multiplier_refinement (shiftFactor 0 0)
  refine ⟨weight, hcall, hrep, ?_⟩
  intro hwrong
  have he := (hrep.1.2 (0 : Fin 8)).symm.trans (hwrong.1.2 (0 : Fin 8))
  rw [coefficient_zero_scale] at he
  exact (by decide +kernel :
    (Fr.ofNat 64).inverse * Fr.ofNat (2^260) ≠ (1 : Fr) * Fr.ofNat (2^260)) he

private def batch (n : Nat) : fr8.Fr8 :=
  ⟨List.ofFn (fun j : Fin 5 => Vector.replicate 8
    (UInt64.ofNat (n / 2 ^ (52 * j.val) % 2 ^ 52))), by simp⟩

private def input : fr8.Fr8 := batch (Fr.modulus - 1)
private def weight : fr8.Fr8 := batch (2 ^ 260 % Fr.modulus)
private def product : fr8.Fr8 :=
  FrModel.toFr8 ((FrModel.ofFr8 input).mulRaw (FrModel.ofFr8 weight))

private theorem input_normal : Normalized input := by
  unfold Normalized
  decide +kernel

private theorem input_value : ∀ lane : Fin 8,
    laneValue input lane = Fr.ofNat (Fr.modulus - 1) := by decide +kernel

private theorem weight_valid : MultiplierRep weight (fun _ => 1) := by
  unfold MultiplierRep Represents Bounded Normalized
  decide +kernel

private theorem product_limb : (product.val[0]!)[0].toNat = 27021593469255680 := by
  decide +kernel

private def repeated (value : fr8.Fr8) : Slice fr8.Fr8 :=
  ⟨List.replicate 8 value, by simp; scalar_tac⟩

private def productValues : _root_.Array Fr :=
  _root_.Array.replicate 64 (Fr.ofNat (Fr.modulus - 1) * (1 : Fr))

theorem missing_first_normalise_rejects_dit_input :
    ∃ normal,
      Normalized input ∧ MultiplierRep weight (fun _ => 1) ∧
      fr8.Fr8.mul input weight = ok product ∧
      fr8.Fr8.normalise product = ok normal ∧
      DataRep (repeated normal) productValues ∧
      ¬ DataRep (repeated product) productValues := by
  have hmul : fr8.Fr8.mul input weight = ok product := FrModel.Fr8.mul_refines input weight
  obtain ⟨out, hout, hrep⟩ := mul_multiplier_refinement input weight
    (fun _ => Fr.ofNat (Fr.modulus - 1)) (fun _ => 1) input_normal input_value weight_valid
  have he : out = product := Result.ok.inj (hout.symm.trans hmul)
  subst out
  obtain ⟨normal, hnormal, hn, hv⟩ := normalise_lazy_refinement product _ hrep
    (by decide) (by decide)
  have hb : Bounded normal := by
    refine ⟨hn, fun lane => ?_⟩
    have hl := (hrep.1 lane).2.1
    rw [← (hv lane).1] at hl
    exact_mod_cast hl
  refine ⟨normal, input_normal, weight_valid, hmul, hnormal, ?_, ?_⟩
  · refine ⟨by simp [repeated, productValues], ?_⟩
    intro v
    have hvi : v.val < 8 := by simpa only [repeated, List.length_replicate] using v.isLt
    simp only [repeated, List.getElem_replicate]
    refine ⟨hb, fun lane => ?_⟩
    rw [(hv lane).2]
    simp only [productValues, _root_.Array.getElem!_replicate, show 8*v.val+lane.val < 64 by omega]
  · intro hraw
    have hbound := (hraw.2 ⟨0, by simp [repeated]⟩).1.1 (0 : Fin 5) (0 : Fin 8)
    simp only [repeated, List.getElem_replicate, Fin.getElem_fin, Fin.val_zero] at hbound
    rw [product_limb] at hbound
    norm_num at hbound

private def addCellWrongUsed [KzgExternals]
    (kernel : interpolation_kernel.InterpolationKernel)
    (cell : Array U8 2048#usize) (column : Usize) (power : blst.blst_fr) :
    Result interpolation_kernel.InterpolationKernel := do
  let next ← interpolation_kernel.InterpolationKernel.add_cell kernel cell column power
  ok { next with used := alloc.vec.Vec.set kernel.used 0#usize true }

theorem wrong_used_column_rejected [e : KzgExternals] (hblst : BlstCorrect e)
    (kernel : interpolation_kernel.InterpolationKernel) (hk : StateInvariant kernel)
    (cell : Array U8 2048#usize) (values : _root_.Array Fr) (hcell : CellRep cell values)
    (hflags : kernel.used.val = List.replicate 128 false) :
    ∃ next mutated,
      interpolation_kernel.InterpolationKernel.add_cell kernel cell 1#usize (frEncode 1) = ok next ∧
      next.used.val = kernel.used.val.set 1 true ∧
      addCellWrongUsed kernel cell 1#usize (frEncode 1) = ok mutated ∧
      mutated.used.val ≠ next.used.val := by
  obtain ⟨next, hcall, _, _, hused, _, _⟩ := add_cell_refinement hblst kernel hk cell
    1#usize 1 values (_root_.Array.replicate 64 0) (by decide) hcell
    (by simp [hflags]) (by intro _ j; simp [j.isLt])
  refine ⟨next, { next with used := alloc.vec.Vec.set kernel.used 0#usize true },
    hcall, hused, by simp only [addCellWrongUsed, hcall, bind_tc_ok], ?_⟩
  intro hwrong
  have he := congrArg (fun flags : List Bool => flags[1]!) (hwrong.trans hused)
  simp [alloc.vec.Vec.set, hflags] at he

private def noncanonicalCell : Array U8 2048#usize :=
  ⟨List.replicate 2048 255#u8, by simp only [List.length_replicate, UScalar.ofNatCore_val_eq]⟩

private theorem noncanonical_first :
    (bytesToBlsField ((arrayBytes noncanonicalCell).extract 0 32)).toOption.isSome = false := by
  decide +kernel

theorem canonical_cell_accepted (kernel : interpolation_kernel.InterpolationKernel)
    (cell : Array U8 2048#usize) (values : _root_.Array Fr) (hcell : CellRep cell values) :
    interpolation_kernel.InterpolationKernel.check_cell kernel cell = ok true := by
  rw [check_cell_refinement]
  congr 1
  simp only [decodedCellElements, List.flatMap_cons, List.flatMap_nil, List.append_nil,
    List.all_map, List.all_eq_true, List.mem_range]
  intro j hj
  simp only [Function.comp_apply]
  rw [hcell.2 ⟨j, hj⟩]
  rfl

theorem noncanonical_cell_rejected (kernel : interpolation_kernel.InterpolationKernel) :
    interpolation_kernel.InterpolationKernel.check_cell kernel noncanonicalCell = ok false ∧
      interpolation_kernel.InterpolationKernel.check_cell kernel noncanonicalCell ≠ ok true := by
  have hnot : (decodedCellElements [noncanonicalCell]).all Option.isSome ≠ true := by
    intro h
    have hall := List.all_eq_true.mp h
    have hmem : (bytesToBlsField ((arrayBytes noncanonicalCell).extract 0 32)).toOption ∈
        decodedCellElements [noncanonicalCell] := by
      simp only [decodedCellElements, List.flatMap_cons, List.flatMap_nil, List.append_nil]
      apply List.mem_map.mpr
      exact ⟨0, by simp, rfl⟩
    have he := hall _ hmem
    rw [noncanonical_first] at he
    exact Bool.noConfusion he
  have hfalse : (decodedCellElements [noncanonicalCell]).all Option.isSome = false :=
    Bool.eq_false_iff.mpr hnot
  rw [check_cell_refinement, hfalse]
  exact ⟨rfl, by intro h; cases h⟩

#print axioms omitting_inverse_size_rejects_multiplier
#print axioms missing_first_normalise_rejects_dit_input
#print axioms wrong_used_column_rejected
#print axioms canonical_cell_accepted
#print axioms noncanonical_cell_rejected

end LeanBlsSimd.Kzg.InterpolationKernel.Controls
