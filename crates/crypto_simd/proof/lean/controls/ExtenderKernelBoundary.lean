import controls.ExtenderLayout
import controls.ExtenderExternalBoundary
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary

open Kernel

set_option maxRecDepth 8000
set_option exponentiation.threshold 1000

private def rejectedInput : Slice U8 :=
  ⟨List.replicate 256 255#u8, by simp only [List.length_replicate]; scalar_tac⟩

private theorem rejected_input_size : rejectedInput.val.length = 256 := by
  simp only [rejectedInput, List.length_replicate]

private theorem rejected_first_integer :
    Fr.bytesBEToNat ((bytes rejectedInput.val).extract 0 32) = 2 ^ 256 - 1 := by
  decide +kernel

theorem rejected_decode_retains_raw_integer :
    ∃ out mask, fr8.Fr8.from_bytes rejectedInput 0#usize = ok (out, mask) ∧
      laneNat out ⟨0, by decide⟩ = 2 ^ 256 - 1 ∧ mask ≠ 255#u8 ∧ ¬ Bounded out := by
  obtain ⟨out, mask, hout, _, hlanes, hall⟩ := from_bytes_refinement rejectedInput 0#usize
    (by rw [rejected_input_size]; decide)
  have hraw : laneNat out ⟨0, by decide⟩ = 2 ^ 256 - 1 := by
    have hfirst : laneNat out ⟨0, by decide⟩ =
        Fr.bytesBEToNat ((bytes rejectedInput.val).extract 0 32) := by
      simpa only [UScalar.ofNatCore_val_eq, Nat.mul_zero, Nat.zero_add, Nat.mul_one]
        using (hlanes ⟨0, by decide⟩).1
    exact hfirst.trans rejected_first_integer
  refine ⟨out, mask, hout, hraw, ?_, ?_⟩
  · intro he
    have hc := hall.mp he ⟨0, by decide⟩
    rw [hraw] at hc
    exact (by decide : ¬ 2 ^ 256 - 1 < Fr.modulus) hc
  · intro hb
    have hc := hb.2 ⟨0, by decide⟩
    rw [hraw] at hc
    exact (by decide : ¬ 2 ^ 256 - 1 < 2 * Fr.modulus) hc

private theorem rejected_blob_first_integer :
    Fr.bytesBEToNat ((arrayBytes (layoutBlob 255#u8)).extract 0 32) = 2 ^ 256 - 1 := by
  have hchunk := blobChunk_bytes (layoutBlob 255#u8) 0 (by decide)
  have hsame : blobChunk (layoutBlob 255#u8) 0 (by decide) = layoutChunk 255#u8 := by
    apply Subtype.ext
    simp [-List.reduceReplicate, blobChunk, layoutBlob, layoutChunk, List.slice]
  rw [hsame] at hchunk
  rw [← hchunk]
  decide +kernel

theorem rejected_kernel_decode_retains_raw_integer
    (kernel : extension_kernel.ExtensionKernel) (hk : Kernel.StateInvariant kernel) :
    ∃ next, extension_kernel.ExtensionKernel.decode kernel (layoutBlob 255#u8) =
        ok (false, next) ∧ Kernel.StateInvariant next ∧ SameTables kernel next ∧
      laneNat next.data.val[0]! ⟨0, by decide⟩ = 2 ^ 256 - 1 ∧
      ¬ Bounded next.data.val[0]! := by
  obtain ⟨verdict, next, hdecode, hn, ht, hc, _, hraw, _⟩ :=
    Kernel.decode_refinement kernel hk (layoutBlob 255#u8)
  have hv : verdict = false := by
    cases verdict with
    | false => rfl
    | true => exact False.elim (layout_ff_blob_noncanonical (hc.mp rfl))
  subst verdict
  have hfirst : laneNat next.data.val[0]! ⟨0, by decide⟩ = 2 ^ 256 - 1 := by
    simpa only [Nat.mul_zero, Nat.zero_add, Nat.mul_one, rejected_blob_first_integer]
      using hraw ⟨0, by decide⟩ ⟨0, by decide⟩
  refine ⟨next, hdecode, hn, ht, hfirst, ?_⟩
  intro hb
  have hbound := hb.2 ⟨0, by decide⟩
  rw [hfirst] at hbound
  exact (by decide : ¬ 2 ^ 256 - 1 < 2 * Fr.modulus) hbound

def acceptEveryLane (input : Slice U8) : Result (fr8.Fr8 × U8) := do
  let (out, _) ← fr8.Fr8.from_bytes input 0#usize
  ok (out, 255#u8)

theorem accepting_every_lane_changes_generated_decode :
    fr8.Fr8.from_bytes rejectedInput 0#usize ≠ acceptEveryLane rejectedInput := by
  obtain ⟨out, mask, hout, _, hmask, _⟩ := rejected_decode_retains_raw_integer
  simp only [acceptEveryLane, hout, bind_tc_ok]
  intro he
  exact hmask (congrArg Prod.snd (Result.ok.inj he))

private def wrongPermute (a index b : M512) : M512 :=
  Vector.ofFn fun lane : Fin 8 =>
    if index[lane].toNat < 8 then a[index[lane].toNat % 8] else b[index[lane].toNat % 8]

theorem permute_uses_bit_three :
    _mm512_permutex2var_epi64 (.replicate 8 1) (.replicate 8 16) (.replicate 8 2) ≠
      wrongPermute (.replicate 8 1) (.replicate 8 16) (.replicate 8 2) := by
  decide +kernel

theorem permute_ignores_higher_index_bits (a b : M512) :
    _mm512_permutex2var_epi64 a (.replicate 8 16) b =
      _mm512_permutex2var_epi64 a (.replicate 8 0) b ∧
    _mm512_permutex2var_epi64 a (.replicate 8 24) b =
      _mm512_permutex2var_epi64 a (.replicate 8 8) b := by
  constructor <;> apply Vector.ext <;> intro i hi <;>
    simp [_mm512_permutex2var_epi64, Nat.testBit_eq_decide_div_mod_eq]

theorem omitting_multiplier_scale_changes_generated_multiplier (hfr : FrCorrect) :
    fr8.multiplier (frEncode 1) ≠ ok (frEncode 1) := by
  have h := Kernel.multiplier_refinement hfr (1 : Fr)
  rw [h.1]
  intro he
  have hword := congrArg (fun x : blst.blst_fr => x.l.val[0]!.val) (Result.ok.inj he)
  exact (by decide +kernel : (frEncode (1 * Fr.ofNat 16)).l.val[0]!.val ≠
    (frEncode 1).l.val[0]!.val) hword

theorem failing_simd_serialization_is_incorrect : ¬ SerializationLaw failSerialization :=
  failSerialization_rejected

theorem kernel_route_does_not_require_serialization (hfr : FrCorrect) :
    ∃ initial kernel,
      @cell_extender.CellExtender.new ⟨true, false, false⟩ = ok initial ∧
      initial.kernel = some kernel ∧ Extender.StateInvariant initial ∧
      ∀ blob cells, ∃ verdict next out,
        cell_extender.CellExtender.compute initial blob cells =
          ok (verdict, next, out) ∧
        (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) := by
  obtain ⟨initial, hnew, hi, hsimd⟩ := @new_dispatch_refinement ⟨true, false, false⟩ hfr
  cases hk : initial.kernel with
  | none => simp only [hk, Option.isSome_none] at hsimd; cases hsimd
  | some kernel =>
    refine ⟨initial, kernel, hnew, hk, hi, ?_⟩
    intro blob cells
    obtain ⟨verdict, next, out, hc, _, hm, _, _⟩ :=
      Kernel.compute_refinement initial hi kernel hk blob cells
    exact ⟨verdict, next, out, hc, hm⟩

end LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary

#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.rejected_decode_retains_raw_integer
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.rejected_kernel_decode_retains_raw_integer
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.accepting_every_lane_changes_generated_decode
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.permute_uses_bit_three
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.permute_ignores_higher_index_bits
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.omitting_multiplier_scale_changes_generated_multiplier
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.failing_simd_serialization_is_incorrect
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBoundary.kernel_route_does_not_require_serialization
