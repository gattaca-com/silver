import LeanBlsSimd.Kzg.Extender.Kernel.Basic
import LeanBlsSimd.Refines.Fr8Core
import LeanBlsSimd.Proofs.Fr8

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

open scoped EthCryptographySpecs.Bls.Fr

theorem getElem_lane_ofFr8 (x : fr8.Fr8) (j : Fin 5) (lane : Fin 8) :
    ((FrModel.ofFr8 x).lane lane)[j.val] = (x.val[j.val]!)[lane] := by
  have hj : j.val < x.val.length := by rw [x.property]; exact j.isLt
  rw [getElem!_pos x.val j.val hj]
  simp only [FrModel.Fr8.lane, FrModel.ofFr8, Vector.getElem_map, getElem_ofArray, id_eq]

theorem laneNat_eq_val (x : fr8.Fr8) (lane : Fin 8) :
    laneNat x lane = FrModel.val ((FrModel.ofFr8 x).lane lane) := by
  unfold laneNat FrModel.val
  rw [Fin.sum_univ_def]
  apply congrArg List.sum
  apply List.map_congr_left
  intro j _
  change (x.val[j.val]!)[lane].toNat * 2 ^ (52 * j.val) =
    ((FrModel.ofFr8 x).lane lane)[j.val].toNat * 2 ^ (52 * j.val)
  rw [getElem_lane_ofFr8]

theorem normalized_iff_model (x : fr8.Fr8) :
    Normalized x ↔ ∀ lane : Fin 8, ∀ j : Fin FrModel.LIMBS,
      ((FrModel.ofFr8 x).lane lane)[j].toNat < 2 ^ 52 := by
  constructor
  · intro h lane j
    change ((FrModel.ofFr8 x).lane lane)[j.val].toNat < 2 ^ 52
    rw [getElem_lane_ofFr8]
    exact h j lane
  · intro h j lane
    have h' := h lane j
    change ((FrModel.ofFr8 x).lane lane)[j.val].toNat < 2 ^ 52 at h'
    rwa [getElem_lane_ofFr8] at h'

theorem bounded_iff_model (x : fr8.Fr8) :
    Bounded x ↔ ∀ lane : Fin 8, FrModel.Fr8Inv ((FrModel.ofFr8 x).lane lane) := by
  rw [Bounded, normalized_iff_model]
  constructor
  · rintro ⟨hn, hb⟩ lane
    exact ⟨hn lane, by simpa only [laneNat_eq_val] using hb lane⟩
  · intro h
    exact ⟨fun lane => (h lane).normal, fun lane => by
      simpa only [laneNat_eq_val] using (h lane).bound⟩

end LeanBlsSimd.Kzg.Extender.Kernel
