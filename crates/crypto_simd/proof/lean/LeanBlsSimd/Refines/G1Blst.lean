import LeanBlsSimd.Portable.G1DecoderContract

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG1

/-- Agreement includes rejection and every affine limb, including infinity's zero limbs. -/
def BlstMatchesSpec [KzgExternals] : Prop :=
  ∀ bytes : Array U8 48#usize, KzgExternals.uncompressG1 bytes = specVerdict bytes

class FallbackCorrect [RuntimeFeatures] [KzgExternals] : Prop where
  matchesSpec : RuntimeFeatures.simdAvailable = false → BlstMatchesSpec

theorem fallbackCorrect_ifma [RuntimeFeatures] [KzgExternals]
    (hifma : RuntimeFeatures.simdAvailable = true) : FallbackCorrect :=
  ⟨by simp [hifma]⟩

private def vectorSlice {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max) : Slice α :=
  ⟨v.toList, by simpa using h⟩

private theorem vectorSlice_set {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max)
    (i : Usize) (hi : i.val < n) (x : α) :
    (vectorSlice v h).set i x = vectorSlice (v.set i.val x hi) h := by
  apply Subtype.ext
  simp [vectorSlice, Slice.set, Slice.setAtNat, Vector.toList_set]

theorem blst_list_refines [KzgExternals]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option g1_point.G1Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, uncompress_all_in_g1_blst inputs out = ok result ∧
      result.val = inputs.val.map KzgExternals.uncompressG1 := by
  let target : Fin inputs.val.length → Option blst.blst_p1_affine :=
    fun i => KzgExternals.uncompressG1 inputs.val[i.val]
  let enc := fun v : Vector (Option blst.blst_p1_affine) inputs.val.length =>
    vectorSlice v inputs.property
  have ho : enc (ofSlice id out hlen) = out := by
    apply Subtype.ext
    simp [enc, vectorSlice]
  refine ⟨enc (Vector.ofFn target), ?_, ?_⟩
  · rw [uncompress_all_in_g1_blst, uncompress_all_in_g1_blst_loop, ← ho]
    apply loop_range (n := inputs.val.length) _ (Slice.len inputs) rfl enc
      (fun v j => v.set j (target j)) enc (ofSlice id out hlen) (enc (Vector.ofFn target))
    · intro r v he hs hn
      simp only [uncompress_all_in_g1_blst_loop.body, hn, bind_tc_ok,
        Function.uncurry_apply_pair]
    · intro r r' v j he hs he' hs' hn
      have hj : r.start.val < inputs.val.length := by omega
      simp only [uncompress_all_in_g1_blst_loop.body, hn, bind_tc_ok,
        Function.uncurry_apply_pair]
      rw [show Slice.index_usize inputs r.start = ok inputs.val[r.start.val] by
        simp [Slice.index_usize, hj]]
      simp only [uncompress_in_g1_blst, bind_tc_ok]
      have hupdate : ∀ x, Slice.update (enc v) r.start x = ok ((enc v).set r.start x) := by
        intro x
        simp [Slice.update, enc, vectorSlice, hj, Slice.set, Slice.setAtNat]
      have htarget : target j = KzgExternals.uncompressG1 inputs.val[r.start.val] := by
        simp only [target, hs]
      rw [htarget]
      cases KzgExternals.uncompressG1 inputs.val[r.start.val] <;>
        simp only [g1_point.G1Point.from_trusted, bind_tc_ok, hupdate,
          vectorSlice_set v inputs.property r.start hj, enc, hs]
    · rw [foldl_set_ofFn]
  · apply List.ext_getElem (by simp [enc, vectorSlice])
    intro i hi hj
    simp [enc, vectorSlice, target]

end LeanBlsSimd.UncompressG1
