import LeanBlsSimd.Refines.DecompressG1
import LeanBlsSimd.Spec.G1Encoding

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Decode
open DecompressG1
set_option maxRecDepth 4096

private theorem scan (b : Encoding) (i : Usize) (hi : i.val ≤ 48) :
    ∃ j, portable.decompress.extraordinary_loop (toArray toU8 b) i = ok j ∧
      (j = 48#usize ↔ ∀ k, i.val ≤ k → (hk : k < 48) → b[k] = 0) := by
  induction hn : 48-i.val generalizing i with
  | zero =>
    have he : i = 48#usize := UScalar.eq_of_val_eq (by change i.val = 48; omega)
    subst i
    refine ⟨48#usize,?_,?_⟩
    · rw [portable.decompress.extraordinary_loop,loop.eq_1]
      simp only [portable.decompress.extraordinary_loop.body,bls.COMPRESSED_LEN,
        lt_self_iff_false,if_false]
    · simp only [true_iff]
      intro k hlo hhi
      omega
  | succ n ih =>
    have hlt : i.val < 48 := by omega
    have hstep : i+1#usize = ok (UScalar.ofNatCore (i.val+1) (by scalar_tac)) := by
      rw [usize_add_ok _ _ (by scalar_tac)]
      rfl
    rw [portable.decompress.extraordinary_loop,loop.eq_1]
    simp only [portable.decompress.extraordinary_loop.body,bls.COMPRESSED_LEN,
      UScalar.lt_equiv,show (48#usize).val = 48 from rfl,hlt,if_true]
    simp (disch := omega) only [index_usize_toArray,bind_tc_ok]
    rw [show (0#u8) = toU8 0 from rfl]
    simp only [toU8_inj]
    by_cases hz : b[i.val] = 0
    · simp only [hz,if_true,hstep,bind_tc_ok]
      obtain ⟨j,hj,hs⟩ := ih (UScalar.ofNatCore (i.val+1) (by scalar_tac)) (by simp; omega) (by simp; omega)
      refine ⟨j,?_,?_⟩
      · simpa only [portable.decompress.extraordinary_loop,portable.decompress.extraordinary_loop.body,
          bls.COMPRESSED_LEN,UScalar.lt_equiv,show (48#usize).val = 48 from rfl,
          show (0#u8) = toU8 0 from rfl] using hj
      rw [hs]
      simp only [UScalar.ofNatCore_val_eq]
      constructor
      · intro h k hlo hk
        by_cases he : k=i.val
        · subst k; exact hz
        · exact h k (by omega) hk
      · intro h k hlo hk
        exact h k (by omega) hk
    · simp only [hz,if_false]
      refine ⟨i,rfl,?_⟩
      constructor
      · intro he
        have := congrArg UScalar.val he
        simp only [show (48#usize).val = 48 from rfl] at this
        omega
      · intro h
        exact False.elim (hz (h i.val (by omega) hlt))

theorem infinity_iff (b : Encoding) : b = G1Spec.infinity ↔
    b[0] = 192 ∧ ∀ k, 1 ≤ k → (hk : k < 48) → b[k] = 0 := by
  constructor
  · rintro rfl
    constructor
    · rfl
    · intro k hlo hk
      simp [G1Spec.infinity,show 0 ≠ k by omega]
  · intro h
    apply Vector.ext
    intro k hk
    by_cases hz : k=0
    · subst k
      simpa [G1Spec.infinity] using h.1
    · simpa [G1Spec.infinity,show 0 ≠ k from Ne.symm hz] using h.2 k (by omega) hk

theorem extraordinary_refines (b : Encoding) :
    portable.decompress.extraordinary (toArray toU8 b) =
      ok (if b = G1Spec.infinity then
        some (toBlstP1Affine (point (.replicate 6 0) (.replicate 6 0))) else none) := by
  obtain ⟨j,hj,hs⟩ := scan b 1#usize (by decide)
  simp only [portable.decompress.extraordinary,hj,bind_tc_ok]
  simp (disch := decide) only [index_usize_toArray,bind_tc_ok]
  rw [DecompressG2.FLAG_COMPRESSED_refines,DecompressG2.FLAG_INFINITY_refines]
  simp only [lift,bind_tc_ok,toU8_or,toU8_inj,bls.COMPRESSED_LEN]
  change (if b[0] = 192 then (if j = 48#usize then _ else _) else _) = _
  by_cases hb : b = G1Spec.infinity
  · obtain ⟨h0,ht⟩ := (infinity_iff b).mp hb
    have hj48 : j = 48#usize := hs.mpr ht
    simp only [h0,hj48,hb,if_true,default_refines,bind_tc_ok]
    rfl
  · by_cases h0 : b[0] = 192
    · have hj48 : j ≠ 48#usize := fun h => hb ((infinity_iff b).mpr ⟨h0,hs.mp h⟩)
      simp only [h0,hj48,hb,if_true,if_false]
    · simp only [h0,hb,if_false]

end LeanBlsSimd.Portable.Decode
