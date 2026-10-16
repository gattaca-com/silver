import LeanBlsSimd.Extracted.Funs
import LeanBlsSimd.Kzg.Representation

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

private theorem bytes_beq_eq (xs ys : List U8) :
    (bytes xs == bytes ys) = decide (xs = ys) := by
  change ((xs.map (fun x => UInt8.ofBitVec x.bv)).toArray ==
    (ys.map (fun x => UInt8.ofBitVec x.bv)).toArray) = decide (xs = ys)
  rw [Bool.eq_iff_iff]
  simp only [beq_iff_eq, decide_eq_true_eq]
  constructor
  · intro h
    have hm := List.toArray_inj h
    have := congrArg (List.map (fun x : UInt8 => (⟨x.toBitVec⟩ : U8))) hm
    simpa [List.map_map, Function.comp_def] using this
  · rintro rfl
    rfl

private theorem same_bytes_index (a : Aeneas.Std.Array U8 48#usize) (i : Usize)
    (hi : i.val < 48) : Array.index_usize a i = ok a.val[i.val]! := by
  simp [Array.index_usize, a.property, hi]

private theorem same_bytes_loop_eq (a b : Aeneas.Std.Array U8 48#usize)
    (i : Usize) (hi : i.val ≤ 48)
    (hp : ∀ j, j < i.val → a.val[j]! = b.val[j]!) :
    ∃ j, loop (verify.same_bytes_loop.body a b) i = ok j ∧
      (j = 48#usize ↔ a.val = b.val) := by
  induction hk : 48 - i.val generalizing i with
  | zero =>
    have he : i.val = 48 := by omega
    have heq : a.val = b.val := by
      apply List.ext_getElem (by simp [a.property, b.property])
      intro j ha hb
      have hj : j < i.val := by simpa [a.property, he] using ha
      simpa only [getElem!_pos a.val j ha, getElem!_pos b.val j hb] using hp j hj
    refine ⟨i, ?_, ?_⟩
    · rw [loop.eq_1]
      simp [verify.same_bytes_loop.body, bls.COMPRESSED_LEN, he]
    · simp [heq, UScalar.eq_equiv, he]
  | succ k ih =>
    have hlt : i.val < 48 := by omega
    by_cases heq : a.val[i.val]! = b.val[i.val]!
    · have hbound : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
        have hb : 48 < 2 ^ UScalarTy.Usize.numBits := by
          rcases System.Platform.numBits_eq with h | h <;>
            simp [UScalarTy.numBits, h]
        omega
      let i' : Usize := UScalar.ofNatCore (i.val + 1) hbound
      have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
      have hadd : i + 1#usize = ok i' := by
        show UScalar.tryMk .Usize (i.val + (1#usize).val) = ok i'
        have hb : i.val + 1 < 2 ^ System.Platform.numBits := hbound
        simp [UScalar.tryMk, UScalar.tryMkOpt, hb, Result.ofOption, i']
      have hp' : ∀ j, j < i'.val → a.val[j]! = b.val[j]! := by
        intro j hj
        by_cases hj' : j < i.val
        · exact hp j hj'
        · have : j = i.val := by omega
          simpa [this] using heq
      obtain ⟨j, hj, hfin⟩ := ih i' (by omega) hp' (by omega)
      refine ⟨j, ?_, hfin⟩
      rw [loop.eq_1]
      simp only [verify.same_bytes_loop.body, bls.COMPRESSED_LEN]
      simp only [UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true,
        same_bytes_index a i hlt, same_bytes_index b i hlt, bind_tc_ok,
        heq, hadd]
      exact hj
    · refine ⟨i, ?_, ?_⟩
      · rw [loop.eq_1]
        simp only [verify.same_bytes_loop.body, bls.COMPRESSED_LEN, bind_tc_ok,
          UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true,
          same_bytes_index a i hlt, same_bytes_index b i hlt, heq, if_false]
      · have hi48 : i ≠ 48#usize := by
          intro h
          have := congrArg UScalar.val h
          simp only [UScalar.ofNatCore_val_eq] at this
          omega
        have hab : a.val ≠ b.val := by
          intro h
          exact heq (congrArg (fun xs : List U8 => xs[i.val]!) h)
        simp [hi48, hab]

theorem same_bytes_refinement (a b : Aeneas.Std.Array U8 48#usize) :
    verify.same_bytes a b = ok (arrayBytes a == arrayBytes b) := by
  obtain ⟨j, hj, hfin⟩ := same_bytes_loop_eq a b 0#usize (by decide)
    (by intro j hj; simp at hj)
  unfold verify.same_bytes verify.same_bytes_loop
  rw [hj]
  simp only [bind_tc_ok, bls.COMPRESSED_LEN]
  rw [arrayBytes, arrayBytes, bytes_beq_eq]
  congr 1
  apply Bool.eq_iff_iff.mpr
  simpa only [decide_eq_true_eq] using hfin

end LeanBlsSimd.Kzg
