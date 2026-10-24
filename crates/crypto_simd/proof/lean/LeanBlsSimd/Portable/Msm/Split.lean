import LeanBlsSimd.Msm8.SplitGroup

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Split
open LeanBlsSimd.Msm8 silver_crypto_simd.bls

theorem split_loop_eq (scalars halves : alloc.vec.Vec ScalarWords)
    (fs ss : alloc.vec.Vec Bool) (n i : Usize) :
    portable.msm.Msm.split_scalars_loop scalars halves fs ss n i =
      bls.msm8.Msm8.split_scalars_loop scalars halves fs ss n i := rfl

private theorem clone_scalar_words (words : ScalarWords) :
    (core.clone.CloneArray 4#usize core.clone.CloneU64).clone words = ok words := by
  obtain ⟨out, hout, heq⟩ := WP.spec_imp_exists
    (core.array.CloneArray.clone_spec core.clone.CloneU64 words (by intro x hx; rfl))
  simpa only [← heq] using hout

theorem split_scalars_exact (self : portable.msm.Msm)
    (first second : Fin self.finite_scalars.val.length → glv.Half)
    (hcap : 2 * self.finite_scalars.val.length < 2 ^ UScalarTy.Usize.numBits)
    (hd : ∀ j : Fin self.finite_scalars.val.length,
      glv.decompose self.finite_scalars.val[j.val] = ok (first j, second j)) :
    ∃ halves fs ss, portable.msm.Msm.split_scalars self =
        ok { self with halves := halves, first_signs := fs, second_signs := ss } ∧
      SplitInv self.finite_scalars.val.length first second halves fs ss
        self.finite_scalars.val.length := by
  let n := alloc.vec.Vec.len self.finite_scalars
  let count : Usize := UScalar.ofNatCore (2 * n.val) hcap
  let empty : alloc.vec.Vec ScalarWords := ⟨[], by simp⟩
  let signs : alloc.vec.Vec Bool := ⟨[], by simp⟩
  let zero : ScalarWords := Array.repeat 4#usize 0#u64
  obtain ⟨initial, hinit, hinitial⟩ := WP.spec_imp_exists (alloc.vec.Vec.resize_spec
    (core.clone.CloneArray 4#usize core.clone.CloneU64) empty count zero (clone_scalar_words zero))
  have hlength : initial.val.length = 2 * n.val := by
    rw [hinitial]
    simp [count]
  have hinv : SplitInv n.val first second initial signs signs 0 :=
    ⟨hlength, rfl, rfl, by intro j hj; omega⟩
  obtain ⟨halves, fs, ss, hloop, hout⟩ :=
    split_scalar_loop self.finite_scalars initial signs signs n 0#usize first second
      rfl (Nat.zero_le _) hcap hinv hd
  refine ⟨halves, fs, ss, ?_, hout⟩
  have hcount : 2#usize * n = ok count := by
    rw [mul_ok (2#usize) n hcap]
    rfl
  simp only [portable.msm.Msm.split_scalars, alloc.vec.Vec.clear, bind_tc_ok]
  change (do
    let count ← 2#usize * n
    let initial ← alloc.vec.Vec.resize (core.clone.CloneArray 4#usize core.clone.CloneU64) empty count zero
    let (halves, fs, ss) ← portable.msm.Msm.split_scalars_loop self.finite_scalars initial signs signs n 0#usize
    ok { self with halves := halves, first_signs := fs, second_signs := ss }) = _
  rw [hcount]
  simp only [bind_tc_ok, hinit, split_loop_eq, hloop]

theorem split_scalars_refines (self : portable.msm.Msm)
    (hcap : 2 * self.finite_scalars.val.length < 2 ^ UScalarTy.Usize.numBits)
    (hk : ∀ j : Fin self.finite_scalars.val.length,
      GlvRefines.value self.finite_scalars.val[j.val] < 2 ^ 255) :
    ∃ (first second : Fin self.finite_scalars.val.length → glv.Half), ∃ halves fs ss,
      portable.msm.Msm.split_scalars self =
        ok { self with halves := halves, first_signs := fs, second_signs := ss } ∧
      SplitInv self.finite_scalars.val.length first second halves fs ss
        self.finite_scalars.val.length ∧
      ∀ j, GlvRefines.signedValue (first j) =
          Glv.first (GlvRefines.value self.finite_scalars.val[j.val]) ∧
        GlvRefines.signedValue (second j) =
          Glv.second (GlvRefines.value self.finite_scalars.val[j.val]) ∧
        GlvRefines.value (first j).magnitude < 2 ^ 127 ∧
        GlvRefines.value (second j).magnitude < 2 ^ 127 := by
  have h := fun j : Fin self.finite_scalars.val.length =>
    GlvRefines.decompose_refines self.finite_scalars.val[j.val] (hk j)
  choose first second hd hfirst hsecond hfirst_bound hsecond_bound using h
  obtain ⟨halves, fs, ss, hexact, hinv⟩ := split_scalars_exact self first second hcap hd
  exact ⟨first, second, halves, fs, ss, hexact, hinv,
    fun j => ⟨hfirst j, hsecond j, hfirst_bound j, hsecond_bound j⟩⟩


end LeanBlsSimd.Portable.Msm.Split
