import LeanBlsSimd.Msm8.Glv

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Msm8

abbrev ScalarWords := Array U64 4#usize

def SplitInv (n : ℕ) (first second : Fin n → msm8.glv.Half)
    (halves : alloc.vec.Vec ScalarWords) (fs ss : alloc.vec.Vec Bool) (i : ℕ) : Prop :=
  halves.val.length = 2 * n ∧ fs.val.length = i ∧ ss.val.length = i ∧
    ∀ j : Fin n, j.val < i →
      halves.val[j.val]? = some (first j).magnitude ∧
      halves.val[n + j.val]? = some (second j).magnitude ∧
      fs.val[j.val]? = some (first j).negative ∧
      ss.val[j.val]? = some (second j).negative

private theorem scalar_vec_index {α : Type} (v : alloc.vec.Vec α) (i : Usize)
    (hi : i.val < v.val.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i =
      ok v.val[i.val] := by
  simp [alloc.vec.Vec.index, Slice.index_usize, hi]

private theorem scalar_vec_index_mut {α : Type} (v : alloc.vec.Vec α) (i : Usize)
    (hi : i.val < v.val.length) :
    alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice α) v i =
      ok (v.val[i.val], fun x => (⟨v.val.set i.val x, by simpa using v.property⟩ : alloc.vec.Vec α)) := by
  simp [alloc.vec.Vec.index_mut, Slice.index_mut_usize, Slice.index_usize, hi]
  rfl

theorem split_scalar_step (scalars halves : alloc.vec.Vec ScalarWords)
    (fs ss : alloc.vec.Vec Bool) (n i : Usize)
    (first second : Fin n.val → msm8.glv.Half)
    (hn : scalars.val.length = n.val) (hi : i.val < n.val)
    (hcap : 2 * n.val < 2 ^ UScalarTy.Usize.numBits)
    (hinv : SplitInv n.val first second halves fs ss i.val)
    (hd : msm8.glv.decompose (scalars.val[i.val]'(by omega)) =
      ok (first ⟨i.val, hi⟩, second ⟨i.val, hi⟩)) :
    ∃ h' fs' ss' next,
      next.val = i.val + 1 ∧
      msm8.Msm8.split_scalars_loop.body scalars n halves fs ss i =
        ok (cont (h', fs', ss', next)) ∧
      SplitInv n.val first second h' fs' ss' next.val := by
  obtain ⟨hh, hf, hs, hprefix⟩ := hinv
  let f := first ⟨i.val, hi⟩
  let s := second ⟨i.val, hi⟩
  let mid : alloc.vec.Vec ScalarWords :=
    ⟨halves.val.set i.val f.magnitude, by simpa using halves.property⟩
  let out : alloc.vec.Vec ScalarWords :=
    ⟨mid.val.set (n.val + i.val) s.magnitude, by simpa using mid.property⟩
  let at2 : Usize := UScalar.ofNatCore (n.val + i.val) (by omega)
  let next : Usize := UScalar.ofNatCore (i.val + 1) (by omega)
  have hat : n + i = ok at2 := by
    rw [add_ok _ _ (by omega)]
  have hnext : i + 1#usize = ok next := by
    rw [add_ok _ _ (by change i.val + 1 < _; omega)]
    rfl
  have hfs : fs.val.length < Usize.max := by
    rw [hf]
    have hb := halves.property
    rw [hh] at hb
    omega
  have hss : ss.val.length < Usize.max := by
    rw [hs]
    have hb := halves.property
    rw [hh] at hb
    omega
  obtain ⟨fs', hfs', hfsval⟩ := WP.spec_imp_exists (alloc.vec.Vec.push_spec fs f.negative hfs)
  obtain ⟨ss', hss', hssval⟩ := WP.spec_imp_exists (alloc.vec.Vec.push_spec ss s.negative hss)
  refine ⟨out, fs', ss', next, rfl, ?_, ?_⟩
  · simp only [msm8.Msm8.split_scalars_loop.body, UScalar.lt_equiv, hi, if_true,
      scalar_vec_index scalars i (by omega), hd, bind_tc_ok,
      scalar_vec_index_mut halves i (by omega)]
    change (do
      let at2 ← n + i
      let (_, back) ← alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice ScalarWords) mid at2
      let fs' ← alloc.vec.Vec.push fs f.negative
      let ss' ← alloc.vec.Vec.push ss s.negative
      let next ← i + 1#usize
      ok (cont (back s.magnitude, fs', ss', next))) = _
    rw [hat]
    simp only [bind_tc_ok, scalar_vec_index_mut mid at2 (by simp [mid, at2, hh]; omega),
      hfs', hss', hnext]
    rfl
  · refine ⟨by simp [out, mid, hh], ?_, ?_, ?_⟩
    · simp [hfsval, hf, next]
    · simp [hssval, hs, next]
    · intro j hj
      have hjle : j.val ≤ i.val := by simpa only [next, UScalar.ofNatCore_val_eq, Nat.lt_succ_iff] using hj
      by_cases hji : j.val = i.val
      · have hej : j = ⟨i.val, hi⟩ := Fin.ext hji
        subst j
        have hne : n.val + i.val ≠ i.val := by omega
        simp only [out, mid, List.getElem?_set, List.length_set, hh,
          hne, if_false, if_true, hfsval, hssval, List.getElem?_append, hf, hs]
        simp [f, s, show i.val < 2 * n.val by omega,
          show n.val + i.val < 2 * n.val by omega]
      · have hjlt : j.val < i.val := by omega
        obtain ⟨h1, h2, h3, h4⟩ := hprefix j hjlt
        have ha : j.val ≠ n.val + i.val := by omega
        have hb : n.val + j.val ≠ i.val := by have := j.isLt; omega
        have hc : n.val + j.val ≠ n.val + i.val := by omega
        simp only [out, mid, List.getElem?_set, Ne.symm hji, Ne.symm ha,
          Ne.symm hb, Ne.symm hc, if_false, h1, h2, hfsval, hssval,
          List.getElem?_append, hf, hs, if_pos hjlt, h3, h4, and_self]


theorem split_scalar_loop (scalars halves : alloc.vec.Vec ScalarWords)
    (fs ss : alloc.vec.Vec Bool) (n i : Usize)
    (first second : Fin n.val → msm8.glv.Half)
    (hn : scalars.val.length = n.val) (hi : i.val ≤ n.val)
    (hcap : 2 * n.val < 2 ^ UScalarTy.Usize.numBits)
    (hinv : SplitInv n.val first second halves fs ss i.val)
    (hd : ∀ j : Fin n.val, msm8.glv.decompose (scalars.val[j.val]'(by omega)) =
      ok (first j, second j)) :
    ∃ h' fs' ss', msm8.Msm8.split_scalars_loop scalars halves fs ss n i =
        ok (h', fs', ss') ∧ SplitInv n.val first second h' fs' ss' n.val := by
  unfold msm8.Msm8.split_scalars_loop
  induction count_eq : n.val - i.val generalizing i halves fs ss with
  | zero =>
    have heq : i.val = n.val := by omega
    refine ⟨halves, fs, ss, ?_, ?_⟩
    · rw [loop.eq_1]
      simp [msm8.Msm8.split_scalars_loop.body, UScalar.lt_equiv, heq]
    · simpa only [heq] using hinv
  | succ count ih =>
    have hlt : i.val < n.val := by omega
    obtain ⟨halves', fs', ss', next, hnxt, hstep, hinv'⟩ :=
      split_scalar_step scalars halves fs ss n i first second hn hlt hcap hinv
        (hd ⟨i.val, hlt⟩)
    obtain ⟨out, fsout, ssout, hloop, hfull⟩ :=
      ih halves' fs' ss' next (by omega) hinv' hd (by omega)
    refine ⟨out, fsout, ssout, ?_, hfull⟩
    rw [loop.eq_1]
    dsimp only
    rw [hstep]
    exact hloop

private theorem clone_scalar_words (words : ScalarWords) :
    (core.clone.CloneArray 4#usize core.clone.CloneU64).clone words = ok words := by
  obtain ⟨out, hout, heq⟩ := WP.spec_imp_exists
    (core.array.CloneArray.clone_spec core.clone.CloneU64 words (by intro x hx; rfl))
  simpa only [← heq] using hout

theorem split_scalars_exact (self : msm8.Msm8)
    (first second : Fin self.finite_scalars.val.length → msm8.glv.Half)
    (hcap : 2 * self.finite_scalars.val.length < 2 ^ UScalarTy.Usize.numBits)
    (hd : ∀ j : Fin self.finite_scalars.val.length,
      msm8.glv.decompose self.finite_scalars.val[j.val] = ok (first j, second j)) :
    ∃ halves fs ss, msm8.Msm8.split_scalars self =
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
  simp only [msm8.Msm8.split_scalars, alloc.vec.Vec.clear, bind_tc_ok]
  change (do
    let count ← 2#usize * n
    let initial ← alloc.vec.Vec.resize (core.clone.CloneArray 4#usize core.clone.CloneU64) empty count zero
    let (halves, fs, ss) ← msm8.Msm8.split_scalars_loop self.finite_scalars initial signs signs n 0#usize
    ok { self with halves := halves, first_signs := fs, second_signs := ss }) = _
  rw [hcount]
  simp only [bind_tc_ok, hinit, hloop]

theorem split_scalars_refines (self : msm8.Msm8)
    (hcap : 2 * self.finite_scalars.val.length < 2 ^ UScalarTy.Usize.numBits)
    (hk : ∀ j : Fin self.finite_scalars.val.length,
      GlvRefines.value self.finite_scalars.val[j.val] < 2 ^ 255) :
    ∃ (first second : Fin self.finite_scalars.val.length → msm8.glv.Half), ∃ halves fs ss,
      msm8.Msm8.split_scalars self =
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

end LeanBlsSimd.Msm8
