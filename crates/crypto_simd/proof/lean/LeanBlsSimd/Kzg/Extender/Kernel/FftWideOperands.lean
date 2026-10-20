import LeanBlsSimd.Kzg.Extender.Kernel.FftWidePipeline
import LeanBlsSimd.Kzg.Extender.Kernel.FftWidePair

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.WideStage

structure Valid (s : WideStage) : Prop where
  input_length : s.input.val.length = s.table.vectors.val
  size_le : s.table.vectors.val ≤ 512
  half_pow : ∃ stage : Nat, s.half.val = 2 ^ stage
  half_lt : s.half.val < s.table.vectors.val
  divides : 2 * s.half.val ∣ s.table.vectors.val
  wide_length : 2 * s.half.val - 1 ≤ s.table.wide.val.length

theorem Valid.half_pos {s : WideStage} (h : s.Valid) : 0 < s.half.val := by
  obtain ⟨stage, hs⟩ := h.half_pow
  rw [hs]
  exact Nat.two_pow_pos stage

theorem add_eq (a b c : Usize) (hc : c.val = a.val + b.val) : a + b = ok c := by
  obtain ⟨out, hout, hv⟩ := WP.spec_imp_exists
    (Usize.add_spec (x := a) (y := b) (by scalar_tac))
  have heq : out = c := UScalar.eq_of_val_eq (hv.trans hc.symm)
  simpa only [heq] using hout

theorem Valid.indices {s : WideStage} (h : s.Valid) (n : Nat)
    (hn : n < s.table.vectors.val / 2) :
    ∃ first second : Usize,
      first.val = pairFirst s.half.val n ∧
      second.val = pairFirst s.half.val n + s.half.val ∧
      first + s.half = ok second := by
  have hb := pairFirst_add_half_lt s.half.val n s.table.vectors.val h.half_pos h.divides hn
  let first : Usize := UScalar.ofNatCore (pairFirst s.half.val n)
    (lt_trans (by omega : pairFirst s.half.val n < s.table.vectors.val) s.table.vectors.hmax)
  let second : Usize := UScalar.ofNatCore (pairFirst s.half.val n + s.half.val)
    (lt_trans hb s.table.vectors.hmax)
  refine ⟨first, second, rfl, rfl, add_eq first s.half second ?_⟩
  rfl

def prepare (s : WideStage) (data : Slice fr8.Fr8) (n : Usize) :
    Result ((fr8.Fr8 × fr8.Fr8) × Slice fr8.Fr8) :=
  if s.dit then do
    let p ← fft8.Fft8.dit_wide_operands s.table data s.half n
    ok (p, data)
  else fft8.Fft8.dif_wide_operands s.table data s.half n s.offset

def finish (s : WideStage) (data : Slice fr8.Fr8) (first : Usize) (p : fr8.Fr8) :
    Result (Slice fr8.Fr8) :=
  if s.dit then fft8.dit_finish data first s.half p s.offset
  else do
    let second ← first + s.half
    Slice.update data second p

private theorem table_address (s : WideStage) (h : s.Valid) (n : Usize) :
    ∃ mask wi : Usize,
      s.half - 1#usize = ok mask ∧
      mask + (n &&& mask) = ok wi ∧
      alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        s.table.wide wi = ok (s.factor n.val) := by
  obtain ⟨mask, hm, hmv, _⟩ := WP.spec_imp_exists
    (Usize.sub_spec (x := s.half) (y := 1#usize)
      (by simp only [UScalar.ofNatCore_val_eq]; exact h.half_pos))
  simp only [UScalar.ofNatCore_val_eq] at hmv
  obtain ⟨stage, hs⟩ := h.half_pow
  have hand := twiddle_mask_val n mask s.half.val stage hs hmv
  have hr := Nat.mod_lt n.val h.half_pos
  have hwbound : mask.val + (n &&& mask).val < s.table.wide.val.length := by
    rw [hmv, hand]
    have := h.wide_length
    have := h.half_pos
    omega
  obtain ⟨wi, hw, hwv⟩ := WP.spec_imp_exists
    (Usize.add_spec (x := mask) (y := n &&& mask)
      (by have := s.table.wide.property; omega))
  refine ⟨mask, wi, hm, hw, ?_⟩
  have hwi : wi.val < s.table.wide.val.length := by omega
  have hread : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
      s.table.wide wi = ok s.table.wide.val[wi.val]! := by
    simp [alloc.vec.Vec.index_usize, List.getElem?_eq_getElem hwi]
  rw [hread, hwv, hmv, hand]
  rfl

theorem prepare_refines (s : WideStage) (h : s.Valid) (data : Slice fr8.Fr8)
    (n first : Usize) (hn : n.val < s.table.vectors.val / 2)
    (hlen : data.val.length = s.input.val.length)
    (hfirst : first.val = pairFirst s.half.val n.val)
    (hx : data.val[first.val]! = s.x n.val)
    (hy : data.val[first.val + s.half.val]! = s.y n.val) :
    s.prepare data n = ok ((s.normal n.val, s.factor n.val),
      if s.dit then data else data.set first (s.left n.val)) := by
  obtain ⟨stage, hs⟩ := h.half_pow
  obtain ⟨actual, hactual, hactualv⟩ := first_of_pair_refinement n s.half stage hs
    (by have := h.size_le; omega)
  have heq : actual = first := UScalar.eq_of_val_eq (hactualv.trans hfirst.symm)
  subst actual
  obtain ⟨_, second, hf, hsecond, hadd⟩ := h.indices n.val hn
  have hadd' : first + s.half = ok second := add_eq first s.half second (by omega)
  have hb := pairFirst_add_half_lt s.half.val n.val s.table.vectors.val h.half_pos h.divides hn
  have hfb : first.val < data.val.length := by rw [hlen, h.input_length]; omega
  have hsb : second.val < data.val.length := by rw [hlen, h.input_length]; omega
  have hreadx : Slice.index_usize data first = ok (s.x n.val) := by
    rw [slice_read data first hfb, hx]
  have hready : Slice.index_usize data second = ok (s.y n.val) := by
    rw [slice_read data second hsb, show second.val = first.val + s.half.val by omega, hy]
  obtain ⟨mask, wi, hm, hw, hreadw⟩ := table_address s h n
  change alloc.vec.Vec.index_usize s.table.wide wi = ok (s.factor n.val) at hreadw
  have hupdate (v : fr8.Fr8) := slice_update data first v hfb
  cases hd : s.dit <;>
    simp [prepare, fft8.Fft8.dit_wide_operands, fft8.Fft8.dif_wide_operands,
      hactual, hadd', hreadx, hready, hm, hw, hreadw, hupdate, lift,
      fr8.Fr8.add, FrModel.Fr8.add_raw_refines, FrModel.Fr8.sub_raw_refines,
      FrModel.Fr8.normalise_refines, FrModel.Fr8.reduced_refines,
      FrModel.ofFr8_toFr8, normal, left, hd]

theorem finish_refines (s : WideStage) (h : s.Valid) (data : Slice fr8.Fr8)
    (n : Nat) (first second : Usize) (hn : n < s.table.vectors.val / 2)
    (hlen : data.val.length = s.input.val.length)
    (hfirst : first.val = pairFirst s.half.val n)
    (hsecond : second.val = pairFirst s.half.val n + s.half.val)
    (hx : s.dit = true → data.val[first.val]! = s.x n) :
    s.finish data first (s.product n) = ok
      (if s.dit then (data.set first (s.left n)).set second (s.right n)
       else data.set second (s.right n)) := by
  have hb := pairFirst_add_half_lt s.half.val n s.table.vectors.val h.half_pos h.divides hn
  have hfb : first.val < data.val.length := by rw [hlen, h.input_length]; omega
  have hsb : second.val < data.val.length := by rw [hlen, h.input_length]; omega
  have hadd := add_eq first s.half second (by omega)
  have hu (v : fr8.Fr8) := slice_update data first v hfb
  have hus (v : fr8.Fr8) := slice_update data second v hsb
  have hu' (a b : fr8.Fr8) : Slice.update (data.set first a) second b =
      ok ((data.set first a).set second b) :=
    slice_update _ _ _ (by simpa [Slice.set, Slice.setAtNat] using hsb)
  cases hd : s.dit
  · simp [finish, hd, right, hadd, hus]
  · have hr : Slice.index_usize data first = ok (s.x n) := by
      rw [slice_read data first hfb, hx hd]
    simp [finish, fft8.dit_finish, hr, FrModel.Fr8.add_raw_refines,
      FrModel.Fr8.sub_raw_refines, hu, hu', hadd, left, right, hd]

theorem pair_refines (s : WideStage) (n : Nat) :
    widePairRun s.dit s.offset (s.x n) (s.y n) (s.factor n) =
      ok (s.left n, s.right n) := by
  have hmul (a b : fr8.Fr8) : fr8.Fr8.mul a b =
      ok (FrModel.Fr8.reduceValue (FrModel.Fr8.productValue a b)) := by
    rw [FrModel.Fr8.mul_eq_reduce_product, FrModel.Fr8.product_refines]
    simp only [bind_tc_ok, FrModel.Fr8.reduce_refines]
  cases hd : s.dit <;>
    simp [widePairRun, fr8.Fr8.add, FrModel.Fr8.add_raw_refines,
      FrModel.Fr8.sub_raw_refines, FrModel.Fr8.normalise_refines,
      FrModel.Fr8.reduced_refines, FrModel.ofFr8_toFr8, hmul,
      left, right, product, pending, normal, hd]

end LeanBlsSimd.Kzg.Extender.Kernel.WideStage
