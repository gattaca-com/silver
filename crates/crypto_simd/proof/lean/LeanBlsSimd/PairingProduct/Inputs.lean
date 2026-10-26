import LeanBlsSimd.PairingProduct.LaneStepMeaning
import LeanBlsSimd.Kzg.LanePairingInputs
import LeanBlsSimd.Refines.Loop

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.PairingProduct.Lanes

set_option maxRecDepth 8000
set_option maxHeartbeats 2000000

private abbrev Words := Fin 6 → Array (Array U64 6#usize) 8#usize

private def coordinate (p : pairing_product.AffinePair) : Fin 6 → blst.blst_fp :=
  ![p.p.x, p.p.y, p.q.x.fp.val[0], p.q.x.fp.val[1], p.q.y.fp.val[0], p.q.y.fp.val[1]]

private def encodeWords (w : Words) : Array (Array (Array U64 6#usize) 8#usize) 6#usize :=
  ⟨[w 0, w 1, w 2, w 3, w 4, w 5], rfl⟩

private def writeWords (w : Words) (i : Usize) (p : pairing_product.AffinePair) : Words :=
  fun c => (w c).set i (coordinate p c).l

private theorem write_body (pairs : Slice pairing_product.AffinePair)
    (r r' : core.ops.range.Range Usize) (w : Words)
    (hi : r.start.val < pairs.val.length) (h8 : r.start.val < 8)
    (hn : core.iter.range.IteratorRange.next core.iter.range.StepUsize r =
      ok (some r.start, r')) :
    lane_pairs.LanePairs.new_loop.body pairs r (encodeWords w) =
      ok (cont (r', encodeWords (writeWords w r.start pairs.val[r.start.val]))) := by
  simp [lane_pairs.LanePairs.new_loop.body, hn, Slice.index_usize, hi,
    encodeWords, coordinate, writeWords, Array.index_mut_usize,
    Array.index_usize, Array.update, h8]
  rfl

private def Filled (pairs : Slice pairing_product.AffinePair) (n : Nat) (w : Words) : Prop :=
  ∀ (c : Fin 6) (l : Fin 8) (hl : l.val < n) (hp : l.val < pairs.val.length),
    (w c).val[l.val] = (coordinate pairs.val[l.val] c).l

private theorem write_filled (pairs : Slice pairing_product.AffinePair) (w : Words)
    (i : Usize) (hi : i.val < pairs.val.length) (hw : Filled pairs i.val w) :
    Filled pairs (i.val + 1) (writeWords w i pairs.val[i.val]) := by
  intro c l hl hp
  by_cases he : l.val = i.val
  · simp [writeWords, he]
  · simpa [writeWords, Array.set, List.getElem_set, he, Ne.symm he] using
      hw c l (by omega) hp

private theorem fill_loop (pairs : Slice pairing_product.AffinePair)
    (h8 : pairs.val.length ≤ 8) (r : core.ops.range.Range Usize)
    (he : r.end.val = pairs.val.length) (hi : r.start.val ≤ pairs.val.length)
    (w : Words) (hw : Filled pairs r.start.val w) :
    ∃ out : Words, lane_pairs.LanePairs.new_loop r pairs (encodeWords w) =
      ok (encodeWords out) ∧ Filled pairs pairs.val.length out := by
  induction hd : pairs.val.length - r.start.val generalizing r w with
  | zero =>
    have hs : r.start.val = pairs.val.length := by omega
    refine ⟨w, ?_, hs ▸ hw⟩
    unfold lane_pairs.LanePairs.new_loop
    rw [loop.eq_1]
    simp [lane_pairs.LanePairs.new_loop.body, next_ge r (by omega)]
  | succ d ih =>
    have hs : r.start.val < pairs.val.length := by omega
    obtain ⟨r', hr's, hr'e, hn⟩ := next_lt r (by omega)
    obtain ⟨out, ho, hf⟩ := ih r' (by simpa [hr'e] using he) (by omega)
      (writeWords w r.start pairs.val[r.start.val])
      (hr's ▸ write_filled pairs w r.start hs hw) (by omega)
    refine ⟨out, ?_, hf⟩
    unfold lane_pairs.LanePairs.new_loop at ho ⊢
    rw [loop.eq_1]
    simp only [write_body pairs r r' w hs (by omega) hn]
    exact ho

private theorem packed_holds (values : Array (Array U64 6#usize) 8#usize)
    (l : Fin 8) (raw : blst.blst_fp) (he : values.val[l.val] = raw.l)
    (hr : Kzg.FpReduced raw) : (Kzg.packedFromBlst values).Holds l (Kzg.fpRead raw) := by
  apply Fp8.from_blst_holds (ofArray (m := 8) (ofArray (m := 6) ofU64) values) l
  simpa only [Fin.getElem_fin, getElem_ofArray, he] using
    Kzg.fpRead_montgomery_value raw hr

private theorem coordinate_reduced (p : pairing_product.AffinePair)
    (hp : Kzg.G1AffineValid p.p) (hq : Kzg.G2AffineValid p.q) (c : Fin 6) :
    Kzg.FpReduced (coordinate p c) := by
  have he : p = ⟨Kzg.g1Affine (Kzg.g1ReadAffine p.p),
      Kzg.g2Affine (Kzg.g2ReadAffine p.q)⟩ := by
    cases p
    exact congrArg₂ pairing_product.AffinePair.mk hp.1 hq.1
  rw [he]
  fin_cases c <;> exact Kzg.fpEncode_reduced _

private def initialState (w : Words) (n : Usize) : State :=
  let f := fun c => Kzg.packedFromBlst (w c)
  let qx : Fp2x8 := ⟨f 2, f 3⟩
  let qy : Fp2x8 := ⟨f 4, f 5⟩
  ⟨⟨qx, qy, Fp2x8.one⟩, qx, qy, ((f 0).add (f 0)).neg,
    (f 1).add (f 1), n, 0⟩

private theorem initial_holds (pairs : Slice pairing_product.AffinePair) (w : Words)
    (hw : Filled pairs pairs.val.length w)
    (valid : ∀ p ∈ pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (l : Fin 8) (hl : l.val < pairs.val.length) :
    (initialState w (Slice.len pairs)).Holds l
      ![Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.x),
        Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.y), 1]
      (Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.x),
        Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.y))
      (Kzg.fpRead pairs.val[l.val].p.x) (Kzg.fpRead pairs.val[l.val].p.y) := by
  have hv := valid pairs.val[l.val] (List.getElem_mem hl)
  have hc (c : Fin 6) := packed_holds (w c) l (coordinate pairs.val[l.val] c)
    (hw c l hl hl) (coordinate_reduced _ hv.1 hv.2 c)
  have hx : (Fp2x8.mk (Kzg.packedFromBlst (w 2)) (Kzg.packedFromBlst (w 3))).Holds l
      (Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.x)) := ⟨hc 2, hc 3⟩
  have hy : (Fp2x8.mk (Kzg.packedFromBlst (w 4)) (Kzg.packedFromBlst (w 5))).Holds l
      (Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.y)) := ⟨hc 4, hc 5⟩
  exact ⟨⟨hx, hy, Fp2x8.holds_one l⟩, hx, hy, ((hc 0).add (hc 0)).neg,
    (hc 1).add (hc 1)⟩

theorem new_holds (pairs : Slice pairing_product.AffinePair)
    (hlo : 1 ≤ pairs.val.length) (hhi : pairs.val.length ≤ 8)
    (valid : ∀ p ∈ pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q) :
    ∃ s, lane_pairs.LanePairs.new pairs = ok s ∧ s.count.val = pairs.val.length ∧
      s.degenerate = 0#u8 ∧ ∀ (l : Fin 8) (hl : l.val < pairs.val.length),
        (ofState s).Holds l
          ![Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.x),
            Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.y), 1]
          (Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.x),
            Fp2.toField (Kzg.fp2Read pairs.val[l.val].q.y))
          (Kzg.fpRead pairs.val[l.val].p.x) (Kzg.fpRead pairs.val[l.val].p.y) := by
  let zero : Words := fun _ => Array.repeat 8#usize (Array.repeat 6#usize 0#u64)
  obtain ⟨w, hw, hf⟩ := fill_loop pairs hhi
    ⟨0#usize, Slice.len pairs⟩ (by simp) (by simp) zero (by intro c l hl; simp at hl)
  refine ⟨toState (initialState w (Slice.len pairs)), ?_, rfl, rfl, ?_⟩
  · unfold lane_pairs.LanePairs.new
    have hz : encodeWords zero = Array.repeat 6#usize
        (Array.repeat 8#usize (Array.repeat 6#usize 0#u64)) := rfl
    rw [hz] at hw
    simp only [core.slice.Slice.is_empty, Slice.len_val, Slice.length, UScalar.le_equiv,
      limbs.LANES, UScalar.ofNatCore_val_eq]
    simp [show pairs.val.length ≠ 0 by omega, hhi, hw, encodeWords,
      Array.index_usize, Kzg.from_blst_limbs_refinement, Fp2x8.one_refines,
      Fp8.add_refines, Fp8.neg_refines, initialState, toState, toG2x8, toFp2x8]
    rfl
  · intro l hl
    simpa only [ofState_toState] using initial_holds pairs w hf valid l hl

end LeanBlsSimd.PairingProduct.Lanes
