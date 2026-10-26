import LeanBlsSimd.PairingProduct.FieldRep
import LeanBlsSimd.PairingProduct.LaneStepMeaning
import LeanBlsSimd.LaneTower.LineCoordinates
import LeanBlsSimd.Refines.Loop

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd.bls

namespace LeanBlsSimd.PairingProduct.Lanes

open Pairing

noncomputable section

def firstIndices (l : Fin 8) : Array I64 8#usize :=
  let i := G1x8.toI64 (Int64.ofNat l.val)
  let j := G1x8.toI64 (Int64.ofNat (8 + l.val))
  Array.make 8#usize [i, j, i, i, i, i, i, i] (by rfl)

def secondIndices (l : Fin 8) : Array I64 8#usize :=
  let j := G1x8.toI64 (Int64.ofNat (8 + l.val))
  Array.make 8#usize [0#i64, 1#i64, j, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64] (by rfl)

def indices (is : Array I64 8#usize) : Vector Int64 8 :=
  ofArray (fun i => Int64.ofBitVec i.bv) is

def pack (lines : Lines) (l : Fin 8) : Fp2x8 :=
  (lines.l0.permute2 lines.l1 (indices (firstIndices l))).permute2
    lines.l2 (indices (secondIndices l))

private theorem pack_lane (a b c : Fp8) (l j : Fin 8) :
    ((a.permute2 b (indices (firstIndices l))).permute2 c
      (indices (secondIndices l))).lane j =
        if j = 1 then b.lane l else if j = 2 then c.lane l else a.lane l := by
  simp only [Fp8.lane_permute2]
  fin_cases l <;> fin_cases j <;> rfl

def packedValues (a b c : Fp2Field) : LaneTower.P LaneTower.F :=
  (![a.re, b.re, c.re, a.re, a.re, a.re, a.re, a.re],
   ![a.im, b.im, c.im, a.im, a.im, a.im, a.im, a.im])

theorem pack_strict {lines : Lines} {l : Fin 8} {a b c : Fp2Field}
    (ha : lines.l0.Holds l a) (hb : lines.l1.Holds l b) (hc : lines.l2.Holds l c) :
    LaneTower.Strict2 256 (toFp2x8 (pack lines l)) (packedValues a b c) := by
  constructor <;> intro j
  · simp only [toFp2x8, ofFp8_toFp8]
    fin_cases j
    all_goals
      simp only [packedValues]
      apply Fp8.CappedRep.boundRep (k := 2) ?_ (by decide)
      first
      | apply ha.re.capped.of_lane_eq; simp [pack, Fp2x8.permute2, pack_lane]
      | apply hb.re.capped.of_lane_eq; simp [pack, Fp2x8.permute2, pack_lane]
      | apply hc.re.capped.of_lane_eq; simp [pack, Fp2x8.permute2, pack_lane]
  · simp only [toFp2x8, ofFp8_toFp8]
    fin_cases j
    all_goals
      simp only [packedValues]
      apply Fp8.CappedRep.boundRep (k := 2) ?_ (by decide)
      first
      | apply ha.im.capped.of_lane_eq; simp [pack, Fp2x8.permute2, pack_lane]
      | apply hb.im.capped.of_lane_eq; simp [pack, Fp2x8.permute2, pack_lane]
      | apply hc.im.capped.of_lane_eq; simp [pack, Fp2x8.permute2, pack_lane]

def lineValue (coefficients : Fin 3 → Fp2Field) : Fp12Field :=
  fp2Embed (coefficients 0) + fp2Embed (coefficients 1) * Fp12Field.w ^ 2 +
    fp2Embed (coefficients 2) * Fp12Field.w ^ 3

theorem packed_value (a b c : Fp2Field) :
    Fp12.toField (LaneTower.value (LaneTower.sparseLine (packedValues a b c))) =
      lineValue ![a, b, c] := by
  have h : LaneTower.value (LaneTower.sparseLine (packedValues a b c)) =
      Portable.Fp12.line (Fp2.toField.symm a) (Fp2.toField.symm b) (Fp2.toField.symm c) := by
    apply LaneTower.fp12_ext <;> apply LaneTower.fp6_ext <;> apply LaneTower.fp2_ext <;> rfl
  rw [h, Pairing.line_field]
  simp only [RingEquiv.apply_symm_apply, lineValue, Matrix.cons_val_zero,
    Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons]

def multiplyPair (lines : lane_pairs.Lines) (value : fp12.Fp12) (l : Fin 8) :
    Result fp12.Fp12 := do
  let first ← fp2x8.Fp2x8.permute2 lines.l0 lines.l1 (firstIndices l)
  let packed ← fp2x8.Fp2x8.permute2 first lines.l2 (secondIndices l)
  fp12.Fp12.mul_by_line value packed

theorem multiplyPair_refines {lines : Lines} {l : Fin 8} {coefficients : Fin 3 → Fp2Field}
    {value : fp12.Fp12} {v : Fp12Field}
    (h0 : lines.l0.Holds l (coefficients 0))
    (h1 : lines.l1.Holds l (coefficients 1))
    (h2 : lines.l2.Holds l (coefficients 2)) (hv : FieldRep value v) :
    ∃ out, multiplyPair (toLines lines) value l = ok out ∧
      FieldRep out (v * lineValue coefficients) := by
  obtain ⟨out, hout, hrep⟩ := LaneTower.mul_by_line_refines hv (pack_strict h0 h1 h2)
  refine ⟨out, ?_, ?_⟩
  · simpa only [multiplyPair, toLines, Fp2x8.permute2_refines, bind_tc_ok,
      ofFp2x8_toFp2x8, indices, pack] using hout
  · have he : (Fp12.toField.symm v).mul
        (LaneTower.value (LaneTower.sparseLine (packedValues
          (coefficients 0) (coefficients 1) (coefficients 2)))) =
          Fp12.toField.symm (v * lineValue coefficients) := by
      apply Fp12.toField.injective
      rw [Fp12.toField_mul, packed_value]
      simp only [RingEquiv.apply_symm_apply, lineValue,
        Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two,
        Matrix.head_cons, Matrix.tail_cons]
    unfold FieldRep
    rwa [he] at hrep

private theorem index_add (n : Nat) (hn : n < 8) :
    8#i64 + G1x8.toI64 (Int64.ofNat n) =
      ok (G1x8.toI64 (Int64.ofNat (8 + n))) := by
  interval_cases n <;> rfl

private theorem body_cont (lines : lane_pairs.Lines)
    (r r' : core.ops.range.Range Usize) (value : fp12.Fp12)
    (hl : r.start.val < 8)
    (hn : core.iter.range.IteratorRange.next core.iter.range.StepUsize r =
      ok (some r.start, r')) :
    lane_pairs.Lines.multiply_into_loop.body lines r value =
      (do let out ← multiplyPair lines value ⟨r.start.val, hl⟩
          ok (cont (r', out))) := by
  simp only [lane_pairs.Lines.multiply_into_loop.body, hn, bind_tc_ok]
  change (do
    let i1 ← 8#i64 + UScalar.hcast .I64 r.start
    let fx ← fp2x8.Fp2x8.permute2 lines.l0 lines.l1
      (Array.make 8#usize [UScalar.hcast .I64 r.start, i1,
        UScalar.hcast .I64 r.start, UScalar.hcast .I64 r.start,
        UScalar.hcast .I64 r.start, UScalar.hcast .I64 r.start,
        UScalar.hcast .I64 r.start, UScalar.hcast .I64 r.start] (by rfl))
    let packed ← fp2x8.Fp2x8.permute2 fx lines.l2
      (Array.make 8#usize [0#i64, 1#i64, i1, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64] (by rfl))
    let out ← fp12.Fp12.mul_by_line value packed
    ok (cont (r', out))) = _
  simp only [bind_tc_ok, G1x8.hcast_usize_i64, index_add r.start.val hl,
    multiplyPair, firstIndices, secondIndices, bind_assoc_eq]

theorem multiply_loop_refines (lines : Lines) (count : Usize)
    (coefficients : List (Fin 3 → Fp2Field))
    (hc : count.val = coefficients.length) (hhi : coefficients.length ≤ 8)
    (holds : ∀ (l : Fin 8) (hl : l.val < coefficients.length),
      lines.l0.Holds l (coefficients[l.val] 0) ∧
      lines.l1.Holds l (coefficients[l.val] 1) ∧
      lines.l2.Holds l (coefficients[l.val] 2))
    (start : Usize) (hs : start.val ≤ coefficients.length)
    {value : fp12.Fp12} {v : Fp12Field} (hv : FieldRep value v) :
    ∃ out, lane_pairs.Lines.multiply_into_loop
        { start, «end» := count } (toLines lines) value = ok out ∧
      FieldRep out (v * ((coefficients.drop start.val).map lineValue).prod) := by
  unfold lane_pairs.Lines.multiply_into_loop
  induction hd : coefficients.length - start.val generalizing start value v with
  | zero =>
    have he : start.val = coefficients.length := by omega
    have hn := next_ge { start, «end» := count } (by simp [hc, he])
    refine ⟨value, ?_, ?_⟩
    · rw [loop.eq_1]
      simp only [lane_pairs.Lines.multiply_into_loop.body, hn, bind_tc_ok]
      rfl
    · simpa only [he, List.drop_length, List.map_nil, List.prod_nil, mul_one] using hv
  | succ n ih =>
    have hlt : start.val < coefficients.length := by omega
    obtain ⟨r', hrs, hre, hn⟩ := next_lt
      ({ start, «end» := count } : core.ops.range.Range Usize) (by simpa only [hc])
    dsimp only at hrs hre hn
    let l : Fin 8 := ⟨start.val, by omega⟩
    have hh := holds l hlt
    obtain ⟨value', hvalue', hv'⟩ := multiplyPair_refines hh.1 hh.2.1 hh.2.2 hv
    have hb := body_cont (toLines lines) { start, «end» := count } r' value l.isLt hn
    have hb' : lane_pairs.Lines.multiply_into_loop.body (toLines lines)
        { start, «end» := count } value = ok (cont (r', value')) := by
      change _ = (do let out ← multiplyPair (toLines lines) value l
                     ok (cont (r', out))) at hb
      simpa only [hvalue', bind_tc_ok] using hb
    have hr : r' = { start := r'.start, «end» := count } := by
      cases r'
      simp_all
    obtain ⟨out, hout, houtrep⟩ := ih r'.start (by omega) hv' (by omega)
    refine ⟨out, ?_, ?_⟩
    · rw [loop.eq_1]
      dsimp only
      rw [hb']
      change loop (fun (iter, value) =>
        lane_pairs.Lines.multiply_into_loop.body (toLines lines) iter value)
        (r', value') = ok out
      rw [hr]
      exact hout
    · rw [List.drop_eq_getElem_cons hlt]
      simp only [List.map_cons, List.prod_cons, ← mul_assoc]
      simpa only [hrs] using houtrep

theorem multiply_into_refines (lines : Lines) (count : Usize)
    (coefficients : List (Fin 3 → Fp2Field))
    (hc : count.val = coefficients.length) (hhi : coefficients.length ≤ 8)
    (holds : ∀ (l : Fin 8) (hl : l.val < coefficients.length),
      lines.l0.Holds l (coefficients[l.val] 0) ∧
      lines.l1.Holds l (coefficients[l.val] 1) ∧
      lines.l2.Holds l (coefficients[l.val] 2))
    {value : fp12.Fp12} {v : Fp12Field} (hv : FieldRep value v) :
    ∃ out, lane_pairs.Lines.multiply_into (toLines lines) value count = ok out ∧
      FieldRep out (v * (coefficients.map lineValue).prod) := by
  simpa only [lane_pairs.Lines.multiply_into, UScalar.ofNatCore_val_eq, List.drop_zero] using
    multiply_loop_refines lines count coefficients hc hhi holds 0#usize (by simp) hv

end

end LeanBlsSimd.PairingProduct.Lanes
