import LeanBlsSimd.PairingProduct.Combined
import LeanBlsSimd.PairingProduct.LaneStepMeaning
import LeanBlsSimd.Pairing.MillerSchedule
import LeanBlsSimd.PairingProduct.FieldRep
import LeanBlsSimd.PairingProduct.LinePacking

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.PairingProduct.LaneMiller

noncomputable section

set_option maxRecDepth 8000

def EntryHolds (s : Lanes.State) (l : Fin 8) (x : Miller.Input × Miller.State) : Prop :=
  ∃ xp yp : Fp, x.1.xp = Lanes.scalar xp ∧ x.1.yp = Lanes.scalar yp ∧
    s.Holds l x.2.point x.1.q xp yp ∧ s.degenerate.toNat.testBit l = x.2.flagged

structure Holds (s : Lanes.State) (xs : Miller.Entries) : Prop where
  lower : 1 ≤ s.count.val
  upper : s.count.val ≤ 8
  count : xs.length = s.count.val
  lanes : ∀ (l : Fin 8) (h : l.val < xs.length), EntryHolds s l xs[l.val]

def operation (s : Lanes.State) (add : Bool) : Lanes.Lines × Lanes.State :=
  if add then Lanes.add s else Lanes.double s

theorem operation_count (s : Lanes.State) (add : Bool) :
    (operation s add).2.count = s.count := by cases add <;> rfl

theorem operation_entry {s : Lanes.State} {l : Fin 8} {x : Miller.Input × Miller.State}
    (h : EntryHolds s l x) (hhi : s.count.val ≤ 8) (hl : l.val < s.count.val) (add : Bool) :
    EntryHolds (operation s add).2 l (x.1, x.2.step x.1 add) ∧
      ∃ xp yp : Fp, x.1.xp = Lanes.scalar xp ∧ x.1.yp = Lanes.scalar yp ∧
        (operation s add).1.Holds l (x.2.output x.1 add).line xp yp := by
  obtain ⟨xp, yp, hx, hy, hp, hf⟩ := h
  cases add with
  | false =>
    obtain ⟨ht, hn, hz⟩ := Lanes.double_holds hp hhi
    simp only [hl, decide_true, Bool.and_true, hf] at hz
    exact ⟨⟨xp, yp, hx, hy, ht, hz⟩, ⟨xp, yp, hx, hy, hn⟩⟩
  | true =>
    obtain ⟨ht, hn, hz⟩ := Lanes.add_holds hp hhi
    simp only [hl, decide_true, Bool.and_true, hf] at hz
    exact ⟨⟨xp, yp, hx, hy, ht, hz⟩, ⟨xp, yp, hx, hy, hn⟩⟩

theorem operation_holds {s : Lanes.State} {xs : Miller.Entries}
    (h : Holds s xs) (add : Bool) : Holds (operation s add).2 (Miller.advance xs add) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · simpa only [operation_count] using h.lower
  · simpa only [operation_count] using h.upper
  · simpa only [Miller.advance, List.length_map, operation_count] using h.count
  · intro l hl
    have hl' : l.val < xs.length := by simpa only [Miller.advance, List.length_map] using hl
    have hcount := h.count
    simpa only [Miller.advance, List.getElem_map] using
      (operation_entry (h.lanes l hl') h.upper (by omega) add).1

theorem clear {s : Lanes.State} {xs : Miller.Entries} (h : Holds s xs)
    (hc : s.degenerate = 0) : Miller.flags xs = false := by
  simp only [Miller.flags, List.any_eq_false, Bool.not_eq_true]
  intro x hx
  obtain ⟨n, hn, he⟩ := List.getElem_of_mem hx
  have hcount := h.count
  have hhi := h.upper
  have hn8 : n < 8 := by omega
  obtain ⟨xp, yp, _, _, _, hf⟩ := h.lanes ⟨n, hn8⟩ hn
  rw [hc] at hf
  simpa [he] using hf.symm

theorem scalar_neg_two (x : Fp) : Lanes.scalar (-(x + x)) = -2 * Lanes.scalar x := by
  rw [neg_mul, two_mul]
  ext <;> first | rfl | simp [Lanes.scalar]

theorem scalar_two (x : Fp) : Lanes.scalar (x + x) = 2 * Lanes.scalar x := by
  rw [two_mul]
  ext <;> rfl

def coefficients (xs : Miller.Entries) (add : Bool) (n : Nat) : Fin 3 → Fp2Field :=
  if h : n < xs.length then
    let x := xs[n]
    let o := x.2.output x.1 add
    ![o.line 0, o.line 1 * (-2 * x.1.xp), o.line 2 * (2 * x.1.yp)]
  else fun _ => 0

theorem operation_lines {s : Lanes.State} {xs : Miller.Entries}
    (h : Holds s xs) (add : Bool) (l : Fin 8) (hl : l.val < s.count.val) :
    (operation s add).1.l0.Holds l (coefficients xs add l.val 0) ∧
      (operation s add).1.l1.Holds l (coefficients xs add l.val 1) ∧
      (operation s add).1.l2.Holds l (coefficients xs add l.val 2) := by
  have hcount := h.count
  have hlen : l.val < xs.length := by omega
  obtain ⟨xp, yp, hx, hy, hn⟩ := (operation_entry (h.lanes l hlen) h.upper hl add).2
  simp only [coefficients, dif_pos hlen, Matrix.cons_val_zero, Matrix.cons_val_one,
    Matrix.cons_val_two, hx, hy]
  exact ⟨hn.l0, by simpa only [scalar_neg_two] using hn.l1,
    by simpa only [scalar_two] using hn.l2⟩

theorem coefficients_product (xs : Miller.Entries) (add : Bool) :
    ((List.range xs.length).map fun n =>
      Pairing.fp2Embed (coefficients xs add n 0) +
        Pairing.fp2Embed (coefficients xs add n 1) * Fp12Field.w ^ 2 +
        Pairing.fp2Embed (coefficients xs add n 2) * Fp12Field.w ^ 3).prod =
      Miller.lineProduct xs add := by
  apply congrArg List.prod
  apply List.ext_getElem
  · simp
  · intro n hn hm
    have hlen : n < xs.length := by simpa using hn
    simp only [List.getElem_map, List.getElem_range, coefficients, dif_pos hlen,
      Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two]
    rfl

theorem multiply_operation (s : Lanes.State) (xs : Miller.Entries) (h : Holds s xs)
    (add : Bool) (raw : fp12.Fp12) (v : Fp12Field) (hv : FieldRep raw v) :
    ∃ out, lane_pairs.Lines.multiply_into (Lanes.toLines (operation s add).1) raw s.count =
      ok out ∧ FieldRep out (v * Miller.lineProduct xs add) := by
  let cs := (List.range xs.length).map (coefficients xs add)
  have hc : s.count.val = cs.length := by simp only [cs, List.length_map, List.length_range]; exact h.count.symm
  have hhi : cs.length ≤ 8 := by rw [← hc]; exact h.upper
  have hh : ∀ (l : Fin 8) (hl : l.val < cs.length),
      (operation s add).1.l0.Holds l (cs[l.val] 0) ∧
      (operation s add).1.l1.Holds l (cs[l.val] 1) ∧
      (operation s add).1.l2.Holds l (cs[l.val] 2) := by
    intro l hl
    have hlt : l.val < s.count.val := by omega
    simpa only [cs, List.getElem_map, List.getElem_range] using operation_lines h add l hlt
  obtain ⟨out, hout, hr⟩ := Lanes.multiply_into_refines (operation s add).1 s.count cs hc hhi hh hv
  refine ⟨out, hout, ?_⟩
  simpa only [cs, List.map_map, Function.comp_def, Lanes.lineValue, coefficients_product] using hr

section Loop

variable (hpack : ∀ (s : Lanes.State) (xs : Miller.Entries), Holds s xs →
  ∀ (add : Bool) (raw : fp12.Fp12) (v : Fp12Field), FieldRep raw v →
    ∃ out, lane_pairs.Lines.multiply_into (Lanes.toLines (operation s add).1) raw s.count =
      ok out ∧ FieldRep out (v * Miller.lineProduct xs add))

include hpack

theorem miller_body (s : Lanes.State) (xs : Miller.Entries) (h : Holds s xs)
    (n : Fin 63) (raw : fp12.Fp12) (f : Fp12Field) (hf : FieldRep raw f)
    (bit : U32) (hb : bit.val = n.val + 1) (hfirst : n.val + 1 = 63 → f = 1) :
    ∃ s' out bit', lane_pairs.LanePairs.miller_loop_loop.body 63#u32 (Lanes.toState s)
        raw bit = ok (cont (Lanes.toState s', out, bit')) ∧
      bit'.val = n.val ∧ Holds s' (Miller.sharedBitStep (xs, f) n.val).1 ∧
      FieldRep out (Miller.sharedBitStep (xs, f) n.val).2 ∧ s'.count = s.count := by
  let bit' : U32 := UScalar.ofNatCore n.val (by change n.val < 2^32; have := n.isLt; omega)
  have hdec : bit - 1#u32 = ok bit' := by
    rw [sub_ok bit 1#u32 (by simp; omega)]
    apply congrArg ok
    apply UScalar.eq_of_val_eq
    simp only [UScalar.ofNatCore_val_eq]
    change bit.val - 1 = n.val
    omega
  have hstart : 63#u32 - 1#u32 = ok 62#u32 := by rw [sub_ok _ _ (by decide)]; rfl
  obtain ⟨square, hsquare, rsquare⟩ : ∃ square,
      (if bit' < 62#u32 then fp12.Fp12.square raw else ok raw) = ok square ∧
        FieldRep square (f * f) := by
    by_cases hpos : bit' < 62#u32
    · obtain ⟨out, hout, hr⟩ := FieldRep.square hf
      exact ⟨out, by rw [if_pos hpos]; exact hout, hr⟩
    · refine ⟨raw, by rw [if_neg hpos], ?_⟩
      have hn : n.val + 1 = 63 := by
        simp only [UScalar.lt_equiv] at hpos
        change ¬n.val < 62 at hpos
        have := n.isLt
        omega
      simpa only [hfirst hn, one_mul] using hf
  have hd := Lanes.double_refines (Lanes.toState s) h.lower h.upper
  simp only [Lanes.ofState_toState, Prod.map] at hd
  obtain ⟨first, hlines, rfirst⟩ := hpack s xs h false square (f * f) rsquare
  change lane_pairs.Lines.multiply_into (Lanes.toLines (Lanes.double s).1) square s.count =
    ok first at hlines
  have hdouble := operation_holds h false
  have hbit : constants.is_lower_z_bit bit' = ok (blsX.testBit n.val) := by
    rw [G1x8.is_lower_z_bit_refines]
    exact congrArg ok (Pairing.lower_bit_agrees n)
  have hrun : bit > 0#u32 := by simp only [UScalar.lt_equiv]; change 0 < bit.val; omega
  have hdcount : (Lanes.double s).2.count = s.count := rfl
  by_cases hbitset : blsX.testBit n.val = true
  · have ha := Lanes.add_refines (Lanes.toState (Lanes.double s).2)
      hdouble.lower hdouble.upper
    simp only [Lanes.ofState_toState, Prod.map] at ha
    obtain ⟨out, hlines2, rout⟩ := hpack (operation s false).2 (Miller.advance xs false)
      hdouble true first ((f * f) * Miller.lineProduct xs false) rfirst
    change lane_pairs.Lines.multiply_into (Lanes.toLines (Lanes.add (Lanes.double s).2).1)
      first (Lanes.double s).2.count = ok out at hlines2
    refine ⟨(Lanes.add (Lanes.double s).2).2, out, bit', ?_, rfl, ?_, ?_, rfl⟩
    · simp only [lane_pairs.LanePairs.miller_loop_loop.body, hrun, if_true, hdec,
        hstart, bind_tc_ok, hsquare, hd, hbit, hbitset]
      change (do
        let value2 ← lane_pairs.Lines.multiply_into (Lanes.toLines (Lanes.double s).1) square s.count
        let (l1, self2) ← lane_pairs.LanePairs.add (Lanes.toState (Lanes.double s).2)
        let value3 ← lane_pairs.Lines.multiply_into l1 value2 self2.count
        ok (cont (self2, value3, bit'))) = _
      rw [hlines]
      simp only [bind_tc_ok, ha]
      change (do let value3 ← lane_pairs.Lines.multiply_into
                    (Lanes.toLines (Lanes.add (Lanes.double s).2).1) first (Lanes.double s).2.count
                 ok (cont (Lanes.toState (Lanes.add (Lanes.double s).2).2, value3, bit'))) = _
      rw [hlines2]
      simp only [bind_tc_ok]
    · simpa only [Miller.sharedBitStep, hbitset, if_true, Miller.sharedStep] using
        operation_holds hdouble true
    · simpa only [Miller.sharedBitStep, hbitset, if_true, Miller.sharedStep] using rout
  · refine ⟨(Lanes.double s).2, first, bit', ?_, rfl, ?_, ?_, rfl⟩
    · simp only [lane_pairs.LanePairs.miller_loop_loop.body, hrun, if_true, hdec,
        hstart, bind_tc_ok, hsquare, hd, hbit, hbitset,
        Bool.false_eq_true, if_false]
      change (do let value2 ← lane_pairs.Lines.multiply_into
                    (Lanes.toLines (Lanes.double s).1) square s.count
                 ok (cont (Lanes.toState (Lanes.double s).2, value2, bit'))) = _
      rw [hlines]
      simp only [bind_tc_ok]
    · simpa only [Miller.sharedBitStep, hbitset, if_false, Miller.sharedStep] using hdouble
    · simpa only [Miller.sharedBitStep, hbitset, if_false, Miller.sharedStep] using rfirst

theorem miller_loop_refines (n : Nat) (hn : n ≤ 63)
    (s : Lanes.State) (xs : Miller.Entries) (h : Holds s xs)
    (raw : fp12.Fp12) (f : Fp12Field) (hf : FieldRep raw f)
    (bit : U32) (hb : bit.val = n) (hfirst : n = 63 → f = 1) :
    ∃ s' out, lane_pairs.LanePairs.miller_loop_loop 63#u32 (Lanes.toState s) raw bit =
        ok (Lanes.toState s', out) ∧
      Holds s' (Miller.sharedRun xs f (Pairing.lineKinds n)).1 ∧
      FieldRep out (Miller.sharedRun xs f (Pairing.lineKinds n)).2 ∧ s'.count = s.count := by
  induction n generalizing s xs raw f bit with
  | zero =>
    refine ⟨s, raw, ?_, h, hf, rfl⟩
    rw [lane_pairs.LanePairs.miller_loop_loop, loop.eq_1]
    simp only [lane_pairs.LanePairs.miller_loop_loop.body, UScalar.lt_equiv, hb,
      Nat.not_lt_zero, if_false]
  | succ n ih =>
    obtain ⟨s', raw', bit', hbody, hb', hs', hr', hcount⟩ :=
      miller_body hpack s xs h ⟨n, by omega⟩ raw f hf bit hb hfirst
    obtain ⟨s'', out, hloop, hs'', hr'', hcount'⟩ := ih (by omega) s'
      (Miller.sharedBitStep (xs, f) n).1 hs' raw'
      (Miller.sharedBitStep (xs, f) n).2 hr' bit' hb' (by intro he; omega)
    refine ⟨s'', out, ?_, ?_, ?_, hcount'.trans hcount⟩
    · rw [lane_pairs.LanePairs.miller_loop_loop, loop.eq_1]
      dsimp only
      rw [hbody]
      exact hloop
    · rw [Miller.sharedRun_bits]
      exact hs''
    · rw [Miller.sharedRun_bits]
      exact hr''

theorem miller_refines_with_packing (raw : lane_pairs.LanePairs) (inputs : List Miller.Input)
    (h : Holds (Lanes.ofState raw) (Miller.initialEntries inputs)) :
    ∃ out, lane_pairs.LanePairs.miller_loop raw = ok out ∧
      FieldRep out.value (Miller.sharedFactor inputs) ∧
      (out.degenerate = 0#u8 → Miller.flags (Miller.sharedMiller inputs).1 = false) := by
  obtain ⟨one, hone, rone⟩ := FieldRep.one
  obtain ⟨s', value, hloop, hs', hv, _⟩ := miller_loop_refines hpack 63 (by omega)
    (Lanes.ofState raw) (Miller.initialEntries inputs) h one 1 rone 63#u32 rfl (fun _ => rfl)
  rw [Lanes.toState_ofState] at hloop
  obtain ⟨out, hout, rout⟩ := FieldRep.conjugate hv
  have hbit : Array.index_usize constants.Z_BITS 0#usize = ok 63#u32 := by
    rw [Z_BITS_index 0#usize (by decide)]
    rfl
  refine ⟨⟨out, toU8 s'.degenerate⟩, ?_, rout, ?_⟩
  · simp only [lane_pairs.LanePairs.miller_loop, hone, hbit, bind_tc_ok, hloop]
    change (do let f ← fp12.Fp12.conjugate value
               ok (lane_pairs.MillerProduct.mk f (toU8 s'.degenerate))) = _
    rw [hout]
    simp only [bind_tc_ok]
  · intro hz
    apply clear hs'
    exact congrArg ofU8 hz

end Loop

theorem miller_refines (raw : lane_pairs.LanePairs) (inputs : List Miller.Input)
    (h : Holds (Lanes.ofState raw) (Miller.initialEntries inputs)) :
    ∃ out, lane_pairs.LanePairs.miller_loop raw = ok out ∧
      FieldRep out.value (Miller.sharedFactor inputs) ∧
      (out.degenerate = 0#u8 → Miller.flags (Miller.sharedMiller inputs).1 = false) :=
  miller_refines_with_packing multiply_operation raw inputs h

end

end LeanBlsSimd.PairingProduct.LaneMiller
