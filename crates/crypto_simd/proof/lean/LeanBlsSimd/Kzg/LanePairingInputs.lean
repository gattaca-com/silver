import LeanBlsSimd.Kzg.PairingContract
import LeanBlsSimd.Kzg.G1Arithmetic
import LeanBlsSimd.Msm8.Conversion
import LeanBlsSimd.Msm8.Complete

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg


set_option maxRecDepth 8000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 512

theorem val64_eq_limbs (a : Array U64 6#usize) :
    val64 (ofArray ofU64 a) = limbs a.val := by
  have he : a.val = [a.val[0], a.val[1], a.val[2], a.val[3], a.val[4], a.val[5]] := by
    apply List.ext_getElem
    · simp
    · intro i hi hj
      have hlt : i < 6 := by simpa using hi
      interval_cases i <;> rfl
  rw [val64_eq]
  simp only [getElem_ofArray, toNat_ofU64]
  conv_rhs => rw [he]
  simp only [limbs, List.foldr_cons, List.foldr_nil]
  ring

open scoped EthLib.Cryptography.Bls.Fp in
private theorem fpRead_cancel_radix (a : blst.blst_fp) :
    fpRead a * Fp.ofNat (2^384) = Fp.ofNat (limbs a.l.val) := by
  have hc : (Fp.ofNat (2^384) : Fp) ≠ 0 := by decide +kernel
  unfold fpRead
  rw [Fp.inverse_eq_inv]
  exact (mul_assoc _ _ _).trans ((congrArg (fun x : Fp => Fp.ofNat (limbs a.l.val) * x)
    (inv_mul_cancel₀ hc)).trans (mul_one _))

-- Typed binders avoid deep kernel reduction across the Fp and ZMod power instances.
private def zmodMulValue (x y : ZMod Fp.modulus) : Nat := (x * y).val
private def fpMontgomeryValue (x : ZMod Fp.modulus) : Nat := zmodMulValue x (2^384)

private theorem fpMulValue_eq (x y : Fp) : (x * y).val = zmodMulValue x y := by rfl

private theorem fpRadix_cast : (2^384 : ZMod Fp.modulus) = Fp.ofNat (2^384) := by
  have hnat (n : Nat) : (n : ZMod Fp.modulus) = Fp.ofNat n := by rfl
  rw [← hnat]
  exact (Nat.cast_pow (α := ZMod Fp.modulus) 2 384).symm

private theorem fpMontgomeryValue_eq (x : Fp) :
    (x * Fp.ofNat (2^384)).val = fpMontgomeryValue x :=
  (fpMulValue_eq x (Fp.ofNat (2^384))).trans
    (congrArg (zmodMulValue x) fpRadix_cast.symm)

theorem fpRead_montgomery_value (a : blst.blst_fp) (ha : FpReduced a) :
    val64 (ofArray ofU64 a.l) = fpMontgomeryValue (fpRead a) := by
  rw [val64_eq_limbs]
  calc
    limbs a.l.val = (Fp.ofNat (limbs a.l.val)).val := by
      simp only [Fp.ofNat, Fin.val_ofNat, Nat.mod_eq_of_lt ha]
    _ = (fpRead a * Fp.ofNat (2^384)).val :=
      (congrArg (fun x : Fp => x.val) (fpRead_cancel_radix a)).symm
    _ = fpMontgomeryValue (fpRead a) := fpMontgomeryValue_eq (fpRead a)

def packedFromBlst (values : Array (Array U64 6#usize) 8#usize) : Fp8 :=
  (Fp8.load ((ofArray (m := 8) (ofArray (m := 6) ofU64) values).map unpack52)).mul
    (Fp8.splat_limbs (.ofList TWO_POW_448_MOD_P))

private theorem from_blst_loop (values : Array (Array U64 6#usize) 8#usize)
    (v : Vector Limbs 8) (i : Usize) (hi : i.val ≤ 8)
    (hv : ∀ j : Fin 8, j.val < i.val →
      v[j] = unpack52 (ofArray ofU64 values.val[j.val])) :
    fp8.Fp8.from_blst_limbs_loop values (toArray (toArray toU64) v) i =
      ok (toArray (toArray toU64)
        ((ofArray (m := 8) (ofArray (m := 6) ofU64) values).map unpack52)) := by
  unfold fp8.Fp8.from_blst_limbs_loop
  induction hn : 8 - i.val generalizing i v with
  | zero =>
    have hi8 : i.val = 8 := by omega
    rw [loop.eq_1]
    simp only [fp8.Fp8.from_blst_limbs_loop.body, limbs.LANES, UScalar.lt_equiv,
      UScalar.ofNatCore_val_eq, hi8, Nat.lt_irrefl, ↓reduceIte]
    apply congrArg ok
    apply congrArg (toArray (toArray toU64))
    apply Vector.ext
    intro j hj
    simpa only [Vector.getElem_map, getElem_ofArray, Fin.getElem_fin] using hv ⟨j,hj⟩ (by omega)
  | succ n ih =>
    have hlt : i.val < 8 := by omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by scalar_tac)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    let value := unpack52 (ofArray ofU64 (values.val[i.val]'(by simpa using hlt)))
    let v' := v.set i.val value
    have hb : fp8.Fp8.from_blst_limbs_loop.body values (toArray (toArray toU64) v) i =
        ok (cont (toArray (toArray toU64) v', i')) := by
      simp only [fp8.Fp8.from_blst_limbs_loop.body, limbs.LANES, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, hlt, ↓reduceIte,
        index_usize_eq values i hlt, bind_tc_ok, unpack52_refines,
        update_eq (n := 8#usize) _ i _ hlt]
      rw [add_ok _ _ (by scalar_tac)]
      simp only [bind_tc_ok]
      congr 2
      apply Prod.ext
      · exact set_toArray (toArray toU64) v rfl i value hlt
      · rfl
    rw [loop.eq_1]
    simp only [hb]
    apply ih v' i' (by omega) ?_ (by omega)
    intro j hj
    by_cases hji : j.val = i.val
    · simp [v', value, hji]
    · simpa [v', Vector.getElem_set, hji, Ne.symm hji] using hv j (by omega)

theorem from_blst_limbs_refinement (values : Array (Array U64 6#usize) 8#usize) :
    fp8.Fp8.from_blst_limbs values = ok (toFp8 (packedFromBlst values)) := by
  unfold fp8.Fp8.from_blst_limbs
  dsimp only
  have hl : fp8.Fp8.from_blst_limbs_loop values
      (Array.repeat 8#usize (Array.repeat 8#usize 0#u64)) 0#usize =
      ok (toArray (toArray toU64)
        ((ofArray (m := 8) (ofArray (m := 6) ofU64) values).map unpack52)) :=
    from_blst_loop values (Vector.replicate 8 (Vector.replicate 8 0))
      0#usize (by decide) (by simp)
  rw [hl]
  simp only [bind_tc_ok, Fp8.load_refines, Fp8.splat_limbs_refines, Fp8.mul_refines,
    ofFp8_toFp8, ofArray_toArray_ofArray_ofU64]
  change ok (toFp8 ((Fp8.load ((ofArray (m := 8) (ofArray (m := 6) ofU64) values).map unpack52)).mul
    (Fp8.splat_limbs (ofArray ofU64 constants.TWO_POW_448_MOD_P)))) = _
  have hc : ofArray ofU64 constants.TWO_POW_448_MOD_P = Limbs.ofList TWO_POW_448_MOD_P := by
    unfold constants.TWO_POW_448_MOD_P TWO_POW_448_MOD_P
    rfl
  rw [hc]
  rfl

private theorem add_complete_holds {a b : G1x8} {l : Fin 8} {P Q : G1}
    (ha : a.Holds l P) (hb : b.Holds l Q) (hP : G1Valid P) (hQ : G1Valid Q) :
    (a.add_complete b).Holds l (G1.add P Q) := by
  by_cases hz : P.isInfinity = true
  · have hpz : (P.z : ZMod Fp.modulus) = 0 := G1.isZero_iff.mp hz
    have hm : (a.add b).2.toNat.testBit l = true := by
      simp only [G1x8.add_mask a b l P Q ha hb, hpz, decide_true,
        Bool.or_true, Bool.true_or]
    have hn : (a.add b).2 ≠ 0 := by
      intro he
      have := Mmask8.testBit_of_eq_zero he l
      simp only [hm, Bool.true_eq_false] at this
    rw [G1x8.add_complete, if_neg hn, g1_add_of_infinity_left hz]
    apply G1x8.select_true_holds _ _ _ _ _ ?_ hb
    simpa only [(G1x8.Holds.z ha).testBit_is_zero_mask, decide_eq_true_eq] using hpz
  · by_cases hqz : Q.isInfinity = true
    · have hqz' : (Q.z : ZMod Fp.modulus) = 0 := G1.isZero_iff.mp hqz
      have hpz : (P.z : ZMod Fp.modulus) ≠ 0 := G1.isZero_iff.not.mp hz
      have hm : (a.add b).2.toNat.testBit l = true := by
        simp only [G1x8.add_mask a b l P Q ha hb, hqz', decide_true, Bool.or_true]
      have hn : (a.add b).2 ≠ 0 := by
        intro he
        have := Mmask8.testBit_of_eq_zero he l
        simp only [hm, Bool.true_eq_false] at this
      rw [G1x8.add_complete, if_neg hn, g1_add_of_infinity_right hz hqz]
      apply G1x8.select_false_holds
      · simpa only [(G1x8.Holds.z ha).testBit_is_zero_mask, decide_eq_false_iff_not] using hpz
      · apply G1x8.select_true_holds _ _ _ _ _ ?_ ha
        simpa only [(G1x8.Holds.z hb).testBit_is_zero_mask, decide_eq_true_eq] using hqz'
    · exact G1x8.add_complete_correct a b l P Q ha hb
        (g1_groupValid_of_noninfinity hP hz) (g1_groupValid_of_noninfinity hQ hqz)

theorem LaneG1Rep.add_complete {a b : g1x8.G1x8} {l : Fin 8} {P Q : G1}
    (ha : LaneG1Rep a l P) (hb : LaneG1Rep b l Q)
    (hP : G1Valid P) (hQ : G1Valid Q) :
    LaneG1Rep (toG1x8 ((ofG1x8 a).add_complete (ofG1x8 b))) l (G1.add P Q) := by
  obtain ⟨p, hp, hpi, hpa⟩ := ha
  obtain ⟨q, hq, hqi, hqa⟩ := hb
  have hpv := g1Valid_transport hpi hpa hP
  have hqv := g1Valid_transport hqi hqa hQ
  have hm := g1_add_matches hpv hqv hP hQ hpi hpa hqi hqa
  refine ⟨G1.add p q, ?_, hm⟩
  simpa only [ofG1x8_toG1x8] using (add_complete_holds hp hq hpv hqv)

private def negLanePoint (a : g1x8.G1x8) : g1x8.G1x8 :=
  { a with y := toFp8 (ofFp8 a.y).neg }

private theorem negLanePoint_refines (a : g1x8.G1x8) :
    g1x8.G1x8.neg a = ok (negLanePoint a) := by
  simp only [g1x8.G1x8.neg, Fp8.neg_refines, bind_tc_ok, negLanePoint]

private theorem LaneG1Rep.neg {a : g1x8.G1x8} {l : Fin 8} {P : G1}
    (ha : LaneG1Rep a l P) (hP : G1Valid P) :
    LaneG1Rep (negLanePoint a) l (G1.neg P) := by
  obtain ⟨p, hp, hpi, hpa⟩ := ha
  have hm := g1_neg_matches (g1Valid_transport hpi hpa hP) hP hpi hpa
  refine ⟨G1.neg p, ?_, hm⟩
  rcases hp with ⟨hx,hy,hz⟩
  exact ⟨hx, by simpa only [negLanePoint, ofG1x8, ofFp8_toFp8, G1.neg] using hy.neg, hz⟩

private theorem packedFromBlst_holds_value (values : Array (Array U64 6#usize) 8#usize)
    (l : Fin 8) (a : ZMod Fp.modulus)
    (hh : val64 (ofArray (m := 6) ofU64 values.val[l.val]) = fpMontgomeryValue a) :
    (packedFromBlst values).Holds l a := by
  let ws : Vector (Vector UInt64 6) 8 := ofArray (m := 8) (ofArray (m := 6) ofU64) values
  have he : ws[l] = ofArray ofU64 values.val[l.val] := by
    simp only [ws, Fin.getElem_fin, getElem_ofArray]
  apply Fp8.from_blst_holds ws l a
  rw [he]
  exact hh

private theorem packedFromBlst_radix (values : Array (Array U64 6#usize) 8#usize)
    (l : Fin 8) (hr : FpReduced ⟨values.val[l.val]⟩) :
    val64 (ofArray (m := 6) ofU64 values.val[l.val]) =
      fpMontgomeryValue (fpRead ⟨values.val[l.val]⟩) :=
  fpRead_montgomery_value ⟨values.val[l.val]⟩ hr

private theorem packedFromBlst_holds_raw (values : Array (Array U64 6#usize) 8#usize)
    (l : Fin 8) (raw : blst.blst_fp) (he : values.val[l.val] = raw.l)
    (hr : FpReduced raw) : (packedFromBlst values).Holds l (fpRead raw) := by
  apply packedFromBlst_holds_value values l (fpRead raw)
  rw [he]
  exact fpRead_montgomery_value raw hr

private theorem packedFromBlst_holds (values : Array (Array U64 6#usize) 8#usize)
    (l : Fin 8) (hr : FpReduced ⟨values.val[l.val]⟩) :
    (packedFromBlst values).Holds l (fpRead ⟨values.val[l.val]⟩) :=
  packedFromBlst_holds_raw values l ⟨values.val[l.val]⟩ rfl hr

private def pairWords (a b : Array U64 6#usize) : Array (Array U64 6#usize) 8#usize :=
  let z := Array.repeat 6#usize 0#u64
  ⟨[a,b,z,z,z,z,z,z],by rfl⟩

private def twoLanePoint (a b : blst.blst_p1) : g1x8.G1x8 :=
  ⟨toFp8 (packedFromBlst (pairWords a.x.l b.x.l)),
   toFp8 (packedFromBlst (pairWords a.y.l b.y.l)),
   toFp8 (packedFromBlst (pairWords a.z.l b.z.l))⟩

private theorem two_lanes_eq (a b : blst.blst_p1) :
    verify.two_lanes a b = ok (twoLanePoint a b) := by
  unfold verify.two_lanes
  dsimp only
  simp only [update_eq (n := 8#usize) _ 0#usize _ (by decide),
    update_eq (n := 8#usize) _ 1#usize _ (by decide), bind_tc_ok,
    from_blst_limbs_refinement]
  rfl

private theorem pairWords_read (a b : Array U64 6#usize) (l : Fin 8) :
    (pairWords a b).val[l.val] =
      if l.val = 0 then a else if l.val = 1 then b else Array.repeat 6#usize 0#u64 := by
  fin_cases l <;> rfl

private theorem pairWords_reduced (a b : blst.blst_fp) (ha : FpReduced a)
    (hb : FpReduced b) (l : Fin 8) : FpReduced ⟨(pairWords a.l b.l).val[l.val]⟩ := by
  rw [pairWords_read]
  split
  · exact ha
  · split
    · exact hb
    · change limbs (List.replicate 6 0#u64) < Fp.modulus
      decide +kernel

open scoped EthLib.Cryptography.Bls.Fp in
private theorem zero_words_read : fpRead ⟨Array.repeat 6#usize 0#u64⟩ = Fp.zero := by
  simp [fpRead, limbs, Array.repeat, Fp.ofNat, show (0 : Fp) * _ = 0 from zero_mul _]

private def pairValue (a b : G1) (l : Fin 8) : G1 :=
  if l.val = 0 then a else if l.val = 1 then b else ⟨Fp.zero,Fp.zero,Fp.zero⟩

private theorem twoLanePoint_holds (a b : blst.blst_p1)
    (ha : JacobianReduced a) (hb : JacobianReduced b) (l : Fin 8) :
    (ofG1x8 (twoLanePoint a b)).Holds l
      (pairValue (g1ReadJacobian a) (g1ReadJacobian b) l) := by
  have hx := packedFromBlst_holds (pairWords a.x.l b.x.l) l
    (pairWords_reduced a.x b.x ha.1 hb.1 l)
  have hy := packedFromBlst_holds (pairWords a.y.l b.y.l) l
    (pairWords_reduced a.y b.y ha.2.1 hb.2.1 l)
  have hz := packedFromBlst_holds (pairWords a.z.l b.z.l) l
    (pairWords_reduced a.z b.z ha.2.2 hb.2.2 l)
  simp only [pairWords_read] at hx hy hz
  by_cases h0 : l.val = 0
  · simp only [h0, if_true] at hx hy hz
    simpa only [pairValue, h0, if_true, twoLanePoint, ofG1x8, ofFp8_toFp8,
      g1ReadJacobian] using (G1x8.Holds.mk hx hy hz)
  · by_cases h1 : l.val = 1
    · simp only [h0, h1, if_false, if_true] at hx hy hz
      simpa only [pairValue, h0, h1, if_false, if_true, twoLanePoint, ofG1x8,
        ofFp8_toFp8, g1ReadJacobian, show (1:Nat) ≠ 0 by decide] using (G1x8.Holds.mk hx hy hz)
    · simp only [h0, h1, if_false, zero_words_read] at hx hy hz
      simpa only [pairValue, h0, h1, if_false, twoLanePoint,
        ofG1x8, ofFp8_toFp8] using (G1x8.Holds.mk hx hy hz)

theorem two_lanes_refinement (a b : blst.blst_p1) (P Q : G1)
    (ha : G1Rep a P) (hb : G1Rep b Q) :
    ∃ out, verify.two_lanes a b = ok out ∧ LanesPairRep out P Q := by
  refine ⟨twoLanePoint a b, two_lanes_eq a b, ?_⟩
  intro l
  refine ⟨pairValue (g1ReadJacobian a) (g1ReadJacobian b) l,
    twoLanePoint_holds a b ha.1 hb.1 l, ?_⟩
  by_cases h0 : l.val = 0
  · simpa only [pairValue, h0, if_true] using ha.2
  · by_cases h1 : l.val = 1
    · simpa only [pairValue, h0, h1, if_true, if_false] using hb.2
    · simp only [pairValue, h0, h1, if_false]
      exact ⟨rfl,rfl⟩

private def rawInfinity : blst.blst_p1 :=
  let z : blst.blst_fp := ⟨Array.repeat 6#usize 0#u64⟩
  ⟨z, z, z⟩

private theorem rawInfinity_rep : G1Rep rawInfinity G1.zero := by
  have hz : FpReduced ⟨Array.repeat 6#usize 0#u64⟩ := by
    change limbs (List.replicate 6 0#u64) < Fp.modulus
    decide +kernel
  refine ⟨⟨hz, hz, hz⟩, ?_, ?_⟩ <;>
    simp only [rawInfinity, g1ReadJacobian, zero_words_read] <;> rfl

private def pairTarget (P Q : G1) (lane : Fin 8) : G1 :=
  if lane.val = 0 then P else if lane.val = 1 then Q else G1.zero

private theorem pairTarget_valid {P Q : G1} (hP : G1Valid P) (hQ : G1Valid Q)
    (lane : Fin 8) : G1Valid (pairTarget P Q lane) := by
  unfold pairTarget
  split
  · exact hP
  · split
    · exact hQ
    · exact g1Valid_zero

private theorem LaneG1Rep.of_point_eq {raw : g1x8.G1x8} {lane : Fin 8} {P Q : G1}
    (h : LaneG1Rep raw lane P) (hP : G1Valid P) (hQ : G1Valid Q)
    (he : G1.toPoint P = G1.toPoint Q) : LaneG1Rep raw lane Q := by
  obtain ⟨p, hp, hi, ha⟩ := h
  have hm := (g1_toPoint_eq_iff hP hQ).mp he
  exact ⟨p, hp, hi.trans hm.1, ha.trans hm.2⟩

theorem pairing_points_in_lanes_refinement (sums : verify.PairingSums)
    (ll rlc rli rlp : G1)
    (hll : G1Rep sums.ll ll) (hrlc : G1Rep sums.rlc rlc)
    (hrli : G1Rep sums.rli rli) (hrlp : G1Rep sums.rlp rlp)
    (hvll : G1Valid ll) (hvlc : G1Valid rlc)
    (hvli : G1Valid rli) (hvlp : G1Valid rlp) :
    ∃ out, sums.points_in_lanes = ok out ∧
      LanesPairRep out ll (G1.add (G1.add rlc (G1.neg rli)) rlp) := by
  obtain ⟨base, hb, hbr⟩ := two_lanes_refinement sums.ll sums.rlc ll rlc hll hrlc
  obtain ⟨delta, hd, hdr⟩ := two_lanes_refinement rawInfinity sums.rli G1.zero rli rawInfinity_rep hrli
  obtain ⟨plus, hp, hpr⟩ := two_lanes_refinement rawInfinity sums.rlp G1.zero rlp rawInfinity_rep hrlp
  let negDelta := negLanePoint delta
  let difference := toG1x8 ((ofG1x8 base).add_complete (ofG1x8 negDelta))
  let out := toG1x8 ((ofG1x8 difference).add_complete (ofG1x8 plus))
  refine ⟨out, ?_, ?_⟩
  · simp only [verify.PairingSums.points_in_lanes, blst.blst_p1.Insts.CoreDefaultDefault.default,
      bind_tc_ok, show (let z : blst.blst_fp := ⟨Array.repeat 6#usize 0#u64⟩; blst.blst_p1.mk z z z) = rawInfinity from rfl,
      hb, hd, hp, negLanePoint_refines, G1x8.add_complete_refines]
    rfl
  · intro lane
    have hbase : LaneG1Rep base lane (pairTarget ll rlc lane) := hbr lane
    have hdelta : LaneG1Rep delta lane (pairTarget G1.zero rli lane) := hdr lane
    have hplus : LaneG1Rep plus lane (pairTarget G1.zero rlp lane) := hpr lane
    have vb := pairTarget_valid hvll hvlc lane
    have vd := pairTarget_valid g1Valid_zero hvli lane
    have vp := pairTarget_valid g1Valid_zero hvlp lane
    have hn : LaneG1Rep negDelta lane (G1.neg (pairTarget G1.zero rli lane)) := hdelta.neg vd
    have hdiff : LaneG1Rep difference lane
        (G1.add (pairTarget ll rlc lane) (G1.neg (pairTarget G1.zero rli lane))) :=
      hbase.add_complete hn vb (g1Valid_neg vd)
    have hfinal : LaneG1Rep out lane
        (G1.add (G1.add (pairTarget ll rlc lane) (G1.neg (pairTarget G1.zero rli lane)))
          (pairTarget G1.zero rlp lane)) :=
      hdiff.add_complete hplus (g1Valid_add vb (g1Valid_neg vd)) vp
    apply hfinal.of_point_eq (g1Valid_add (g1Valid_add vb (g1Valid_neg vd)) vp)
      (pairTarget_valid hvll (g1Valid_add (g1Valid_add hvlc (g1Valid_neg hvli)) hvlp) lane)
    rw [g1_toPoint_add (g1Valid_add vb (g1Valid_neg vd)) vp,
      g1_toPoint_add vb (g1Valid_neg vd), g1_toPoint_neg vd]
    by_cases h0 : lane.val = 0
    · simp only [pairTarget, h0, if_true, G1.toPoint_zero, neg_zero, add_zero]
    · by_cases h1 : lane.val = 1
      · simp only [pairTarget, h1, show (1 : Nat) ≠ 0 by decide, if_false, if_true]
        rw [g1_toPoint_add (g1Valid_add hvlc (g1Valid_neg hvli)) hvlp,
          g1_toPoint_add hvlc (g1Valid_neg hvli), g1_toPoint_neg hvli]
      · simp only [pairTarget, h0, h1, if_false, G1.toPoint_zero, neg_zero, add_zero]

end LeanBlsSimd.Kzg
