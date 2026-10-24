import LeanBlsSimd.Portable.Fp.Correct
import LeanBlsSimd.Kzg.PairingTableBounds
import LeanBlsSimd.Refines.Fp8
import LeanBlsSimd.Proofs.Convert

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Kzg

set_option maxRecDepth 8000
set_option maxHeartbeats 4000000
set_option exponentiation.threshold 1000

private theorem packed_limbs_value (a : Array U64 6#usize) :
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

private theorem raw_limbs_value (a : Array U64 8#usize) :
    val (ofArray ofU64 a) = pairingRawValue a := by
  have he : a.val = [a.val[0], a.val[1], a.val[2], a.val[3], a.val[4], a.val[5], a.val[6], a.val[7]] := by
    apply List.ext_getElem
    · simp
    · intro i hi hj
      have hlt : i < 8 := by simpa using hi
      interval_cases i <;> rfl
  rw [val_eq]
  simp only [getElem_ofArray, toNat_ofU64]
  conv_rhs => unfold pairingRawValue; rw [he]
  simp only [List.foldr_cons, List.foldr_nil]
  ring

private def radixCorrection : Array U64 6#usize :=
  Array.make 6#usize [0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 4294967296#u64] (by rfl)

private theorem radixCorrection_rep : PortableFpRep radixCorrection
    (Fp.ofNat (2^352) * (Fp.ofNat (2^384)).inverse) := by
  have hv : limbs radixCorrection.val = 2^352 := by decide +kernel
  constructor
  · change limbs radixCorrection.val < Fp.modulus
    rw [hv]
    decide +kernel
  · simp only [fpRead, hv]

private theorem change_radix (x : Fp) :
    (x * (Fp.ofNat (2^384)).inverse) *
      (Fp.ofNat (2^352) * (Fp.ofNat (2^384)).inverse) =
      x * (Fp.ofNat (2^416)).inverse := by
  have hc : (Fp.ofNat (2^384)).inverse *
      (Fp.ofNat (2^352) * (Fp.ofNat (2^384)).inverse) =
      (Fp.ofNat (2^416)).inverse := by
    rw [Fp.inverse_eq_inv, Fp.inverse_eq_inv]
    field_simp
    decide +kernel
  rw [mul_assoc, hc]

private theorem pairing_lane_convert [RuntimeFeatures]
    (step : Fin 68) (lane : Fin 8) :
    ∃ packed out, bls.limbs.pack64 (pairingRaw step lane) = ok packed ∧
      portable.fp.Fp.mul packed radixCorrection = ok out ∧
      PortableFpRep out (pairingLineValue step lane) := by
  let raw := pairingRaw step lane
  let packed : Array U64 6#usize := toArray toU64 (pack64 (ofArray ofU64 raw))
  have hb := pairingRaw_bounds step lane
  have hn : ∀ j : Fin LIMBS, (ofArray ofU64 raw : Limbs)[j].toNat < 2^52 := by
    intro j
    simp only [Fin.getElem_fin, getElem_ofArray, toNat_ofU64]
    exact hb.1 _ (List.getElem_mem _)
  have hval : limbs packed.val = pairingRawValue raw := by
    rw [← packed_limbs_value, ofArray_toArray_ofU64, pack64_spec hn,
      raw_limbs_value, Nat.mod_eq_of_lt (Nat.lt_trans hb.2 (by decide))]
  have hrep : PortableFpRep packed
      (Fp.ofNat (pairingRawValue raw) * (Fp.ofNat (2^384)).inverse) := by
    constructor
    · change limbs packed.val < Fp.modulus
      rw [hval]
      exact hb.2
    · simp only [fpRead, hval]
  obtain ⟨out, hmul, hout⟩ := (LeanBlsSimd.Portable.Fp.portable_fp_correct).mul hrep radixCorrection_rep
  refine ⟨packed, out, pack64_refines raw, hmul, ?_⟩
  rw [change_radix] at hout
  exact hout

private abbrev Lines := portable.pairing.PairingLines

private def tableRead (out : Lines) (s : Fin 68) (p l : Fin 2) : portable.fp2.Fp2 :=
  ((out.val[s.val]'(by simp)).val[p.val]'(by simpa using p.isLt)).val[l.val]'(by simpa using l.isLt)

private def coefficientRep (s : Fin 68) (p l : Fin 2) (v : portable.fp2.Fp2) : Prop :=
  PortableFpRep v.c0 (pairingLineValue s ⟨4*p.val + 2*l.val, by omega⟩) ∧
  PortableFpRep v.c1 (pairingLineValue s ⟨4*p.val + 2*l.val + 1, by omega⟩)

private def tablePrefix (out : Lines) (n : Nat) : Prop :=
  ∀ (s : Fin 68) (p l : Fin 2), 4*s.val + 2*p.val + l.val < n →
    coefficientRep s p l (tableRead out s p l)

private def tableWrite (out : Lines) (s p l : Usize)
    (hs : s.val < 68) (hp : p.val < 2) (_hl : l.val < 2)
    (v : portable.fp2.Fp2) : Lines :=
  let row := out.val[s.val]'(by simpa using hs)
  let pair := row.val[p.val]'(by simpa using hp)
  out.set s (row.set p (pair.set l v))

private theorem tableWrite_read (out : Lines) (s p l : Usize)
    (hs : s.val < 68) (hp : p.val < 2) (hl : l.val < 2)
    (v : portable.fp2.Fp2) (s' : Fin 68) (p' l' : Fin 2) :
    tableRead (tableWrite out s p l hs hp hl v) s' p' l' =
      if s'.val = s.val ∧ p'.val = p.val ∧ l'.val = l.val then v
      else tableRead out s' p' l' := by
  by_cases hss : s'.val = s.val
  · by_cases hpp : p'.val = p.val
    · by_cases hll : l'.val = l.val <;>
        simp [tableRead, tableWrite, hss, hpp, hll, eq_comm]
    · simp [tableRead, tableWrite, hss, hpp, eq_comm]
  · simp [tableRead, tableWrite, hss, eq_comm]

private theorem tableWrite_prefix (out : Lines) (s p l : Usize)
    (hs : s.val < 68) (hp : p.val < 2) (hl : l.val < 2)
    (v : portable.fp2.Fp2)
    (hv : coefficientRep ⟨s.val, hs⟩ ⟨p.val, hp⟩ ⟨l.val, hl⟩ v)
    (hout : tablePrefix out (4*s.val + 2*p.val + l.val)) :
    tablePrefix (tableWrite out s p l hs hp hl v) (4*s.val + 2*p.val + l.val + 1) := by
  intro s' p' l' hlt
  rw [tableWrite_read]
  split
  · rename_i he
    have es : s' = ⟨s.val, hs⟩ := Fin.ext he.1
    have ep : p' = ⟨p.val, hp⟩ := Fin.ext he.2.1
    have el : l' = ⟨l.val, hl⟩ := Fin.ext he.2.2
    subst s' p' l'
    exact hv
  · rename_i he
    apply hout
    have hs' := s'.isLt
    have hp' := p'.isLt
    have hl' := l'.isLt
    omega

private theorem constructor_inner_body [RuntimeFeatures]
    (out : Lines) (s p l : Usize) (hs : s.val < 68) (hp : p.val < 2) (hl : l.val < 2)
    (hout : tablePrefix out (4*s.val + 2*p.val + l.val)) :
    ∃ next l',
      portable.pairing.PairingLines.new_loop0_loop0_loop0.body radixCorrection s p
        pairing_lines.PAIRING_LINES out l = ok (cont (pairing_lines.PAIRING_LINES, next, l')) ∧
      l'.val = l.val + 1 ∧ tablePrefix next (4*s.val + 2*p.val + l'.val) := by
  have hbits := two_pow_32_le_usize
  have hmul0 : 4*p.val < 2^UScalarTy.Usize.numBits := by scalar_tac
  have hmul1 : 2*l.val < 2^UScalarTy.Usize.numBits := by scalar_tac
  let i0 : Usize := UScalar.ofNatCore (4*p.val) hmul0
  let i1 : Usize := UScalar.ofNatCore (2*l.val) hmul1
  have hsum : i0.val + i1.val < 2^UScalarTy.Usize.numBits := by
    simp [i0, i1]; scalar_tac
  let lane : Usize := UScalar.ofNatCore (i0.val+i1.val) hsum
  have hlane : lane.val = 4*p.val + 2*l.val := rfl
  have hbLane : lane.val < 8 := by omega
  have hinc : lane.val + 1 < 2^UScalarTy.Usize.numBits := by scalar_tac
  let lane1 : Usize := UScalar.ofNatCore (lane.val+1) hinc
  have hlane1 : lane1.val = lane.val+1 := rfl
  have hbLane1 : lane1.val < 8 := by omega
  have hlinc : l.val + 1 < 2^UScalarTy.Usize.numBits := by scalar_tac
  let l' : Usize := UScalar.ofNatCore (l.val+1) hlinc
  have hl' : l'.val = l.val+1 := rfl
  obtain ⟨packed0, c0, hpack0, hmulc0, hc0⟩ := pairing_lane_convert ⟨s.val, hs⟩ ⟨lane.val, hbLane⟩
  obtain ⟨packed1, c1, hpack1, hmulc1, hc1⟩ := pairing_lane_convert ⟨s.val, hs⟩ ⟨lane1.val, hbLane1⟩
  let v : portable.fp2.Fp2 := ⟨c0,c1⟩
  let next := tableWrite out s p l hs hp hl v
  have hv : coefficientRep ⟨s.val, hs⟩ ⟨p.val, hp⟩ ⟨l.val, hl⟩ v := by
    exact ⟨hc0, hc1⟩
  let row := pairing_lines.PAIRING_LINES.val[s.val]'(by simpa using hs)
  let outrow := out.val[s.val]'(by simpa using hs)
  let outpair := outrow.val[p.val]'(by simpa using hp)
  have hirow : Array.index_usize pairing_lines.PAIRING_LINES s = ok row :=
    index_usize_eq pairing_lines.PAIRING_LINES s hs
  have hioutrow : Array.index_mut_usize out s = ok (outrow, out.set s) := by
    simp only [Array.index_mut_usize, index_usize_eq out s hs, bind_tc_ok]
    rfl
  have hioutpair : Array.index_mut_usize outrow p = ok (outpair, outrow.set p) := by
    simp only [Array.index_mut_usize, index_usize_eq outrow p hp, bind_tc_ok]
    rfl
  refine ⟨next, l', ?_, hl', ?_⟩
  · have ht : l < 2#usize := by simpa using hl
    unfold portable.pairing.PairingLines.new_loop0_loop0_loop0.body
    have hm0 : 4#usize * p = ok i0 := mul_ok 4#usize p hmul0
    have hm1 : 2#usize * l = ok i1 := mul_ok 2#usize l hmul1
    have ha : i0 + i1 = ok lane := add_ok i0 i1 hsum
    rw [if_pos ht, hm0, hm1]
    simp only [bind_tc_ok]
    rw [ha]
    simp only [bind_tc_ok]
    rw [hirow]
    simp only [bind_tc_ok]
    rw [index_usize_eq row lane hbLane]
    simp only [bind_tc_ok]
    change bls.limbs.pack64 (row.val[lane.val]'(by simpa using hbLane)) = ok packed0 at hpack0
    rw [hpack0]
    simp only [bind_tc_ok]
    rw [hmulc0]
    simp only [bind_tc_ok]
    have ha1 : lane + 1#usize = ok lane1 := add_ok lane 1#usize hinc
    rw [ha1]
    simp only [bind_tc_ok]
    rw [index_usize_eq row lane1 hbLane1]
    simp only [bind_tc_ok]
    change bls.limbs.pack64 (row.val[lane1.val]'(by simpa using hbLane1)) = ok packed1 at hpack1
    rw [hpack1]
    simp only [bind_tc_ok]
    rw [hmulc1]
    simp only [bind_tc_ok, portable.fp2.Fp2.new, hioutrow]
    change (do
      let (a7, back) ← Array.index_mut_usize outrow p
      let a8 ← Array.update a7 l v
      let l1 ← l + 1#usize
      ok (cont (pairing_lines.PAIRING_LINES, out.set s (back a8), l1))) =
        ok (cont (pairing_lines.PAIRING_LINES, next, l'))
    rw [hioutpair]
    simp only [bind_tc_ok]
    change (do
      let a8 ← Array.update outpair l v
      let l1 ← l + 1#usize
      ok (cont (pairing_lines.PAIRING_LINES, out.set s (outrow.set p a8), l1))) =
        ok (cont (pairing_lines.PAIRING_LINES, next, l'))
    rw [update_eq outpair l v hl]
    simp only [bind_tc_ok]
    rw [add_ok l 1#usize hlinc]
    rfl
  · simpa only [hl', Nat.add_assoc] using tableWrite_prefix out s p l hs hp hl v hv hout

private theorem constructor_inner [RuntimeFeatures]
    (out : Lines) (s p l : Usize) (hs : s.val < 68) (hp : p.val < 2) (hl : l.val ≤ 2)
    (hout : tablePrefix out (4*s.val + 2*p.val + l.val)) :
    ∃ next, portable.pairing.PairingLines.new_loop0_loop0_loop0
      pairing_lines.PAIRING_LINES radixCorrection out s p l = ok (pairing_lines.PAIRING_LINES, next) ∧
      tablePrefix next (4*s.val + 2*p.val + 2) := by
  induction hn : 2-l.val generalizing out l with
  | zero =>
    have he : l.val = 2 := by omega
    have hstop : ¬ l < 2#usize := by simpa using (show ¬ l.val < 2 by omega)
    refine ⟨out, ?_, by simpa only [he] using hout⟩
    rw [portable.pairing.PairingLines.new_loop0_loop0_loop0, loop.eq_1]
    simp only [portable.pairing.PairingLines.new_loop0_loop0_loop0.body, hstop, if_false]
  | succ n ih =>
    have hlt : l.val < 2 := by omega
    obtain ⟨next, l', hbody, hl', hnext⟩ := constructor_inner_body out s p l hs hp hlt hout
    obtain ⟨final, hloop, hfinal⟩ := ih next l' (by omega) hnext (by omega)
    refine ⟨final, ?_, hfinal⟩
    rw [portable.pairing.PairingLines.new_loop0_loop0_loop0, loop.eq_1]
    simp only [hbody]
    exact hloop

private theorem constructor_pair [RuntimeFeatures]
    (out : Lines) (s p : Usize) (hs : s.val < 68) (hp : p.val ≤ 2)
    (hout : tablePrefix out (4*s.val + 2*p.val)) :
    ∃ next, portable.pairing.PairingLines.new_loop0_loop0
      pairing_lines.PAIRING_LINES radixCorrection out s p = ok (pairing_lines.PAIRING_LINES, next) ∧
      tablePrefix next (4*s.val + 4) := by
  induction hn : 2-p.val generalizing out p with
  | zero =>
    have he : p.val = 2 := by omega
    have hstop : ¬ p < 2#usize := by simpa using (show ¬ p.val < 2 by omega)
    refine ⟨out, ?_, by simpa only [he] using hout⟩
    rw [portable.pairing.PairingLines.new_loop0_loop0, loop.eq_1]
    simp only [portable.pairing.PairingLines.new_loop0_loop0.body, hstop, if_false]
  | succ n ih =>
    have hlt : p.val < 2 := by omega
    have htest : p < 2#usize := by simpa using hlt
    obtain ⟨next, hinner, hnext⟩ := constructor_inner out s p 0#usize hs hlt (by decide)
      (by simpa using hout)
    have hin : p.val + 1 < 2^UScalarTy.Usize.numBits := by
      have := two_pow_32_le_usize
      scalar_tac
    let p' : Usize := UScalar.ofNatCore (p.val+1) hin
    have hp' : p'.val = p.val+1 := rfl
    have hadd : p + 1#usize = ok p' := add_ok _ _ hin
    have hnext' : tablePrefix next (4*s.val + 2*p'.val) := by
      convert hnext using 1
    obtain ⟨final, hloop, hfinal⟩ := ih next p' (by omega) hnext' (by omega)
    refine ⟨final, ?_, hfinal⟩
    rw [portable.pairing.PairingLines.new_loop0_loop0, loop.eq_1]
    simp only [portable.pairing.PairingLines.new_loop0_loop0.body, htest, if_true,
      hinner, bind_tc_ok]
    simp only [hadd]
    exact hloop

private theorem constructor_steps [RuntimeFeatures]
    (out : Lines) (s : Usize) (hs : s.val ≤ 68)
    (hout : tablePrefix out (4*s.val)) :
    ∃ next, portable.pairing.PairingLines.new_loop0
      pairing_lines.PAIRING_LINES radixCorrection out s = ok next ∧ tablePrefix next 272 := by
  induction hn : 68-s.val generalizing out s with
  | zero =>
    have he : s.val = 68 := by omega
    have hstop : ¬ s < bls.miller_lines.LINE_COUNT := by
      simp only [bls.miller_lines.LINE_COUNT, UScalar.lt_equiv, UScalar.ofNatCore_val_eq]
      omega
    refine ⟨out, ?_, by simpa only [he] using hout⟩
    rw [portable.pairing.PairingLines.new_loop0, loop.eq_1]
    simp only [portable.pairing.PairingLines.new_loop0.body, hstop, if_false]
  | succ n ih =>
    have hlt : s.val < 68 := by omega
    have htest : s < bls.miller_lines.LINE_COUNT := by
      simpa only [bls.miller_lines.LINE_COUNT, UScalar.lt_equiv, UScalar.ofNatCore_val_eq] using hlt
    obtain ⟨next, hpair, hnext⟩ := constructor_pair out s 0#usize hlt (by decide)
      (by simpa using hout)
    have hin : s.val + 1 < 2^UScalarTy.Usize.numBits := by
      have := two_pow_32_le_usize
      scalar_tac
    let s' : Usize := UScalar.ofNatCore (s.val+1) hin
    have hs' : s'.val = s.val+1 := rfl
    have hadd : s + 1#usize = ok s' := add_ok _ _ hin
    have hnext' : tablePrefix next (4*s'.val) := by
      convert hnext using 1
    obtain ⟨final, hloop, hfinal⟩ := ih next s' (by omega) hnext' (by omega)
    refine ⟨final, ?_, hfinal⟩
    rw [portable.pairing.PairingLines.new_loop0, loop.eq_1]
    simp only [portable.pairing.PairingLines.new_loop0.body, htest, if_true,
      hpair, bind_tc_ok]
    simp only [hadd]
    exact hloop

/-- The actual constructor builds the semantic fixed table from primitive field
multiplication; no pairing-verdict premise is used. -/
theorem pairingLines_new_refinement [RuntimeFeatures] :
    ∃ lines, portable.pairing.PairingLines.new pairing_lines.PAIRING_LINES = ok lines ∧
      PortableLinesRep lines := by
  let initial := Array.repeat 68#usize (Array.repeat 2#usize
    (Array.repeat 2#usize portable.fp2.Fp2.ZERO))
  obtain ⟨out, hloop, hout⟩ := constructor_steps initial 0#usize (by decide)
    (by intro s p l hlt; simp only [UScalar.ofNatCore_val_eq, Nat.mul_zero] at hlt; omega)
  refine ⟨out, ?_, ?_⟩
  · have hshift : 1#u64 <<< 32#i32 = ok 4294967296#u64 := by rfl
    unfold portable.pairing.PairingLines.new
    simp only [hshift, bind_tc_ok]
    change (do
      let result ← portable.pairing.PairingLines.new_loop0
        pairing_lines.PAIRING_LINES radixCorrection initial 0#usize
      ok result) = ok out
    rw [hloop]
    rfl
  · intro s p l
    exact hout s p l (by omega)

end LeanBlsSimd.Kzg
