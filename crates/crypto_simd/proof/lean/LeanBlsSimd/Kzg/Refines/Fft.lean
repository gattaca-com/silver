import LeanBlsSimd.Kzg.Fr.Arithmetic
import LeanBlsSimd.Kzg.Refines.Loop
import LeanBlsSimd.Kzg.ScalarConstants
import LeanBlsSimd.Kzg.Model
import EthLib.Cryptography.Proofs.Kzg.Fft
import EthLib.Cryptography.Proofs.Kzg.Polynomials

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

local instance fftRawFrInhabited : Inhabited blst.blst_fr := ⟨frEncode 0⟩

set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

private theorem scale_loop
    (factor : Fr) (remaining doneValues : List Fr) (out : Slice blst.blst_fr)
    (ho : out.val = (doneValues ++ remaining).map frEncode)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val = doneValues.length)
    (he : iter.end.val = doneValues.length + remaining.length) :
    ∃ result, fft.inverse_fft_loop iter out (frEncode factor) = ok result ∧
      result.val = (doneValues ++ remaining.map (· * factor)).map frEncode := by
  induction remaining generalizing doneValues out iter with
  | nil =>
    have hn := Refinement.next_ge iter (by simp_all)
    refine ⟨out, ?_, by simpa using ho⟩
    rw [fft.inverse_fft_loop, loop.eq_1]
    simp only [fft.inverse_fft_loop.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
  | cons a remaining ih =>
    obtain ⟨iter', hi', he', hn⟩ := Refinement.next_lt iter (by simp_all)
    have hindex : Slice.index_usize out iter.start = ok (frEncode a) := by
      simp [Slice.index_usize, ho, hi, List.getElem_append_right]
    have hlen : ((doneValues ++ [a * factor] ++ remaining).map frEncode).length =
        out.val.length := by simp [ho]
    let out' : Slice blst.blst_fr :=
      ⟨(doneValues ++ [a * factor] ++ remaining).map frEncode, by rw [hlen]; exact out.property⟩
    have hupdate : Slice.update out iter.start (frEncode (a * factor)) = ok out' := by
      simp [Slice.update, ho, hi, out', List.set_append_right]
    have hbody : fft.inverse_fft_loop.body (frEncode factor) iter out =
        ok (cont (iter', out')) := by
      simp only [fft.inverse_fft_loop.body, hn, bind_tc_ok, Function.uncurry_apply_pair,
        hindex, FrScalar.fr_mul_refines, hupdate]
    obtain ⟨result, hloop, hr⟩ := ih (doneValues ++ [a * factor]) out' rfl iter'
      (by simp [hi', hi]) (by simp [he', he, Nat.add_comm, Nat.add_left_comm])
    refine ⟨result, ?_, ?_⟩
    · rw [fft.inverse_fft_loop, loop.eq_1]
      simp only [hbody]
      exact hloop
    · simpa [List.append_assoc] using hr

private theorem slice_index_middle (s : Slice blst.blst_fr)
    (before after : List blst.blst_fr) (a : blst.blst_fr)
    (hs : s.val = before ++ a :: after) (i : Usize) (hi : i.val = before.length) :
    Slice.index_usize s i = ok a := by
  simp [Slice.index_usize, hs, hi, List.getElem_append_right]

private theorem slice_update_middle (s : Slice blst.blst_fr)
    (before after : List blst.blst_fr) (a b : blst.blst_fr)
    (hs : s.val = before ++ a :: after) (i : Usize) (hi : i.val = before.length) :
    ∃ result, Slice.update s i b = ok result ∧ result.val = before ++ b :: after := by
  have hb : (before ++ b :: after).length ≤ Usize.max := by
    have := s.property
    simpa [hs] using this
  refine ⟨⟨before ++ b :: after, hb⟩, ?_, rfl⟩
  simp [Slice.update, hs, hi, List.set_append_right]

private abbrev ButterflyInput := Fr × Fr × Fr
private def leftInputs (xs : List ButterflyInput) := xs.map (·.1)
private def rightInputs (xs : List ButterflyInput) := xs.map (·.2.1)
private def upperOutputs (xs : List ButterflyInput) := xs.map fun p => p.1 + p.2.1 * p.2.2
private def lowerOutputs (xs : List ButterflyInput) := xs.map fun p => p.1 - p.2.1 * p.2.2

private theorem overwrite_halves {α : Type} (xs left right : List α) (n : Nat)
    (hx : xs.length = n + n) (hl : left.length = n) (hr : right.length = n) :
    (xs.setSlice! 0 left).setSlice! n right = left ++ right := by
  have hfirst : xs.setSlice! 0 left = left ++ xs.drop n := by
    simp [List.setSlice!, hx, hl]
  rw [hfirst]
  simp [List.setSlice!, hl, hr, hx]

@[simp] private theorem half_double (n : Nat) : (n + n) / 2 = n := by omega

private theorem halve_get (xs : _root_.Array Fr) (start i : Nat) (hi : i < xs.size / 2) :
    (fftHalve xs start)[i]! = xs[start + 2 * i]! := by
  rw [getElem!_pos _ i (by simpa only [size_fftHalve] using hi)]
  simp [fftHalve]

private def butterflyInputs (left right roots : _root_.Array Fr) (n : Nat) : List ButterflyInput :=
  List.ofFn fun i : Fin n => (left[i.val]!, right[i.val]!, roots[i.val]!)

private theorem butterfly_left (left right roots : _root_.Array Fr) (n : Nat)
    (hl : left.size = n) : leftInputs (butterflyInputs left right roots n) = left.toList := by
  apply List.ext_getElem (by simp [leftInputs, butterflyInputs, hl])
  intro i hi hx
  have hx' : i < left.size := by simpa using hx
  simp [leftInputs, butterflyInputs, getElem!_pos left i hx']

private theorem butterfly_right (left right roots : _root_.Array Fr) (n : Nat)
    (hr : right.size = n) : rightInputs (butterflyInputs left right roots n) = right.toList := by
  apply List.ext_getElem (by simp [rightInputs, butterflyInputs, hr])
  intro i hi hx
  have hx' : i < right.size := by simpa using hx
  simp [rightInputs, butterflyInputs, getElem!_pos right i hx']

private theorem butterfly_spec (values roots : _root_.Array Fr) (n : Nat)
    (hn : 0 < n) (hv : values.size = n + n) :
    let inputs := butterflyInputs
      (fftFieldAux (fftHalve values 0) (fftHalve roots 0))
      (fftFieldAux (fftHalve values 1) (fftHalve roots 0)) roots n
    upperOutputs inputs ++ lowerOutputs inputs = (fftFieldAux values roots).toList := by
  dsimp only
  conv_rhs => rw [fftFieldAux]
  have hlarge : ¬ values.size ≤ 1 := by omega
  have hhalf : values.size / 2 = n := by omega
  simp only [hlarge, if_false, size_fftFieldAux, size_fftHalve, hhalf]
  apply List.ext_getElem (by simp [upperOutputs, lowerOutputs, butterflyInputs, hv])
  intro i hi hx
  by_cases h : i < n
  · simp [upperOutputs, lowerOutputs, butterflyInputs, h]
  · simp [upperOutputs, lowerOutputs, butterflyInputs, List.getElem_append, h]

private theorem butterfly_suffix
    (remaining : List ButterflyInput) (doneLeft doneRight : List Fr)
    (out roots : Slice blst.blst_fr) (stride half : Usize)
    (iter : core.ops.range.Range Usize)
    (ho : out.val = (doneLeft ++ leftInputs remaining ++ doneRight ++ rightInputs remaining).map frEncode)
    (hd : doneRight.length = doneLeft.length)
    (hi : iter.start.val = doneLeft.length) (he : iter.end = half)
    (hn : half.val = doneLeft.length + remaining.length)
    (hs : 0 < stride.val) (hb : half.val * stride.val ≤ roots.val.length)
    (hr : ∀ j (hj : j < remaining.length),
      roots.val[(doneLeft.length + j) * stride.val]! = frEncode (remaining[j].2.2)) :
    ∃ result, fft.transform_loop iter out roots stride half = ok result ∧
      result.val =
        (doneLeft ++ upperOutputs remaining ++ doneRight ++ lowerOutputs remaining).map frEncode := by
  induction remaining generalizing doneLeft doneRight out iter with
  | nil =>
    have hnext := Refinement.next_ge iter (by simp_all)
    refine ⟨out, ?_, ?_⟩
    · rw [fft.transform_loop, loop.eq_1]
      simp only [fft.transform_loop.body, hnext, bind_tc_ok, Function.uncurry_apply_pair]
    · simpa [leftInputs, rightInputs, upperOutputs, lowerOutputs] using ho
  | cons p remaining ih =>
    rcases p with ⟨a, b, w⟩
    have hnextBound : iter.start.val < iter.end.val := by simp [he, hn, hi]
    obtain ⟨iter', hi', he', hnext⟩ := Refinement.next_lt iter hnextBound
    have houtlen : out.val.length = 2 * half.val := by
      simp [ho, leftInputs, rightInputs, hd, hn]
      omega
    have haddBound : half.val + iter.start.val ≤ Usize.max := by
      have := out.property
      simp only [houtlen] at this
      rw [he] at hnextBound
      omega
    obtain ⟨oddIndex, hadd, hoddIndex⟩ := WP.spec_imp_exists
      (Usize.add_spec (x := half) (y := iter.start) haddBound)
    have hrootlt : iter.start.val * stride.val < roots.val.length := by
      have hlt := Nat.mul_lt_mul_of_pos_right (show iter.start.val < half.val by
        simpa [he] using hnextBound) hs
      omega
    obtain ⟨rootIndex, hmul, hrootIndex⟩ := WP.spec_imp_exists
      (Usize.mul_spec (x := iter.start) (y := stride)
        (Nat.le_trans (Nat.le_of_lt hrootlt) roots.property))
    have hroot : Slice.index_usize roots rootIndex = ok (frEncode w) := by
      have hval := hr 0 (by simp)
      simp only [Nat.add_zero, List.getElem_cons_zero] at hval
      rw [getElem!_pos _ _ (by simpa [hi] using hrootlt)] at hval
      have hbound : doneLeft.length * stride.val < roots.val.length := by simpa [hi] using hrootlt
      simp [Slice.index_usize, hrootIndex, hi, List.getElem?_eq_getElem hbound, hval]
    let beforeOdd := (doneLeft ++ leftInputs ((a, b, w) :: remaining) ++ doneRight).map frEncode
    let afterOdd := (rightInputs remaining).map frEncode
    have hsplitOdd : out.val = beforeOdd ++ frEncode b :: afterOdd := by
      simp [ho, beforeOdd, afterOdd, leftInputs, rightInputs, List.append_assoc]
    have hoddPos : oddIndex.val = beforeOdd.length := by
      simp [hoddIndex, beforeOdd, leftInputs, hd, hn, hi]
      omega
    have hodd := slice_index_middle out beforeOdd afterOdd (frEncode b) hsplitOdd oddIndex hoddPos
    obtain ⟨out1, hupdateOdd, hout1⟩ := slice_update_middle out beforeOdd afterOdd
      (frEncode b) (frEncode (a - b * w)) hsplitOdd oddIndex hoddPos
    let beforeEven := doneLeft.map frEncode
    let afterEven := (leftInputs remaining ++ doneRight ++ [a - b * w] ++ rightInputs remaining).map frEncode
    have hsplitEven : out1.val = beforeEven ++ frEncode a :: afterEven := by
      simp [hout1, beforeOdd, afterOdd, beforeEven, afterEven, leftInputs, rightInputs,
        List.append_assoc]
    have hevenPos : iter.start.val = beforeEven.length := by simp [beforeEven, hi]
    have heven := slice_index_middle out (doneLeft.map frEncode)
      ((leftInputs remaining ++ doneRight ++ rightInputs ((a, b, w) :: remaining)).map frEncode)
      (frEncode a) (by simp [ho, leftInputs, rightInputs, List.append_assoc]) iter.start
      (by simp [hi])
    have heven1 := slice_index_middle out1 beforeEven afterEven (frEncode a)
      hsplitEven iter.start hevenPos
    obtain ⟨out2, hupdateEven, hout2⟩ := slice_update_middle out1 beforeEven afterEven
      (frEncode a) (frEncode (a + b * w)) hsplitEven iter.start hevenPos
    have hout2' : out2.val =
        ((doneLeft ++ [a + b * w]) ++ leftInputs remaining ++
          (doneRight ++ [a - b * w]) ++ rightInputs remaining).map frEncode := by
      simp [hout2, beforeEven, afterEven, List.append_assoc]
    have hbody : fft.transform_loop.body roots stride half iter out = ok (cont (iter', out2)) := by
      simp only [fft.transform_loop.body, hnext, bind_tc_ok, Function.uncurry_apply_pair,
        hadd, hodd, hmul, hroot, FrScalar.fr_mul_refines, heven,
        FrScalar.fr_sub_refines, hupdateOdd, heven1,
        FrScalar.fr_add_refines, hupdateEven]
    obtain ⟨result, hloop, hresult⟩ := ih (doneLeft ++ [a + b * w]) (doneRight ++ [a - b * w])
      out2 iter' hout2' (by simp [hd]) (by simp [hi', hi]) (he'.trans he)
      (by simp only [List.length_append, List.length_cons, List.length_nil] at hn ⊢; omega)
      (by
        intro j hj
        have hx := hr (j + 1) (by simp; omega)
        simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using hx)
    refine ⟨result, ?_, ?_⟩
    · rw [fft.transform_loop, loop.eq_1]
      simp only [hbody]
      exact hloop
    · simpa [upperOutputs, lowerOutputs, List.append_assoc] using hresult


private theorem transform_refinement
    (capacity k : Nat) (hcapacity : capacity ≤ Usize.max) (out input roots : Slice blst.blst_fr) (start stride : Usize)
    (values rvalues : _root_.Array Fr)
    (ho : out.val.length = 2^k) (hiLen : input.val.length = capacity)
    (hrLen : roots.val.length = capacity) (hv : values.size = 2^k)
    (hrv : rvalues.size = 2^k) (hcap : 2^k * stride.val = capacity)
    (hstart : start.val < stride.val)
    (hin : ∀ j, j < 2^k → input.val[start.val + j * stride.val]! = frEncode values[j]!)
    (hroot : ∀ j, j < 2^k → roots.val[j * stride.val]! = frEncode rvalues[j]!) :
    ∃ result, fft.transform out input start stride roots stride = ok result ∧
      result.val = (fftFieldAux values rvalues).toList.map frEncode := by
  induction k generalizing out start stride values rvalues with
  | zero =>
    simp only [pow_zero, one_mul] at ho hv hrv hcap hin hroot
    have hlen : Slice.len out = 1#usize := UScalar.eq_of_val_eq (by simpa using ho)
    have hs : start.val < input.val.length := by omega
    have hvalue := hin 0 (by decide)
    simp only [Nat.zero_mul, Nat.add_zero] at hvalue
    rw [getElem!_pos input.val start.val hs] at hvalue
    have hindex : Slice.index_usize input start = ok (frEncode values[0]!) := by
      simp [Slice.index_usize, List.getElem?_eq_getElem hs, hvalue]
    obtain ⟨a, ha⟩ := List.length_eq_one_iff.mp ho
    obtain ⟨result, hupdate, hresult⟩ := slice_update_middle out [] [] a
      (frEncode values[0]!) (by simpa using ha) 0#usize (by simp)
    have hvals : values.toList = [values[0]!] := by
      apply List.ext_getElem (by simp [hv])
      intro i hi hj
      have : i = 0 := by simpa using hj
      subst i
      simp [getElem!_pos values 0 (by omega)]
    refine ⟨result, ?_, ?_⟩
    · rw [fft.transform]
      simp only [hlen, if_true, hindex, bind_tc_ok, hupdate]
    · rw [fftFieldAux]
      simpa [hv, hvals] using hresult
  | succ k ih =>
    let n := 2^k
    have hn : 0 < n := Nat.two_pow_pos k
    have hnSize : 2^(k+1) = n + n := by simp [n, pow_succ, Nat.mul_two]
    have hv' : values.size = n + n := hv.trans hnSize
    have ho' : out.val.length = n + n := ho.trans hnSize
    have hrv' : rvalues.size = n + n := hrv.trans hnSize
    have hcap' : (n + n) * stride.val = capacity := by simpa [hnSize] using hcap
    have hstride : 0 < stride.val := by nlinarith
    have hdouble : 2 * stride.val ≤ capacity := by nlinarith
    have hnNe : Slice.len out ≠ 1#usize := by
      intro heq
      have heq' : out.val.length = 1 := by simpa using congrArg UScalar.val heq
      omega
    obtain ⟨half, hdiv, hhalf⟩ := UScalar.div_spec (Slice.len out) (y := 2#usize) (by simp)
    have hhalf' : half.val = n := by simpa [Slice.len_val, ho'] using hhalf
    obtain ⟨⟨leftSlice, leftBack⟩, hleft, hleftVal, hleftLen, hleftBack⟩ :=
      WP.spec_imp_exists
        (core.slice.index.SliceIndexRangeToUsizeSlice.index_mut.step_spec
          { «end» := half } out (by simp [Slice.length, hhalf', ho']))
    obtain ⟨twice, hmul, htwice⟩ := WP.spec_imp_exists
      (Usize.mul_spec (x := 2#usize) (y := stride) (by simp; scalar_tac))
    have htwice' : twice.val = 2 * stride.val := by simpa using htwice
    have hcapHalf : 2^k * twice.val = capacity := by
      change n * twice.val = capacity
      rw [htwice']
      nlinarith
    have hhalfValues : (fftHalve values 0).size = 2^k := by simp [hv', n]
    have hhalfRoots : (fftHalve rvalues 0).size = 2^k := by simp [hrv', n]
    obtain ⟨leftResult, hleftRun, hleftResult⟩ := ih leftSlice start twice
      (fftHalve values 0) (fftHalve rvalues 0)
      (by simpa [Slice.length, hhalf', n] using hleftLen) hhalfValues hhalfRoots hcapHalf
      (by omega)
      (by
        intro j hj
        have hj' : 2*j < 2^(k+1) := by rw [hnSize]; change j < n at hj; omega
        rw [halve_get values 0 j (by simpa [hv', n] using hj)]
        simpa [htwice', Nat.mul_assoc, Nat.mul_left_comm, Nat.mul_comm] using hin (2*j) hj')
      (by
        intro j hj
        have hj' : 2*j < 2^(k+1) := by rw [hnSize]; change j < n at hj; omega
        rw [halve_get rvalues 0 j (by simpa [hrv', n] using hj)]
        simpa [htwice', Nat.mul_assoc, Nat.mul_left_comm, Nat.mul_comm] using hroot (2*j) hj')
    let out1 := leftBack leftResult
    have hout1 : out1.val = out.val.setSlice! 0 leftResult.val := hleftBack _
    have hout1Len : out1.val.length = n + n := by simp [hout1, ho']
    obtain ⟨⟨rightSlice, rightBack⟩, hright, hrightVal, hrightLen, hrightBack⟩ :=
      WP.spec_imp_exists
        (core.slice.index.SliceIndexRangeFromUsizeSlice.index_mut.step_spec
          { start := half } out1 (by simp [Slice.length, hhalf', hout1Len]))
    obtain ⟨nextStart, hadd, hnextStart⟩ := WP.spec_imp_exists
      (Usize.add_spec (x := start) (y := stride) (by scalar_tac))
    obtain ⟨rightResult, hrightRun, hrightResult⟩ := ih rightSlice nextStart twice
      (fftHalve values 1) (fftHalve rvalues 0)
      (by simpa [Slice.length, hhalf', hout1Len, n] using hrightLen)
      (by simp [hv', n]) hhalfRoots hcapHalf (by omega)
      (by
        intro j hj
        have hj' : 1+2*j < 2^(k+1) := by rw [hnSize]; change j < n at hj; omega
        rw [halve_get values 1 j (by simpa [hv', n] using hj)]
        have hix : nextStart.val + j * twice.val = start.val + (1+2*j)*stride.val := by
          rw [hnextStart, htwice']; ring
        rw [hix]
        exact hin _ hj')
      (by
        intro j hj
        have hj' : 2*j < 2^(k+1) := by rw [hnSize]; change j < n at hj; omega
        rw [halve_get rvalues 0 j (by simpa [hrv', n] using hj)]
        simpa [htwice', Nat.mul_assoc, Nat.mul_left_comm, Nat.mul_comm] using hroot (2*j) hj')
    let out2 := rightBack rightResult
    have hleftSize : leftResult.val.length = n := by simp [hleftResult, hv']
    have hrightSize : rightResult.val.length = n := by simp [hrightResult, hv']
    have hout2 : out2.val = leftResult.val ++ rightResult.val := by
      rw [show out2.val = out1.val.setSlice! half.val rightResult.val from hrightBack _]
      rw [hout1, hhalf']
      exact overwrite_halves out.val leftResult.val rightResult.val n ho' hleftSize hrightSize
    let inputs := butterflyInputs (fftFieldAux (fftHalve values 0) (fftHalve rvalues 0))
      (fftFieldAux (fftHalve values 1) (fftHalve rvalues 0)) rvalues n
    have hinputs : inputs.length = n := by simp [inputs, butterflyInputs]
    have hleftInputs := butterfly_left (fftFieldAux (fftHalve values 0) (fftHalve rvalues 0))
      (fftFieldAux (fftHalve values 1) (fftHalve rvalues 0)) rvalues n (by simp [hv'])
    have hrightInputs := butterfly_right (fftFieldAux (fftHalve values 0) (fftHalve rvalues 0))
      (fftFieldAux (fftHalve values 1) (fftHalve rvalues 0)) rvalues n (by simp [hv'])
    obtain ⟨result, hloop, hresult⟩ := butterfly_suffix inputs [] [] out2 roots stride half
      { start := 0#usize, «end» := half }
      (by simpa [inputs, hleftInputs, hrightInputs, hleftResult, hrightResult] using hout2)
      rfl (by simp) rfl (by simpa using hhalf'.trans hinputs.symm) hstride
      (by rw [hrLen, hhalf']; nlinarith)
      (by
        intro j hj
        have hjn : j < n := by simpa [hinputs] using hj
        have hj' : j < 2^(k+1) := by rw [hnSize]; omega
        simpa [inputs, butterflyInputs] using hroot j hj')
    dsimp only [out1] at hright
    refine ⟨result, ?_, ?_⟩
    · rw [fft.transform]
      simp only [if_neg hnNe, hdiv, bind_tc_ok, Function.uncurry_apply_pair,
        Slice.index_mut_SliceIndexRangeToUsizeSliceInst, hleft, hmul, hleftRun,
        Slice.index_mut_SliceIndexRangeFromUsizeSliceInst, hright, hadd, hrightRun]
      exact hloop
    · have hspec := butterfly_spec values rvalues n hn hv'
      change upperOutputs inputs ++ lowerOutputs inputs = (fftFieldAux values rvalues).toList at hspec
      simpa only [List.nil_append, List.append_nil, hspec] using hresult


theorem fft_refinement_of_blst
    (k : Nat) (out input roots : Slice blst.blst_fr) (values rvalues : _root_.Array Fr)
    (ho : out.val.length = 2^k) (hv : values.size = 2^k) (hrv : rvalues.size = 2^k)
    (hi : input.val = values.toList.map frEncode)
    (hr : roots.val = rvalues.toList.map frEncode) :
    ∃ result, fft.fft out input roots = ok result ∧
      result.val = (fftFieldAux values rvalues).toList.map frEncode := by
  have hp : 0 < 2^k := Nat.two_pow_pos k
  have hiLen : input.val.length = 2^k := by simp [hi, hv]
  have hrLen : roots.val.length = 2^k := by simp [hr, hrv]
  let n := Slice.len out
  have hn : n.val = 2^k := by simp [n, ho]
  have hinLen : Slice.len input = n := UScalar.eq_of_val_eq (by simp [hn, hiLen])
  have hrootsLen : Slice.len roots = n := UScalar.eq_of_val_eq (by simp [hn, hrLen])
  obtain ⟨transformed, htransform, htransformed⟩ := transform_refinement (2^k) k
    (by simpa [ho] using out.property) out input roots
    0#usize 1#usize values rvalues ho hiLen hrLen hv hrv (by simp) (by simp)
    (by
      intro j hj
      have hjv : j < values.size := by omega
      have hji : j < input.val.length := by omega
      have hget : input.val[j]! = frEncode values[j]! := by
        rw [getElem!_pos input.val j hji, getElem!_pos values j hjv]
        simp [hi]
      simpa using hget)
    (by
      intro j hj
      have hjv : j < rvalues.size := by omega
      have hjr : j < roots.val.length := by omega
      have hget : roots.val[j]! = frEncode rvalues[j]! := by
        rw [getElem!_pos roots.val j hjr, getElem!_pos rvalues j hjv]
        simp [hr]
      simpa using hget)
  obtain ⟨sub, hsub, hsubval, _⟩ := WP.spec_imp_exists
    (Usize.sub_spec (x := n) (y := 1#usize) (by simp [hn]))
  have hand : (n &&& sub) = 0#usize := by
    apply UScalar.eq_of_val_eq
    simp only [UScalar.val_and, hn, hsubval, UScalar.ofNatCore_val_eq]
    simp
  obtain ⟨rem, hrem, hremval⟩ := WP.spec_imp_exists
    (UScalar.rem_spec n (y := n) (by simp [hn]))
  have hremeq : rem = 0#usize := UScalar.eq_of_val_eq (by simpa using hremval)
  subst rem
  obtain ⟨quot, hquot, hquotval⟩ := UScalar.div_spec n (y := n) (by simp [hn])
  have hquoteq : quot = 1#usize := UScalar.eq_of_val_eq (by simpa [hn, Nat.ne_of_gt hp] using hquotval)
  subst quot
  refine ⟨transformed, ?_, htransformed⟩
  have hnpos : n > 0#usize := by simp [UScalar.lt_equiv, hn]
  simp only [fft.fft, show Slice.len out = n from rfl, hnpos, hinLen, hrootsLen,
    hsub, lift, bind_tc_ok, hand, hrem, hquot, htransform]
  simp [massert]

theorem inverse_fft_refinement_of_blst
    (k : Nat) (out input roots : Slice blst.blst_fr) (values rvalues : _root_.Array Fr)
    (scale : Fr)
    (ho : out.val.length = 2^k) (hv : values.size = 2^k) (hrv : rvalues.size = 2^k)
    (hi : input.val = values.toList.map frEncode)
    (hr : roots.val = rvalues.toList.map frEncode) :
    ∃ result, fft.inverse_fft out input roots (frEncode scale) = ok result ∧
      result.val = (Model.inverseFft values rvalues scale).toList.map frEncode := by
  obtain ⟨transformed, hfft, htransformed⟩ :=
    fft_refinement_of_blst k out input roots values rvalues ho hv hrv hi hr
  obtain ⟨result, hscale, hresult⟩ := scale_loop scale
    (fftFieldAux values rvalues).toList [] transformed (by simpa using htransformed)
    { start := 0#usize, «end» := Slice.len transformed } (by simp)
    (by simp [htransformed])
  refine ⟨result, ?_, ?_⟩
  · simp only [fft.inverse_fft, hfft, bind_tc_ok, hscale]
  · simpa [Model.inverseFft] using hresult

theorem inverse_fft_refinement
    (out input roots : Slice blst.blst_fr) (values : _root_.Array Fr)
    (ho : out.val.length = 64) (hv : values.size = 64)
    (hi : input.val = values.toList.map frEncode)
    (hr : roots.val = (Model.inverseRoots (Model.roots 6)).toList.map frEncode) :
    ∃ result, fft.inverse_fft out input roots (frEncode (Fr.ofNat 64).inverse) = ok result ∧
      result.val =
        (Model.inverseFft values (Model.inverseRoots (Model.roots 6)) (Fr.ofNat 64).inverse).toList.map
          frEncode :=
  inverse_fft_refinement_of_blst 6 out input roots values
    (Model.inverseRoots (Model.roots 6)) (Fr.ofNat 64).inverse ho hv
    (by simp [Model.inverseRoots, Model.roots]) hi hr

end LeanBlsSimd.Kzg
