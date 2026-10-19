import LeanBlsSimd.Kzg.Extender.Kernel.FftOperations
import LeanBlsSimd.Kzg.Extender.Kernel.FftMath
import LeanBlsSimd.Kzg.Extender.Decode
open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg
attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero
namespace LeanBlsSimd.Kzg.Extender.Kernel
set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

def LaneTwiddles (twiddles : Option fr8.Fr8) (roots : _root_.Array Fr) (h : Nat) : Prop :=
  match twiddles with
  | none => h = 1 ∧ roots[0]! = 1
  | some w => (h = 2 ∨ h = 4) ∧
      MultiplierRep w (fun lane => roots[(lane.val % h) * (roots.size / (2 * h))]!)

def lanePairValues (dit : Bool) (pairs : fft8.LanePairs) (a b w : Fin 8 → Fr) :
    (Fin 8 → Fr) × (Fin 8 → Fr) :=
  let upper := permuted a b pairs.upper
  let lower := permuted a b pairs.lower
  let sum := if dit then (fun lane => upper lane + lower lane * w lane)
    else (fun lane => upper lane + lower lane)
  let difference := if dit then (fun lane => upper lane - lower lane * w lane)
    else (fun lane => (upper lane - lower lane) * w lane)
  (permuted sum difference pairs.first, permuted sum difference pairs.second)

theorem lane_pair_values (dit : Bool) (pairs : fft8.LanePairs) (values roots : _root_.Array Fr)
    (h v : Nat) (hpairs : LanePairsInvariant pairs h) (hv : 8 * (v+2) ≤ values.size)
    (hsize : values.size = roots.size) :
    lanePairValues dit pairs (fun lane => values[8*v+lane.val]!)
      (fun lane => values[8*(v+1)+lane.val]!)
      (fun lane => roots[(lane.val % h) * (roots.size / (2*h))]!) =
      ((fun lane => (butterflyStage dit values roots h)[8*v+lane.val]!),
       (fun lane => (butterflyStage dit values roots h)[8*(v+1)+lane.val]!)) := by
  obtain ⟨hh, hget, hput⟩ := hpairs
  have hu (i : Nat) (hi : i < 8) : pairs.upper[i].toNat =
      i % 4 / h * (2 * h) + i % h + i / 4 * 8 := (hget ⟨i, hi⟩).1
  have hl (i : Nat) (hi : i < 8) : pairs.lower[i].toNat =
      i % 4 / h * (2 * h) + i % h + i / 4 * 8 + h := (hget ⟨i, hi⟩).2
  have hf (i : Nat) (hi : i < 8) : pairs.first[i].toNat =
      i / (2*h)*h + i%h + (if i%(2*h)<h then 0 else 8) := (hput ⟨i, hi⟩).1
  have hs (i : Nat) (hi : i < 8) : pairs.second[i].toNat =
      i / (2*h)*h + i%h + 4 + (if i%(2*h)<h then 0 else 8) := (hput ⟨i, hi⟩).2
  have hst (i : Nat) (hi : i < values.size) :
      (butterflyStage dit values roots h)[i]! =
        (let j := i % h
         let upper := i / (2*h) * (2*h) + j
         let a := values[upper]!
         let b := values[upper+h]!
         let w := roots[j*(values.size/(2*h))]!
         if dit then (if i % (2*h) < h then a + b*w else a-b*w)
         else (if i % (2*h) < h then a+b else (a-b)*w)) := by
    rw [getElem!_pos _ i (by simpa [butterflyStage] using hi)]
    simp only [butterflyStage, _root_.Array.getElem_ofFn]
  have hdiv2 (q : Nat) : 8*q/2*2 = 8*q := by omega
  have hdiv4 (q : Nat) : 8*q/4*4 = 8*q := by omega
  apply Prod.ext <;> funext lane
  all_goals dsimp only
  all_goals rw [hst _ (by have := lane.isLt; omega)]
  all_goals fin_cases lane
  all_goals
    rcases hh with rfl | rfl | rfl <;> cases dit <;>
    simp [lanePairValues, permuted, hu, hl, hf, hs,
      Nat.testBit_eq_decide_div_mod_eq, Nat.add_mod, Nat.mul_mod, Nat.add_div,
      hdiv2, hdiv4, ← hsize]
  all_goals repeat' first | omega | congr 1

def twiddleRun (x : fr8.Fr8) (twiddles : Option fr8.Fr8) : Result fr8.Fr8 :=
  match twiddles with
  | none => ok x
  | some w => fr8.Fr8.mul x w

theorem twiddle_representation (x : fr8.Fr8) (av : Fin 8 → Fr)
    (twiddles : Option fr8.Fr8) (roots : _root_.Array Fr) (h : Nat)
    (ha : Represents x av) (htw : LaneTwiddles twiddles roots h) :
    ∃ out, twiddleRun x twiddles = ok out ∧
      Represents out (fun lane => av lane * roots[(lane.val % h) * (roots.size/(2*h))]!) := by
  cases twiddles with
  | none =>
    obtain ⟨rfl, hunit⟩ := htw
    exact ⟨x, rfl, by simpa [hunit, Nat.mod_one, Nat.zero_mul, Fin.mul_one] using ha⟩
  | some w =>
    exact mul_multiplier_refinement x w av _ ha htw.2

def lanePairRun (dit : Bool) (pairs : fft8.LanePairs) (twiddles : Option fr8.Fr8)
    (a b : fr8.Fr8) : Result (fr8.Fr8 × fr8.Fr8) :=
  if dit then do
    let upper ← fr8.Fr8.permute a pairs.upper b
    let lower ← fr8.Fr8.permute a pairs.lower b
    let t ← twiddleRun lower twiddles
    let sum ← fr8.Fr8.add upper t
    let difference ← fr8.Fr8.sub upper t
    let first ← fr8.Fr8.permute sum pairs.first difference
    let second ← fr8.Fr8.permute sum pairs.second difference
    ok (first, second)
  else do
    let upper ← fr8.Fr8.permute a pairs.upper b
    let lower ← fr8.Fr8.permute a pairs.lower b
    let sum ← fr8.Fr8.add upper lower
    let d ← fr8.Fr8.sub upper lower
    let difference ← twiddleRun d twiddles
    let first ← fr8.Fr8.permute sum pairs.first difference
    let second ← fr8.Fr8.permute sum pairs.second difference
    ok (first, second)

theorem lane_pair_representation (dit : Bool) (pairs : fft8.LanePairs)
    (twiddles : Option fr8.Fr8) (roots : _root_.Array Fr) (h : Nat)
    (a b : fr8.Fr8) (av bv : Fin 8 → Fr)
    (ha : Represents a av) (hb : Represents b bv)
    (htw : LaneTwiddles twiddles roots h) :
    ∃ first second, lanePairRun dit pairs twiddles a b = ok (first, second) ∧
      Represents first (lanePairValues dit pairs av bv
        (fun lane => roots[(lane.val % h) * (roots.size/(2*h))]!)).1 ∧
      Represents second (lanePairValues dit pairs av bv
        (fun lane => roots[(lane.val % h) * (roots.size/(2*h))]!)).2 := by
  obtain ⟨upper, hu, hru⟩ := permute_representation a b av bv pairs.upper ha hb
  obtain ⟨lower, hl, hrl⟩ := permute_representation a b av bv pairs.lower ha hb
  cases dit with
  | true =>
    obtain ⟨t, ht, hrt⟩ := twiddle_representation lower _ twiddles roots h hrl htw
    obtain ⟨sum, hs, hrs⟩ := add_representation upper t _ _ hru hrt
    obtain ⟨difference, hd, hrd⟩ := sub_representation upper t _ _ hru hrt
    obtain ⟨first, hf, hrf⟩ := permute_representation sum difference _ _ pairs.first hrs hrd
    obtain ⟨second, hg, hrg⟩ := permute_representation sum difference _ _ pairs.second hrs hrd
    exact ⟨first, second, by simp [lanePairRun, hu, hl, ht, hs, hd, hf, hg], hrf, hrg⟩
  | false =>
    obtain ⟨sum, hs, hrs⟩ := add_representation upper lower _ _ hru hrl
    obtain ⟨d, hd, hrd⟩ := sub_representation upper lower _ _ hru hrl
    obtain ⟨difference, ht, hrt⟩ := twiddle_representation d _ twiddles roots h hrd htw
    obtain ⟨first, hf, hrf⟩ := permute_representation sum difference _ _ pairs.first hrs hrt
    obtain ⟨second, hg, hrg⟩ := permute_representation sum difference _ _ pairs.second hrs hrt
    exact ⟨first, second, by simp [lanePairRun, hu, hl, ht, hs, hd, hf, hg], hrf, hrg⟩

def laneBody (dit : Bool) (pairs : fft8.LanePairs) (twiddles : Option fr8.Fr8)
    (data : Slice fr8.Fr8) (v : Usize) : Result (ControlFlow (Slice fr8.Fr8 × Usize) (Slice fr8.Fr8)) :=
  if dit then fft8.dit_lanes_loop.body pairs twiddles data v
  else fft8.dif_lanes_loop.body pairs twiddles data v

theorem lane_body_pair (dit : Bool) (pairs : fft8.LanePairs) (twiddles : Option fr8.Fr8)
    (data : Slice fr8.Fr8) (v v1 v2 : Usize)
    (hv1 : v1.val = v.val+1) (hv2 : v2.val = v.val+2)
    (hv : v.val+2 ≤ data.val.length) :
    laneBody dit pairs twiddles data v = (do
      let (first, second) ← lanePairRun dit pairs twiddles data.val[v.val]! data.val[v1.val]!
      ok (cont ((data.set v first).set v1 second, v2))) := by
  have hlt : v < Slice.len data := by
    simpa only [UScalar.lt_equiv, Slice.len, Usize.ofNatCore_val_eq] using (show v.val < data.val.length by omega)
  have ha : Slice.index_usize data v = ok data.val[v.val]! := by
    simp [Slice.index_usize, List.getElem?_eq_getElem (show v.val < data.val.length by omega)]
  have hb : Slice.index_usize data v1 = ok data.val[v1.val]! := by
    simp [Slice.index_usize, List.getElem?_eq_getElem (show v1.val < data.val.length by omega)]
  have h1 : v + 1#usize = ok v1 := by
    have ht := scalar_add_ok v 1#usize (by scalar_tac)
    have he : UScalar.ofNatCore (v.val + (1#usize).val) (by scalar_tac) = v1 := by
      apply UScalar.eq_of_val_eq
      simpa using hv1.symm
    exact ht.trans (congrArg ok he)
  have h2 : v + 2#usize = ok v2 := by
    have ht := scalar_add_ok v 2#usize (by scalar_tac)
    have he : UScalar.ofNatCore (v.val + (2#usize).val) (by scalar_tac) = v2 := by
      apply UScalar.eq_of_val_eq
      simpa using hv2.symm
    exact ht.trans (congrArg ok he)
  have hu (x : fr8.Fr8) : Slice.update data v x = ok (data.set v x) := by
    simp [Slice.update, Slice.set, Slice.setAtNat,
      List.getElem?_eq_getElem (show v.val < data.val.length by omega)]
  have hu1 (x y : fr8.Fr8) : Slice.update (data.set v x) v1 y = ok ((data.set v x).set v1 y) := by
    simp [Slice.update, Slice.set, Slice.setAtNat,
      List.getElem?_eq_getElem (show v1.val < (data.val.set v.val x).length by simpa using (show v1.val < data.val.length by omega))]
  cases dit <;> simp only [laneBody, Bool.false_eq_true, if_false, if_true,
    fft8.dit_lanes_loop.body, fft8.dif_lanes_loop.body, hlt, ha, hb, h1, h2,
    hu, hu1, lanePairRun, bind_tc_ok, bind_assoc_eq, twiddleRun]
  all_goals rfl

private def PairPrefix (data : Slice fr8.Fr8) (values output : _root_.Array Fr)
    (n count : Nat) : Prop :=
  data.val.length = n ∧ ∀ v : Fin n, Represents data.val[v.val]!
    (fun lane => if v.val < count then output[8*v.val+lane.val]! else values[8*v.val+lane.val]!)

private theorem pair_prefix_set (data : Slice fr8.Fr8) (values output : _root_.Array Fr)
    (n : Nat) (v v1 : Usize) (hv1 : v1.val = v.val+1) (hv : v.val+2 ≤ n)
    (first second : fr8.Fr8)
    (hfirst : Represents first (fun lane => output[8*v.val+lane.val]!))
    (hsecond : Represents second (fun lane => output[8*v1.val+lane.val]!))
    (hprefix : PairPrefix data values output n v.val) :
    PairPrefix ((data.set v first).set v1 second) values output n (v.val+2) := by
  refine ⟨by simpa [Slice.set, Slice.setAtNat] using hprefix.1, ?_⟩
  intro j
  have hlen := hprefix.1
  have hvb : v.val < data.val.length := by omega
  have hv1b : v1.val < data.val.length := by omega
  by_cases hj : j.val = v.val
  · have hlt : j.val < v.val+2 := by omega
    simp only [Slice.set, Slice.setAtNat]
    simpa [List.getElem!_set, List.getElem!_set_ne, hj, hvb, hv1, hlt] using hfirst
  · by_cases hj1 : j.val = v1.val
    · have hlt : v1.val < v.val+2 := by omega
      have hget : (((data.set v first).set v1 second).val)[j.val]! = second := by
        simp only [Slice.set, Slice.setAtNat, hj1]
        exact List.getElem!_set (data.val.set v.val first) v1.val second (by simpa using hv1b)
      rw [hget]
      simpa only [hj1, hlt, if_true] using hsecond
    · have hiff : (j.val < v.val+2) = (j.val < v.val) := propext (by omega)
      simpa only [Slice.set, Slice.setAtNat,
        List.getElem!_set_ne (data.val.set v.val first) v1.val j.val second (by omega),
        List.getElem!_set_ne data.val v.val j.val first (by omega), hiff]
        using hprefix.2 j

private theorem lane_loops (dit : Bool) (pairs : fft8.LanePairs)
    (twiddles : Option fr8.Fr8) (values roots : _root_.Array Fr) (h n : Nat)
    (hpairs : LanePairsInvariant pairs h) (htw : LaneTwiddles twiddles roots h)
    (hsize : values.size = roots.size) (hn : values.size = 8*n) (hsmall : n ≤ 512)
    (remaining : Nat) :
    ∀ (data : Slice fr8.Fr8) (v : Usize), n = v.val + 2*remaining →
      PairPrefix data values (butterflyStage dit values roots h) n v.val →
      ∃ out, loop (fun (d, i) => laneBody dit pairs twiddles d i) (data,v) = ok out ∧
        PairPrefix out values (butterflyStage dit values roots h) n n := by
  induction remaining with
  | zero =>
    intro data v hv hd
    have he : v.val = n := by omega
    refine ⟨data, ?_, by simpa only [he] using hd⟩
    rw [loop.eq_1]
    cases dit <;> simp [laneBody, fft8.dit_lanes_loop.body, fft8.dif_lanes_loop.body,
      UScalar.lt_equiv, Slice.len, Usize.ofNatCore_val_eq, he, hd.1]
  | succ remaining ih =>
    intro data v hv hd
    have hdlen := hd.1
    have hvn : v.val+2 ≤ n := by omega
    have hv0 : v.val < n := by omega
    have hv1n : v.val+1 < n := by omega
    let v1 : Usize := UScalar.ofNatCore (v.val+1) (by scalar_tac)
    let v2 : Usize := UScalar.ofNatCore (v.val+2) (by scalar_tac)
    have hv1 : v1.val = v.val+1 := UScalar.ofNatCore_val_eq _
    have hv2 : v2.val = v.val+2 := UScalar.ofNatCore_val_eq _
    have ha : Represents data.val[v.val]! (fun lane => values[8*v.val+lane.val]!) := by
      simpa only [lt_self_iff_false, if_false] using hd.2 ⟨v.val,hv0⟩
    have hb : Represents data.val[v1.val]! (fun lane => values[8*v1.val+lane.val]!) := by
      simpa only [show ¬v1.val<v.val by omega, if_false] using hd.2 ⟨v1.val,by omega⟩
    obtain ⟨first, second, hrun, hfirst, hsecond⟩ :=
      lane_pair_representation dit pairs twiddles roots h _ _ _ _ ha hb htw
    have he := lane_pair_values dit pairs values roots h v.val hpairs (by omega) hsize
    rw [hv1] at hfirst hsecond
    rw [he] at hfirst hsecond
    let next := (data.set v first).set v1 second
    have hnext : PairPrefix next values (butterflyStage dit values roots h) n v2.val := by
      rw [hv2]
      apply pair_prefix_set data values _ n v v1 hv1 hvn first second hfirst
      · simpa only [hv1] using hsecond
      · exact hd
    obtain ⟨out, hout, ho⟩ := ih next v2 (by omega) hnext
    refine ⟨out, ?_, ho⟩
    rw [loop.eq_1]
    have hbody := lane_body_pair dit pairs twiddles data v v1 v2 hv1 hv2 (by omega)
    simp only [hbody, hrun, bind_tc_ok]
    exact hout

theorem lanes_refinement (dit : Bool) (data : Slice fr8.Fr8) (values roots : _root_.Array Fr)
    (pairs : fft8.LanePairs) (h : Nat) (twiddles : Option fr8.Fr8)
    (hn : TransformSize roots.size) (hsize : values.size = roots.size)
    (hdata : DataRep data values) (hpairs : LanePairsInvariant pairs h)
    (htwiddles : LaneTwiddles twiddles roots h) :
    ∃ out, (if dit then fft8.dit_lanes data pairs twiddles else fft8.dif_lanes data pairs twiddles) = ok out ∧
      DataRep out (butterflyStage dit values roots h) := by
  obtain ⟨k, hk4, hk12, hk⟩ := hn
  have hs : roots.size ≤ 4096 := by rw [hk]; exact Nat.pow_le_pow_right (by decide) hk12
  have hn16 : roots.size = 16 * 2^(k-4) := by
    rw [hk]
    conv_lhs => rw [show k=(k-4)+4 by omega, Nat.pow_add]
    ring
  have hdsize := hdata.1
  have hlen : data.val.length = 2 * 2^(k-4) := by omega
  have hprefix : PairPrefix data values (butterflyStage dit values roots h) data.val.length 0 := by
    refine ⟨rfl, ?_⟩
    intro v
    simpa only [getElem!_pos data.val v.val v.isLt, Nat.not_lt_zero, if_false] using hdata.2 v
  obtain ⟨out, hout, ho⟩ := lane_loops dit pairs twiddles values roots h data.val.length
    hpairs htwiddles hsize hdata.1 (by omega) (2^(k-4)) data 0#usize
    (by simpa using hlen) hprefix
  refine ⟨out, ?_, ?_, ?_⟩
  · cases dit <;> simpa only [laneBody, Bool.false_eq_true, Bool.true_eq, if_true, if_false,
      fft8.dit_lanes, fft8.dif_lanes, fft8.dit_lanes_loop, fft8.dif_lanes_loop] using hout
  · simp only [butterflyStage, _root_.Array.size_ofFn]
    rw [ho.1]
    exact hdata.1
  · intro v
    have hv : v.val < data.val.length := by simpa only [ho.1] using v.isLt
    simpa only [getElem!_pos out.val v.val v.isLt, hv, if_true] using ho.2 ⟨v.val,hv⟩

end LeanBlsSimd.Kzg.Extender.Kernel
