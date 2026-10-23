import LeanBlsSimd.Kzg.Extender.Kernel.FftOperations
import LeanBlsSimd.Kzg.Extender.Kernel.FftMath
open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg
attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero
namespace LeanBlsSimd.Kzg.Extender.Kernel

theorem butterfly_pair_get (dit : Bool) (values roots : _root_.Array Fr)
    (h block j : Nat) (hh : 0 < h) (hj : j < h) (hblock : block % (2*h)=0)
    (hsize : block+2*h  ≤  values.size) :
    (butterflyStage dit values roots h)[block+j]! =
      (if dit then values[block+j]! + values[block+j+h]! * roots[j*(values.size/(2*h))]!
       else values[block+j]! + values[block+j+h]!) ∧
    (butterflyStage dit values roots h)[block+j+h]! =
      (if dit then values[block+j]! - values[block+j+h]! * roots[j*(values.size/(2*h))]!
       else (values[block+j]! - values[block+j+h]!) * roots[j*(values.size/(2*h))]!) := by
  have hblock' : block / (2*h) * (2*h) = block := Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero hblock)
  have hbmod : block % h = 0 := by
    have hd : h ∣ block := (dvd_mul_left h 2).trans (Nat.dvd_of_mod_eq_zero hblock)
    exact Nat.mod_eq_zero_of_dvd hd
  have hj2 : j  <  2*h := by omega
  have hjh2 : j+h  <  2*h := by omega
  have hi0 : block+j  <  values.size := by omega
  have hi1 : block+j+h  <  values.size := by omega
  have hmod0 : (block+j) % h = j := by simp [Nat.add_mod, hbmod, Nat.mod_eq_of_lt hj]
  have hmod1 : (block+j+h) % h = j := by simpa [Nat.add_mod] using hmod0
  have hmod20 : (block+j) % (2*h) = j := by simp [Nat.add_mod, hblock, Nat.mod_eq_of_lt hj2]
  have hmod21 : (block+j+h) % (2*h) = j+h := by
    rw [Nat.add_assoc]
    simp [Nat.add_mod, hblock, Nat.mod_eq_of_lt hjh2]
  have hdiv0 : (block+j)/(2*h) = block/(2*h) := by
    rw [Nat.add_div_of_dvd_right (Nat.dvd_of_mod_eq_zero hblock), Nat.div_eq_of_lt hj2, Nat.add_zero]
  have hdiv1 : (block+j+h)/(2*h) = block/(2*h) := by
    rw [Nat.add_assoc, Nat.add_div_of_dvd_right (Nat.dvd_of_mod_eq_zero hblock), Nat.div_eq_of_lt hjh2, Nat.add_zero]
  have he (i : Nat) (hi : i  <  values.size) :
      (butterflyStage dit values roots h)[i]! =
        (let a := values[i/(2*h)*(2*h)+i%h]!
         let b := values[i/(2*h)*(2*h)+i%h+h]!
         let w := roots[(i%h)*(values.size/(2*h))]!
         if dit then (if i%(2*h) < h then a+b*w else a-b*w)
         else (if i%(2*h) < h then a+b else (a-b)*w)) := by
    rw [getElem!_pos _ i (by simpa [butterflyStage] using hi)]
    simp only [butterflyStage, _root_.Array.getElem_ofFn]
  rw [he _ hi0, he _ hi1]
  simp [hmod0,hmod1,hmod20,hmod21,hdiv0,hdiv1,hblock',hj,show ¬j+h < h by omega]

theorem wide_pair_values (dit : Bool) (values roots : _root_.Array Fr)
    (half block j : Nat) (hh : 0 < half) (hj : j < half) (hb : block % (2*half)=0)
    (hn : block+2*half  ≤  values.size/8) (hn8 : values.size % 8 = 0)
    (hsize : values.size=roots.size) (lane : Fin 8) :
    (butterflyStage dit values roots (8*half))[8*(block+j)+lane.val]! =
      (if dit then values[8*(block+j)+lane.val]! +
          values[8*(block+j+half)+lane.val]! * roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!
       else values[8*(block+j)+lane.val]! + values[8*(block+j+half)+lane.val]!) ∧
    (butterflyStage dit values roots (8*half))[8*(block+j+half)+lane.val]! =
      (if dit then values[8*(block+j)+lane.val]! -
          values[8*(block+j+half)+lane.val]! * roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!
       else (values[8*(block+j)+lane.val]! - values[8*(block+j+half)+lane.val]!) *
          roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!) := by
  have hb' : (8*block) % (2*(8*half))=0 := by
    apply Nat.mod_eq_zero_of_dvd
    obtain ⟨q,hq⟩ := Nat.dvd_of_mod_eq_zero hb
    refine ⟨q, ?_⟩
    rw [hq]
    ring
  have hsz : 8*block+2*(8*half)  ≤  values.size := by
    have hmul := Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero hn8)
    omega
  have ht := butterfly_pair_get dit values roots (8*half) (8*block) (8*j+lane.val)
    (by omega) (by have := lane.isLt; omega) hb' hsz
  have h0 : 8*block+(8*j+lane.val) = 8*(block+j)+lane.val := by omega
  have h1 : 8*block+(8*j+lane.val)+8*half = 8*(block+j+half)+lane.val := by omega
  have h1' : 8*(block+j)+lane.val+8*half = 8*(block+j+half)+lane.val := by omega
  simpa only [h0,h1',hsize] using ht


theorem wide_table_bounds (table : fft8.Fft8) (roots : _root_.Array Fr)
    (htable : FftInvariant table roots) :
    roots.size = 8*table.vectors.val ∧ table.vectors.val  ≤  512 ∧
      ∃ k : Nat, table.vectors.val = 2^k := by
  obtain ⟨k,hk4,hk12,hk⟩ := htable.1
  have hpow : roots.size = 8*2^(k-3) := by
    rw [hk]
    conv_lhs => rw [show k=(k-3)+3 by omega, Nat.pow_add]
    ring
  have hv : table.vectors.val = 2^(k-3) := by rw [htable.2.1,hpow]; simp
  refine ⟨by rw [hpow,hv], ?_, ⟨k-3,hv⟩⟩
  rw [hv]
  exact (show 2^(k-3) ≤ 2^9 from Nat.pow_le_pow_right (by decide) (by omega))

theorem wide_multiplier (table : fft8.Fft8) (roots : _root_.Array Fr)
    (htable : FftInvariant table roots) (half stage j : Nat)
    (hhalf : half = 2^stage) (hbound : half < table.vectors.val) (hj : j < half) :
    MultiplierRep table.wide.val[half-1+j]!
      (fun lane => roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!) := by
  have hsz := (wide_table_bounds table roots htable).1
  have hp : 2^(stage+3) = 8*half := by rw [hhalf,Nat.pow_add]; ring
  have ht := htable.2.2.2.1 (stage+3) (by omega) (by rw [hp,hsz]; omega)
    ⟨j,by simpa only [hp,Nat.mul_div_cancel_left _ (by decide : 0 < 8)] using hj⟩
  simpa only [hp,Nat.mul_div_cancel_left _ (by decide : 0 < 8)] using ht

def widePairRun (dit : Bool) (offset a b w : fr8.Fr8) : Result (fr8.Fr8 × fr8.Fr8) :=
  if dit then do
    let normal ← fr8.Fr8.normalise b
    let t ← fr8.Fr8.mul normal w
    let first ← fr8.Fr8.add_raw a t
    let second ← fr8.Fr8.sub_raw a t offset
    ok (first,second)
  else do
    let first ← fr8.Fr8.add a b
    let d ← fr8.Fr8.sub_raw a b offset
    let normal ← fr8.Fr8.normalise d
    let second ← fr8.Fr8.mul normal w
    ok (first,second)

def WideOutput (dit : Bool) (k m : Nat) : fr8.Fr8 → (Fin 8 → Fr) → Prop :=
  LazyRep (if dit then k+2 else 2) (if dit then m+33 else 32)

theorem wide_pair_representation (dit : Bool) (k m : Nat)
    (offset a b w : fr8.Fr8) (av bv factors : Fin 8 → Fr)
    (hk : k ≤ 32) (hm : m ≤ 337) (hmode : dit = false → k = 2 ∧ m = 32)
    (hoff : Normalized offset) (hov : ∀ lane, laneNat offset lane = 2 * Fr.modulus)
    (ha : LazyRep k m a av) (hb : LazyRep k m b bv)
    (hw : MultiplierRep w factors) :
    ∃ first second, widePairRun dit offset a b w = ok (first,second) ∧
      WideOutput dit k m first
        (fun lane => if dit then av lane+bv lane*factors lane else av lane+bv lane) ∧
      WideOutput dit k m second
        (fun lane => if dit then av lane-bv lane*factors lane else (av lane-bv lane)*factors lane) := by
  cases dit with
  | true =>
    obtain ⟨normal,t,hn,ht,hrt⟩ := normalise_mul_multiplier_refinement b w bv factors hb
      (by omega) (by omega) hw
    obtain ⟨first,hf,hrf,_⟩ := add_raw_lazy_refinement a t av _ ha hrt (by omega)
    obtain ⟨second,hs,hrs,_⟩ := sub_raw_lazy_refinement a t offset av _ ha hrt hoff hov
      (by decide) (by omega)
    exact ⟨first,second,by simp [widePairRun,hn,ht,hf,hs],
      hrf.mono (by simp) (by simp),hrs⟩
  | false =>
    obtain ⟨rfl,rfl⟩ := hmode rfl
    obtain ⟨first,hf,hrf⟩ := add_lazy_representation a b av bv ha hb (by decide) (by decide)
    obtain ⟨d,hd,hrd,_⟩ := sub_raw_lazy_refinement a b offset av bv ha hb hoff hov
      (by decide) (by decide)
    obtain ⟨normal,second,hn,hs,hrs⟩ := normalise_mul_multiplier_refinement d w _ factors hrd
      (by decide) (by decide) hw
    exact ⟨first,second,by simp [widePairRun,hf,hd,hn,hs],
      hrf.lazy.mono (by decide) (by decide),hrs⟩

end LeanBlsSimd.Kzg.Extender.Kernel
