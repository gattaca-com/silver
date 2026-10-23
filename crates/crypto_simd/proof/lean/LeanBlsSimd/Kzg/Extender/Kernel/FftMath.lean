import LeanBlsSimd.Kzg.Extender.Kernel.Basic
import LeanBlsSimd.Kzg.Extender.SpecMath

open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open scoped EthLib.Cryptography.Bls.Fr BigOperators

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Kernel

def butterflyStage (dit : Bool) (values roots : _root_.Array Fr) (h : Nat) :
    _root_.Array Fr :=
  _root_.Array.ofFn (n := values.size) fun i =>
    let j := i.val % h
    let upper := i.val / (2 * h) * (2 * h) + j
    let a := values[upper]!
    let b := values[upper + h]!
    let w := roots[j * (values.size / (2 * h))]!
    if dit then
      if i.val % (2 * h) < h then a + b * w else a - b * w
    else
      if i.val % (2 * h) < h then a + b else (a - b) * w

def iterativeDit (logSize : Nat) (values roots : _root_.Array Fr) : _root_.Array Fr :=
  (List.range logSize).foldl (fun acc stage => butterflyStage true acc roots (2 ^ stage)) values

def iterativeDif (logSize : Nat) (values roots : _root_.Array Fr) : _root_.Array Fr :=
  (List.range logSize).reverse.foldl
    (fun acc stage => butterflyStage false acc roots (2 ^ stage)) values

namespace FftMath

attribute [local simp] size_bitReversalPermutation

set_option maxHeartbeats 2000000

@[simp] theorem size_stage (dit : Bool) (values roots : Array Fr) (h : Nat) :
    (butterflyStage dit values roots h).size = values.size := by
  simp only [butterflyStage, Array.size_ofFn]

@[simp] theorem size_stages (dit : Bool) (stages : List Nat) (values roots : Array Fr) :
    (stages.foldl (fun acc stage => butterflyStage dit acc roots (2^stage)) values).size = values.size := by
  induction stages generalizing values with
  | nil => rfl
  | cons stage stages ih =>
    simpa only [List.foldl_cons, size_stage] using
      (ih (butterflyStage dit values roots (2^stage)))

@[simp] theorem size_dit (k : Nat) (values roots : Array Fr) :
    (iterativeDit k values roots).size = values.size := size_stages _ _ _ _

@[simp] theorem size_dif (k : Nat) (values roots : Array Fr) :
    (iterativeDif k values roots).size = values.size := size_stages _ _ _ _

def block (values : Array Fr) (n b : Nat) : Array Fr :=
  Array.ofFn (n := n) fun i => values[b*n+i.val]!

@[simp] theorem size_block (values : Array Fr) (n b : Nat) :
    (block values n b).size = n := by simp [block]

theorem getElem!_block (values : Array Fr) (n b i : Nat) (hi : i < n) :
    (block values n b)[i]! = values[b*n+i]! := by
  simp [block, hi]

theorem reverseBits_high_split (k b j : Nat) (hb : b < 2) (hj : j < 2^k) :
    reverseBits (2^k*b+j) (2^(k+1)) = 2*reverseBits j (2^k)+b := by
  change reverseBits (2^k*b+j) (2^(k+1)) = 2^1*reverseBits j (2^k)+b
  apply Nat.eq_of_testBit_eq
  intro i
  rw [testBit_reverseBits]
  conv_rhs => rw [Nat.testBit_two_pow_mul_add _ (show b < 2^1 from hb)]
  by_cases hi : i = 0
  · subst i
    simp only [Nat.zero_lt_succ, if_true, Nat.add_sub_cancel, Nat.sub_zero,
      show 0 < 1 by decide]
    rw [Nat.testBit_two_pow_mul_add _ hj]
    simp
  · by_cases hik : i < k+1
    · rw [if_pos hik, if_neg (by omega : ¬i < 1),
        Nat.testBit_two_pow_mul_add _ hj, if_pos (by omega : k+1-1-i < k),
        testBit_reverseBits, if_pos (by omega : i-1 < k)]
      congr 1
      omega
    · rw [if_neg hik, if_neg (by omega : ¬i < 1), testBit_reverseBits,
        if_neg (by omega : ¬i-1 < k)]

theorem reverseBits_low_split (k b j : Nat) (hb : b < 2) (hj : j < 2^k) :
    reverseBits (2*j+b) (2^(k+1)) = b*2^k+reverseBits j (2^k) := by
  have h := reverseBits_high_split k b (reverseBits j (2^k)) hb (reverseBits_lt_two_pow j k)
  rw [reverseBits_reverseBits hj] at h
  have hx : 2^k*b+reverseBits j (2^k) < 2^(k+1) := by
    have hp := Nat.two_pow_pos k
    have hr := reverseBits_lt_two_pow j k
    rw [pow_succ]
    nlinarith
  have hh := congrArg (fun i => reverseBits i (2^(k+1))) h
  dsimp only at hh
  rw [reverseBits_reverseBits hx] at hh
  simpa [Nat.mul_comm b] using hh.symm

theorem getElem!_stage (dit : Bool) (values roots : Array Fr) (h i : Nat)
    (hi : i < values.size) :
    (butterflyStage dit values roots h)[i]! =
      let j := i % h
      let upper := i / (2*h) * (2*h)+j
      let a := values[upper]!
      let b := values[upper+h]!
      let w := roots[j*(values.size/(2*h))]!
      if dit then if i%(2*h)<h then a+b*w else a-b*w
      else if i%(2*h)<h then a+b else (a-b)*w := by
  simp [butterflyStage, hi]

theorem stage_block (dit : Bool) (values roots : Array Fr) (h n b : Nat)
    (hv : values.size = 2*n) (hr : roots.size = 2*n)
    (hd : 2*h ∣ n) (hp : 0 < h) (hb : b < 2) :
    block (butterflyStage dit values roots h) n b =
      butterflyStage dit (block values n b) (fftHalve roots 0) h := by
  obtain ⟨q, hq⟩ := hd
  have hp2 : 0 < 2*h := by omega
  have hdiv : n/(2*h) = q := by rw [hq, Nat.mul_div_cancel_left _ hp2]
  have hdbl : (2*n)/(2*h) = 2*q := by
    rw [hq, show 2*(2*h*q) = (2*h)*(2*q) by ring, Nat.mul_div_cancel_left _ hp2]
  have hnmod : n % (2*h) = 0 := by rw [hq, Nat.mul_mod_right]
  have hnh : n % h = 0 := by rw [hq, show 2*h*q = h*(2*q) by ring, Nat.mul_mod_right]
  apply Array.ext
  · simp
  · intro i hi hi'
    have hin : i < n := by simpa using hi
    have hib : b*n+i < values.size := by rw [hv]; nlinarith
    have hj : i%h < h := Nat.mod_lt _ hp
    have hc : i/(2*h)*(2*h)+(i%(2*h)) = i := by simpa [Nat.mul_comm] using Nat.div_add_mod i (2*h)
    have hjle : i%h ≤ i%(2*h) := by
      have hm : i%(2*h)%h = i%h := Nat.mod_mod_of_dvd _ ⟨2, by omega⟩
      rw [← hm]
      exact Nat.mod_le _ _
    have hu : i/(2*h)*(2*h)+i%h < n := by omega
    have hul : i/(2*h)*(2*h)+i%h+h < n := by
      have hid : i/(2*h) < q := by
        apply (Nat.div_lt_iff_lt_mul hp2).mpr
        rw [hq] at hin
        nlinarith
      have hh := Nat.mul_le_mul_right (2*h) (Nat.succ_le_of_lt hid)
      rw [hq]
      nlinarith
    have hjq : i%h*q < n := by rw [hq]; nlinarith
    have hmod : (b*n+i)%h = i%h := by simp [Nat.add_mod, Nat.mul_mod, hnh]
    have hmod2 : (b*n+i)%(2*h) = i%(2*h) := by simp [Nat.add_mod, Nat.mul_mod, hnmod]
    have hdiv2 : (b*n+i)/(2*h) = b*q+i/(2*h) := by
      rw [hq, show b*(2*h*q)+i = (2*h)*(b*q)+i by ring]
      exact Nat.mul_add_div hp2 (b*q) i
    have hu' : (b*n+i)/(2*h)*(2*h)+i%h =
        b*n+(i/(2*h)*(2*h)+i%h) := by rw [hdiv2,hq]; ring
    rw [← getElem!_pos _ i hi, ← getElem!_pos _ i hi', getElem!_block _ _ _ _ hin,
      getElem!_stage _ _ _ _ _ hib, getElem!_stage _ _ _ _ _ (by simp [hin])]
    simp only [size_block, hv, hmod, hmod2, hu', hdbl, hdiv]
    rw [getElem!_block _ _ _ _ hu, getElem!_block _ _ _ _ hul,
      getElem!_fftHalve roots 0 (i%h*q) (by rw [hr]; omega)]
    simp only [Nat.zero_add]
    rw [show i%h*(2*q) = 2*(i%h*q) by ring,
      show b*n+(i/(2*h)*(2*h)+i%h)+h = b*n+(i/(2*h)*(2*h)+i%h+h) by omega]

theorem block_stages (dit : Bool) (k : Nat) (stages : List Nat) (values roots : Array Fr)
    (b : Nat) (hv : values.size = 2*(2^k)) (hr : roots.size = 2*(2^k))
    (hb : b < 2) (hs : ∀ s ∈ stages, s < k) :
    block (stages.foldl (fun acc s => butterflyStage dit acc roots (2^s)) values) (2^k) b =
      stages.foldl (fun acc s => butterflyStage dit acc (fftHalve roots 0) (2^s))
        (block values (2^k) b) := by
  induction stages generalizing values with
  | nil => rfl
  | cons s stages ih =>
    simp only [List.foldl_cons]
    rw [ih _ (by simpa using hv) (fun t ht => hs t (by simp [ht]))]
    rw [stage_block dit values roots (2^s) (2^k) b hv hr ?_ (Nat.two_pow_pos _) hb]
    rw [← pow_succ']
    exact Nat.pow_dvd_pow 2 (Nat.succ_le_of_lt (hs s (by simp)))

theorem halve_bitReversal (k : Nat) (values : Array Fr) (b : Nat)
    (hv : values.size = 2^(k+1)) (hb : b < 2) :
    fftHalve (bitReversalPermutation values) b =
      bitReversalPermutation (block values (2^k) b) := by
  have hp := Nat.two_pow_pos k
  have hpow : 2^(k+1) = 2*(2^k) := by rw [pow_succ']
  have hsz : (fftHalve (bitReversalPermutation values) b).size = 2^k := by
    simp only [size_fftHalve, size_bitReversalPermutation, hv, hpow]
    omega
  apply Array.ext
  · simp [hsz]
  · intro i hi hi'
    have hin : i < 2^k := by simpa using hi'
    have hbi : b+2*i < (bitReversalPermutation values).size := by
      rw [size_bitReversalPermutation,hv,hpow]
      omega
    rw [getElem_fftHalve, getElem!_pos (bitReversalPermutation values) (b+2*i) hbi, getElem_bitReversalPermutation,
      getElem_bitReversalPermutation, hv, size_block,
      show b+2*i = 2*i+b by omega, reverseBits_low_split k b i hb hin,
      getElem!_block _ _ _ _ (reverseBits_lt_two_pow i k)]

theorem dit_eq_recursive (k : Nat) (values roots : Array Fr)
    (hv : values.size = 2^k) (hr : roots.size = 2^k) :
    iterativeDit k values roots = fftFieldAux (bitReversalPermutation values) roots := by
  induction k generalizing values roots with
  | zero =>
    simp only [iterativeDit, List.range_zero, List.foldl_nil]
    rw [fftFieldAux, if_pos (by simpa using (le_of_eq hv : values.size ≤ 1))]
    apply Array.ext
    · simp
    · intro i hi hi'
      have hi0 : i = 0 := by simp only [pow_zero] at hv; omega
      subst i
      rw [getElem_bitReversalPermutation]
      simp [hv, reverseBits, reverseBitsAux]
  | succ k ih =>
    have hp := Nat.two_pow_pos k
    have hpow : 2^(k+1) = 2*(2^k) := by rw [pow_succ']
    have hv' : values.size = 2*(2^k) := hv.trans hpow
    have hr' : roots.size = 2*(2^k) := hr.trans hpow
    have hrhalf : (fftHalve roots 0).size = 2^k := by simp only [size_fftHalve,hr']; omega
    have hsub (b : Nat) (hb : b < 2) :
        block (iterativeDit k values roots) (2^k) b =
          fftFieldAux (fftHalve (bitReversalPermutation values) b) (fftHalve roots 0) := by
      rw [iterativeDit, block_stages true k (List.range k) values roots b hv' hr' hb
        (fun s hs => List.mem_range.mp hs)]
      rw [← iterativeDit, ih _ _ (size_block _ _ _) hrhalf, ← halve_bitReversal k values b hv hb]
    let v := iterativeDit k values roots
    have hvsize : v.size = values.size := size_dit _ _ _
    have hleft (q : Nat) (hq : q < 2^k) :
        v[q]! = (fftFieldAux (fftHalve (bitReversalPermutation values) 0) (fftHalve roots 0))[q]! := by
      have h := congrArg (fun xs : Array Fr => xs[q]!) (hsub 0 (by decide))
      simpa only [getElem!_block _ _ _ _ hq, Nat.zero_mul, Nat.zero_add] using h
    have hright (q : Nat) (hq : q < 2^k) :
        v[q+2^k]! = (fftFieldAux (fftHalve (bitReversalPermutation values) 1) (fftHalve roots 0))[q]! := by
      have h := congrArg (fun xs : Array Fr => xs[q]!) (hsub 1 (by decide))
      simpa only [getElem!_block _ _ _ _ hq, Nat.one_mul, Nat.add_comm] using h
    have hrec : iterativeDit (k+1) values roots = butterflyStage true v roots (2^k) := by
      simp only [iterativeDit, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
      rfl
    rw [hrec]
    apply Array.ext
    · simp [hvsize]
    · intro i hi hi'
      have hin : i < 2*(2^k) := by simpa [hvsize,hv'] using hi
      have hi0 : i/(2*(2^k)) = 0 := Nat.div_eq_of_lt hin
      have him : i%(2*(2^k)) = i := Nat.mod_eq_of_lt hin
      have hq : i%(2^k) < 2^k := Nat.mod_lt _ hp
      rw [← getElem!_pos _ i hi, ← getElem!_pos _ i hi',
        getElem!_stage _ _ _ _ _ (by simpa using hi),
        getElem_fftFieldAux_step _ _ (by rw [size_bitReversalPermutation,hv']; omega) i
          (by simpa using hi')]
      simp only [hvsize,hv',size_bitReversalPermutation,hi0,him,Nat.zero_mul,Nat.zero_add,
        show (2*(2^k))/2 = 2^k by omega, Nat.div_self (by omega : 0 < 2*(2^k)), Nat.mul_one, if_true]
      rw [hleft _ hq, hright _ hq]
      by_cases hit : i < 2^k
      · simp only [hit,if_true,Nat.mod_eq_of_lt hit]
      · have hmod : i%2^k = i-2^k := by
          rw [Nat.mod_eq_sub_mod (by omega : 2^k ≤ i), Nat.mod_eq_of_lt (by omega)]
        simp only [hit,if_false,hmod]

theorem dif_stage_block_get (values roots : Array Fr) (n b i : Nat)
    (hv : values.size = 2*n) (hp : 0 < n) (hb : b < 2) (hi : i < n) :
    (block (butterflyStage false values roots n) n b)[i]! =
      if b = 0 then values[i]!+values[i+n]!
      else (values[i]!-values[i+n]!)*roots[i]! := by
  have hin : b*n+i < values.size := by rw [hv]; nlinarith
  rw [getElem!_block _ _ _ _ hi, getElem!_stage _ _ _ _ _ hin]
  have hbig : b*n+i < 2*n := by omega
  have hp2 : 0 < 2*n := by omega
  have hlow : (b*n+i)%n = i := by simp [Nat.add_mod, Nat.mod_eq_of_lt hi]
  simp only [Nat.div_eq_of_lt hbig, Nat.mod_eq_of_lt hbig, hlow, Nat.zero_mul,
    Nat.zero_add, hv, Nat.div_self hp2, Nat.mul_one, Bool.false_eq_true, if_false]
  interval_cases b <;> simp [hi, show ¬n+i<n by omega]

theorem half_dft {F : Type*} [Field F] (f : Nat → F) (ω : F) (n r b : Nat)
    (hb : b < 2) (hpow : ω^(2*n) = 1) (hneg : ω^n = -1) :
    (∑ t ∈ Finset.range n,
      (if b=0 then f t+f (t+n) else (f t-f (t+n))*ω^t) * (ω^2)^(t*r)) =
      ∑ t ∈ Finset.range (2*n), f t*ω^(t*(2*r+b)) := by
  rw [show 2*n = n+n by omega, Finset.sum_range_add, ← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro t ht
  interval_cases b
  · simp only [Nat.add_zero, if_true]
    rw [← pow_mul, show 2*(t*r) = t*(2*r) by ring,
      show (n+t)*(2*r) = (2*n)*r+t*(2*r) by ring, pow_add,
      pow_mul ω (2*n) r, hpow, one_pow, one_mul, Nat.add_comm n t]
    ring
  · simp only [show ¬(1:Nat)=0 by decide, if_false]
    rw [← pow_mul, show 2*(t*r) = t*(2*r) by ring,
      show t*(2*r+1) = t*(2*r)+t by ring,
      show (n+t)*(2*r+1) = (2*n)*r+n+(t*(2*r)+t) by ring]
    simp only [pow_add]
    rw [pow_mul ω (2*n) r, hpow, one_pow, hneg, Nat.add_comm n t]
    ring

theorem dif_eq_dft (k : Nat) (values roots : Array Fr) (ω : Fr)
    (hv : values.size = 2^k) (hr : roots.size = 2^k)
    (hω : IsPrimitiveRoot ω (2^k)) (hroots : ∀ i, i < 2^k → roots[i]! = ω^i)
    (j : Nat) (hj : j < 2^k) :
    (iterativeDif k values roots)[j]! =
      ∑ t ∈ Finset.range (2^k), values[t]! * ω^(t*reverseBits j (2^k)) := by
  induction k generalizing values roots ω j with
  | zero =>
    have hj0 : j = 0 := by simpa using hj
    subst j
    simp [iterativeDif, reverseBits, reverseBitsAux]
    exact (Fin.mul_one _).symm
  | succ k ih =>
    have hp := Nat.two_pow_pos k
    have hpow : 2^(k+1) = 2*(2^k) := by rw [pow_succ']
    have hv' : values.size = 2*(2^k) := hv.trans hpow
    have hr' : roots.size = 2*(2^k) := hr.trans hpow
    have hrhalf : (fftHalve roots 0).size = 2^k := by simp only [size_fftHalve,hr']; omega
    have hω2 : IsPrimitiveRoot (ω^2) (2^k) := hω.pow (Nat.two_pow_pos (k+1)) hpow
    have hroots2 : ∀ i, i < 2^k → (fftHalve roots 0)[i]! = (ω^2)^i := by
      intro i hi
      rw [getElem!_fftHalve roots 0 i (by rw [hr']; omega), Nat.zero_add,
        hroots (2*i) (by rw [hpow]; omega), ← pow_mul]
    let z := butterflyStage false values roots (2^k)
    have hz : z.size = 2*(2^k) := by simpa [z] using hv'
    let b := j/(2^k)
    let q := j%(2^k)
    have hb : b < 2 := by
      dsimp [b]
      apply (Nat.div_lt_iff_lt_mul hp).mpr
      rwa [hpow] at hj
    have hq : q < 2^k := Nat.mod_lt _ hp
    have hjb : b*(2^k)+q = j := by
      dsimp [b,q]
      simpa [Nat.mul_comm] using Nat.div_add_mod j (2^k)
    have hrec : block (iterativeDif (k+1) values roots) (2^k) b =
        iterativeDif k (block z (2^k) b) (fftHalve roots 0) := by
      simp only [iterativeDif, List.range_succ, List.reverse_append, List.reverse_cons,
        List.reverse_nil, List.nil_append]
      exact block_stages false k ((List.range k).reverse) z roots b hz hr' hb
        (fun s hs => List.mem_range.mp (List.mem_reverse.mp hs))
    have hout := congrArg (fun xs : Array Fr => xs[q]!) hrec
    dsimp only at hout
    rw [getElem!_block _ _ _ _ hq, hjb,
      ih _ _ _ (size_block _ _ _) hrhalf hω2 hroots2 q hq] at hout
    rw [hout, ← hjb, Nat.mul_comm b (2^k), reverseBits_high_split k b q hb hq, hpow]
    calc
      _ = ∑ t ∈ Finset.range (2^k),
          (if b=0 then values[t]!+values[t+2^k]!
            else (values[t]!-values[t+2^k]!)*ω^t) * (ω^2)^(t*reverseBits q (2^k)) := by
        apply Finset.sum_congr rfl
        intro t ht
        have ht' := Finset.mem_range.mp ht
        rw [dif_stage_block_get values roots (2^k) b t hv' hp hb ht',
          hroots t (by rw [hpow]; omega)]
      _ = _ := half_dft (fun t => values[t]!) ω (2^k) (reverseBits q (2^k)) b hb
        (hpow ▸ hω.pow_eq_one) (pow_half_eq_neg_one hp (hpow ▸ hω))

end FftMath

theorem iterative_dit_eq_spec_pow (values roots : Array Fr) (k : Nat)
    (hsize : values.size = roots.size) (hlog : roots.size = 2^k) (_hroots : RootsValid roots) :
    iterativeDit k values roots = fftFieldAux (bitReversalPermutation values) roots :=
  FftMath.dit_eq_recursive k values roots (hsize.trans hlog) hlog

theorem iterative_dif_eq_spec_pow (values roots : Array Fr) (k : Nat)
    (hsize : values.size = roots.size) (hlog : roots.size = 2^k) (hroots : RootsValid roots) :
    iterativeDif k values roots = bitReversalPermutation (fftFieldAux values roots) := by
  obtain ⟨ω, l, hl, hω, hpowers⟩ := hroots
  have hlk : l = k := by
    have he : 2^l = 2^k := hl.symm.trans hlog
    exact Nat.pow_right_injective (by decide) he
  subst l
  have hv := hsize.trans hlog
  apply Array.ext
  · simp only [FftMath.size_dif, size_bitReversalPermutation, size_fftFieldAux]
  · intro i hi hi'
    have hin : i < 2^k := by simpa only [FftMath.size_dif, hv] using hi
    rw [← getElem!_pos _ i hi, getElem_bitReversalPermutation,
      size_fftFieldAux, hv,
      FftMath.dif_eq_dft k values roots ω hv hlog hω (by simpa only [hlog] using hpowers) i hin,
      getElem!_fftFieldAux_dft hω values roots hv hlog (by simpa only [hlog] using hpowers)
        (reverseBits i (2^k)) (reverseBits_lt_two_pow i k)]

end LeanBlsSimd.Kzg.Extender.Kernel
