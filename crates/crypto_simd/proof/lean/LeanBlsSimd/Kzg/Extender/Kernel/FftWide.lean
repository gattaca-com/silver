import LeanBlsSimd.Kzg.Extender.Kernel.FftWideRun
import LeanBlsSimd.Kzg.Extender.Kernel.FftWidePair

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

private theorem pair_block_bound (half n N : Nat) (hhalf : 0 < half)
    (hdiv : 2 * half ∣ N) (hn : n < N / 2) :
    n / half * (2 * half) + 2 * half ≤ N := by
  obtain ⟨q, rfl⟩ := hdiv
  have hN : 2 * half * q / 2 = half * q := by
    rw [Nat.mul_assoc, Nat.mul_div_cancel_left _ (by decide : 0 < 2)]
  rw [hN] at hn
  have hq : n / half < q :=
    (Nat.div_lt_iff_lt_mul hhalf).mpr (by simpa [Nat.mul_comm] using hn)
  nlinarith

private theorem wide_pair_output (s : WideStage) (h : s.Valid) (k m : Nat)
    (hk : k ≤ 32) (hm : m ≤ 337) (hmode : s.dit = false → k = 2 ∧ m = 32)
    (values roots : _root_.Array Fr) (htable : FftInvariant s.table roots)
    (hsize : values.size = roots.size) (hdata : LazyDataRep k m s.input values)
    (hoff : Normalized s.offset) (hov : ∀ lane, laneNat s.offset lane = 2 * Fr.modulus)
    (n : Nat) (hn : n < s.table.vectors.val / 2) :
    WideOutput s.dit k m (s.left n)
      (fun lane => (butterflyStage s.dit values roots (8 * s.half.val))[8 * pairFirst s.half.val n + lane.val]!) ∧
    WideOutput s.dit k m (s.right n)
      (fun lane => (butterflyStage s.dit values roots (8 * s.half.val))[8 * (pairFirst s.half.val n + s.half.val) + lane.val]!) := by
  have htb := wide_table_bounds s.table roots htable
  have hb := pairFirst_add_half_lt s.half.val n s.table.vectors.val h.half_pos h.divides hn
  have hi : pairFirst s.half.val n < s.input.val.length := by rw [h.input_length]; omega
  have hi' : pairFirst s.half.val n + s.half.val < s.input.val.length := by
    rw [h.input_length]; exact hb
  have ha : LazyRep k m (s.x n)
      (fun lane => values[8 * pairFirst s.half.val n + lane.val]!) := by
    simpa only [WideStage.x, getElem!_pos s.input.val (pairFirst s.half.val n) hi]
      using hdata.2 ⟨_, hi⟩
  have hb' : LazyRep k m (s.y n)
      (fun lane => values[8 * (pairFirst s.half.val n + s.half.val) + lane.val]!) := by
    simpa only [WideStage.y,
      getElem!_pos s.input.val (pairFirst s.half.val n + s.half.val) hi']
      using hdata.2 ⟨_, hi'⟩
  obtain ⟨stage, hstage⟩ := h.half_pow
  have hj := Nat.mod_lt n h.half_pos
  have hw : MultiplierRep (s.factor n)
      (fun lane => roots[(8 * (n % s.half.val) + lane.val) *
        (roots.size / (2 * (8 * s.half.val)))]!) :=
    wide_multiplier s.table roots htable s.half.val stage (n % s.half.val)
      hstage h.half_lt hj
  obtain ⟨first, second, hrun, hfirst, hsecond⟩ :=
    wide_pair_representation s.dit k m s.offset (s.x n) (s.y n) (s.factor n)
      _ _ _ hk hm hmode hoff hov ha hb' hw
  rw [s.pair_refines] at hrun
  have he := Result.ok.inj hrun
  have hef := congrArg Prod.fst he
  have hes := congrArg Prod.snd he
  simp only at hef hes
  rw [← hef] at hfirst
  rw [← hes] at hsecond
  have hblock := pair_block_bound s.half.val n s.table.vectors.val h.half_pos h.divides hn
  have hsem (lane : Fin 8) := wide_pair_values s.dit values roots s.half.val
    (n / s.half.val * (2 * s.half.val)) (n % s.half.val) h.half_pos hj
    (by simp) (by rw [hsize, htb.1]; simpa using hblock)
    (by rw [hsize, htb.1]; omega) hsize lane
  have he0 : (fun lane : Fin 8 => if s.dit then
      values[8 * pairFirst s.half.val n + lane.val]! +
        values[8 * (pairFirst s.half.val n + s.half.val) + lane.val]! *
          roots[(8 * (n % s.half.val) + lane.val) * (roots.size / (2 * (8 * s.half.val)))]!
      else values[8 * pairFirst s.half.val n + lane.val]! +
        values[8 * (pairFirst s.half.val n + s.half.val) + lane.val]!) =
      (fun lane => (butterflyStage s.dit values roots (8 * s.half.val))[8 * pairFirst s.half.val n + lane.val]!) := by
    funext lane
    simpa only [pairFirst] using (hsem lane).1.symm
  have he1 : (fun lane : Fin 8 => if s.dit then
      values[8 * pairFirst s.half.val n + lane.val]! -
        values[8 * (pairFirst s.half.val n + s.half.val) + lane.val]! *
          roots[(8 * (n % s.half.val) + lane.val) * (roots.size / (2 * (8 * s.half.val)))]!
      else (values[8 * pairFirst s.half.val n + lane.val]! -
        values[8 * (pairFirst s.half.val n + s.half.val) + lane.val]!) *
          roots[(8 * (n % s.half.val) + lane.val) * (roots.size / (2 * (8 * s.half.val)))]!) =
      (fun lane => (butterflyStage s.dit values roots (8 * s.half.val))[8 * (pairFirst s.half.val n + s.half.val) + lane.val]!) := by
    funext lane
    simpa only [pairFirst] using (hsem lane).2.symm
  exact ⟨he0 ▸ hfirst, he1 ▸ hsecond⟩

private theorem wide_state_output (s : WideStage) (h : s.Valid) (k m : Nat)
    (hk : k ≤ 32) (hm : m ≤ 337) (hmode : s.dit = false → k = 2 ∧ m = 32)
    (values roots : _root_.Array Fr) (htable : FftInvariant s.table roots)
    (hsize : values.size = roots.size) (hdata : LazyDataRep k m s.input values)
    (hoff : Normalized s.offset) (hov : ∀ lane, laneNat s.offset lane = 2 * Fr.modulus) :
    LazyDataRep (if s.dit then k + 2 else 2) (if s.dit then m + 33 else 32)
      (s.state (s.table.vectors.val / 2) false)
      (butterflyStage s.dit values roots (8 * s.half.val)) := by
  refine ⟨?_, ?_⟩
  · simpa only [FftMath.size_stage, WideStage.state_length] using hdata.1
  · intro v
    have hv : v.val < s.input.val.length := by simpa only [WideStage.state_length] using v.isLt
    have hn := pairNumber_lt s.half.val v.val s.table.vectors.val h.half_pos h.divides
      (by have := h.input_length; omega)
    have hp := wide_pair_output s h k m hk hm hmode values roots htable hsize hdata hoff hov
      (pairNumber s.half.val v.val) hn
    rw [← getElem!_pos (s.state (s.table.vectors.val / 2) false).val v.val v.isLt,
      s.state_get _ _ _ hv]
    dsimp only
    rw [if_pos hn]
    by_cases hlo : v.val % (2 * s.half.val) < s.half.val
    · rw [if_pos hlo]
      have he := pair_partition_lower s.half.val v.val h.half_pos hlo
      simpa only [← he] using hp.1
    · rw [if_neg hlo]
      have he := pair_partition_upper s.half.val v.val h.half_pos (by omega)
      simpa only [← he] using hp.2

theorem wide_refinement (dit : Bool) (k m : Nat)
    (hk : k ≤ 32) (hm : m ≤ 337) (hmode : dit = false → k = 2 ∧ m = 32)
    (table : fft8.Fft8) (data : Slice fr8.Fr8) (half : Usize)
    (values roots : _root_.Array Fr) (htable : FftInvariant table roots)
    (hsize : values.size=roots.size) (hdata : LazyDataRep k m data values)
    (hhalf : ∃ stage : Nat, half.val=2^stage) (hbound : half.val < table.vectors.val) :
    ∃ out, (if dit then fft8.Fft8.dit_wide table data half else fft8.Fft8.dif_wide table data half) = ok out ∧
      LazyDataRep (if dit then k+2 else 2) (if dit then m+33 else 32) out (butterflyStage dit values roots (8*half.val)) := by
  obtain ⟨offset, hoffset, hoff, hov⟩ := multiple_of_r_refinement 2#u64 (by decide)
  obtain ⟨stage, hhalf⟩ := hhalf
  obtain ⟨hn, hnle, vectorsLog, hvectorsLog⟩ := wide_table_bounds table roots htable
  have hslt : stage < vectorsLog := by
    have hp : 2 ^ stage < 2 ^ vectorsLog := by rw [← hhalf, ← hvectorsLog]; exact hbound
    exact (Nat.pow_lt_pow_iff_right (by decide)).mp hp
  have hd : 2 * half.val ∣ table.vectors.val := by
    rw [hhalf, hvectorsLog, ← pow_succ']
    exact Nat.pow_dvd_pow 2 (Nat.succ_le_of_lt hslt)
  have hlen : data.val.length = table.vectors.val := by
    have h := hdata.1
    rw [hsize, hn] at h
    omega
  let s : WideStage := ⟨dit, table, data, half, offset⟩
  have hvalid : s.Valid := by
    refine ⟨hlen, hnle, ⟨stage, hhalf⟩, hbound, hd, ?_⟩
    change 2 * half.val - 1 ≤ table.wide.val.length
    rw [htable.2.2.1, ← htable.2.1]
    have hdouble : 2 * half.val ≤ table.vectors.val := by
      obtain ⟨q, hq⟩ := hd
      have hhalfpos : 0 < half.val := by rw [hhalf]; exact Nat.two_pow_pos stage
      have hqpos : 0 < q := by nlinarith
      nlinarith
    omega
  refine ⟨s.state (table.vectors.val / 2) false, s.run_refines hvalid hoffset, ?_⟩
  exact wide_state_output s hvalid k m hk hm hmode values roots htable hsize hdata hoff
    (by simpa only [s, UScalar.ofNatCore_val_eq] using hov)

end LeanBlsSimd.Kzg.Extender.Kernel
