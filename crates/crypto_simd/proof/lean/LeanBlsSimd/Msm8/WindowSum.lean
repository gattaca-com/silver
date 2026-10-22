import LeanBlsSimd.Msm8.Lanes
import LeanBlsSimd.Msm8.Store
import LeanBlsSimd.Msm8.Buckets

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.WindowSums
open EthCryptographySpecs.Bls

structure Entry where
  x : Fp8
  y : Fp8
  present : Mmask8

def joinEntry (running : G1x8) (entry : Entry) : G1x8 :=
  G1x8.select entry.present running (running.add_affine_complete entry.x entry.y)

def joinBucket (entries : ℕ → Entry) (count : ℕ) (running : G1x8) : G1x8 :=
  (List.range count).foldl (fun r j => joinEntry r (entries j)) running

def descendingFold {S : Type} (step : ℕ → S → S) : ℕ → S → S
  | 0, state => state
  | n + 1, state => descendingFold step n (step (n + 1) state)

def windowStep (entries : ℕ → ℕ → Entry) (lengths : ℕ → ℕ) (bucket : ℕ)
    (state : G1x8 × G1x8) : G1x8 × G1x8 :=
  let joined := joinBucket (entries bucket) (lengths bucket) state.1
  (joined, state.2.add_complete joined)

def windowSum (entries : ℕ → ℕ → Entry) (lengths : ℕ → ℕ)
    (bucket : ℕ) (running sum : G1x8) : G1x8 :=
  (descendingFold (windowStep entries lengths) bucket (running, sum)).2

theorem windowSum_zero (entries : ℕ → ℕ → Entry) (lengths : ℕ → ℕ) (running sum : G1x8) :
    windowSum entries lengths 0 running sum = sum := rfl

theorem windowSum_succ (entries : ℕ → ℕ → Entry) (lengths : ℕ → ℕ) (bucket : ℕ)
    (running sum : G1x8) :
    windowSum entries lengths (bucket + 1) running sum =
      windowSum entries lengths bucket (joinBucket (entries (bucket + 1)) (lengths (bucket + 1)) running)
        (sum.add_complete (joinBucket (entries (bucket + 1)) (lengths (bucket + 1)) running)) := by
  unfold windowSum
  rw [descendingFold]
  rfl

def EntryRep (entry : Entry) (l : Fin 8) (P : G1.curve.toAffine.Point) : Prop :=
  if entry.present.toNat.testBit l then
    ∃ x y : Fp, entry.x.Holds l x ∧ entry.y.Holds l y ∧
      G1.Valid ⟨x, y, Fp.one⟩ ∧ G1.toPoint ⟨x, y, Fp.one⟩ = P
  else P = 0

theorem joinEntry_correct (running : G1x8) (entry : Entry) (l : Fin 8)
    (P Q : G1.curve.toAffine.Point) (hp : running.PointRep l P) (hq : EntryRep entry l Q) :
    (joinEntry running entry).PointRep l (P + Q) := by
  obtain ⟨p, hp, hvp, hpp⟩ := hp
  by_cases hbit : entry.present.toNat.testBit l = true
  · obtain ⟨x, y, hx, hy, hvq, hqp⟩ := (if_pos hbit).mp hq
    refine ⟨G1.add p ⟨x, y, Fp.one⟩, ?_, G1.valid_add hvp hvq, ?_⟩
    · apply G1x8.select_true_holds _ _ _ _ _ hbit
      exact G1x8.add_affine_complete_correct _ _ _ _ _ _ _ hp hx hy hvp hvq
    · rw [G1.toPoint_add hvp hvq, hpp, hqp]
  · have hzero : Q = 0 := (if_neg hbit).mp hq
    refine ⟨p, ?_, hvp, ?_⟩
    · apply G1x8.select_false_holds _ _ _ _ _ (by simpa using hbit) hp
    · simpa [hzero] using hpp

theorem joinBucket_correct (entries : ℕ → Entry) (count : ℕ) (running : G1x8) (l : Fin 8)
    (P : G1.curve.toAffine.Point) (Q : ℕ → G1.curve.toAffine.Point)
    (hp : running.PointRep l P) (hq : ∀ j, j < count → EntryRep (entries j) l (Q j)) :
    (joinBucket entries count running).PointRep l (P + ∑ j ∈ Finset.range count, Q j) := by
  induction count with
  | zero => simpa [joinBucket] using hp
  | succ n ih =>
    have prev := ih (fun j hj => hq j (by omega))
    have next := joinEntry_correct (joinBucket entries n running) (entries n) l _ _ prev (hq n (by omega))
    simpa only [joinBucket, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      Finset.sum_range_succ, add_assoc] using next

theorem weighted_step {A : Type} [AddCommGroup A] (S R B T : A) (b : ℕ) :
    S + (b + 1) • R + (T + (b + 1) • B) = (S + (R + B)) + b • (R + B) + T := by
  module

theorem windowSum_correct (entries : ℕ → ℕ → Entry) (lengths : ℕ → ℕ)
    (bucket : ℕ) (running sum : G1x8) (l : Fin 8)
    (R S : G1.curve.toAffine.Point) (Q : ℕ → ℕ → G1.curve.toAffine.Point)
    (hr : running.PointRep l R) (hs : sum.PointRep l S)
    (hq : ∀ b, 1 ≤ b → b ≤ bucket → ∀ j, j < lengths b → EntryRep (entries b j) l (Q b j)) :
    (windowSum entries lengths bucket running sum).PointRep l
      (S + bucket • R + ∑ b ∈ Finset.range bucket, (b + 1) • ∑ j ∈ Finset.range (lengths (b + 1)), Q (b + 1) j) := by
  induction bucket generalizing running sum R S with
  | zero =>
    rw [windowSum_zero, Finset.sum_range_zero, zero_nsmul, add_zero, add_zero]
    exact hs
  | succ b ih =>
    have hj := joinBucket_correct (entries (b + 1)) (lengths (b + 1)) running l R (Q (b + 1))
      hr (hq (b + 1) (by omega) (by omega))
    have ht := ih _ _ _ _ hj (hs.add_complete hj) (fun k hk hkb => hq k hk (by omega))
    rw [windowSum_succ, Finset.sum_range_succ, weighted_step]
    exact ht

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums

structure EntryCall (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group bucket cursor : Usize) (entry : Entry) : Prop where
  exists_entry : ∃ raw : msm8.buckets.Entries,
    msm8.buckets.Buckets.entries state group bucket cursor = ok raw ∧
    msm8.store.PointStore.load_signed store raw.indices raw.negated =
      ok (toFp8 entry.x, toFp8 entry.y) ∧ ofU8 raw.present = entry.present

theorem joinBucket_refines (self : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group bucket longest : Usize) (entries : ℕ → Entry)
    (he : ∀ cursor : Usize, cursor.val < longest.val → EntryCall self store group bucket cursor (entries cursor.val))
    (running : G1x8) :
    msm8.buckets.Buckets.window_sums_loop0_loop0 self.window_bits self.windows self.refs
      self.starts self.lens store group (toG1x8 running) bucket longest 0#usize =
      ok (toG1x8 (joinBucket entries longest.val running)) := by
  let body := fun p : g1x8.G1x8 × Usize =>
    msm8.buckets.Buckets.window_sums_loop0_loop0.body self.window_bits self.windows self.refs
      self.starts self.lens store group bucket longest p.1 p.2
  have hd (r : G1x8) (c : Usize) (hc : c.val = longest.val) (_ : True) :
      body (toG1x8 r, c) = ok (done (toG1x8 r)) := by
    simp [body, msm8.buckets.Buckets.window_sums_loop0_loop0.body, UScalar.lt_equiv, hc]
  have hs (r : G1x8) (c : Usize) (j : Fin longest.val) (hc : c.val = j.val) (_ : True) :
      ∃ next, next.val = j.val + 1 ∧ body (toG1x8 r, c) =
        ok (cont (toG1x8 (joinEntry r (entries j.val)), next)) := by
    have hl : c.val < longest.val := by omega
    obtain ⟨raw, hraw, hload, hmask⟩ := (he c hl).exists_entry
    have hadd : c.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
      have := longest.hBounds
      change c.val + 1 < _
      omega
    refine ⟨UScalar.ofNatCore (c.val + 1) hadd, by simp [hc], ?_⟩
    simp only [body, msm8.buckets.Buckets.window_sums_loop0_loop0.body,
      UScalar.lt_equiv, hl, if_true, hraw, bind_tc_ok, hload,
      G1x8.add_affine_complete_refines, G1x8.select_refines, ofG1x8_toG1x8]
    rw [add_ok _ _ hadd]
    simp only [bind_tc_ok, hmask, hc, joinEntry, UScalar.ofNatCore_val_eq]
    change ok (cont (toG1x8 (G1x8.select (entries j.val).present r
      (r.add_affine_complete (ofFp8 (toFp8 (entries j.val).x)) (ofFp8 (toFp8 (entries j.val).y)))),
      UScalar.ofNatCore (j.val + 1) _)) = _
    rw [ofFp8_toFp8, ofFp8_toFp8]
  have hloop := loop_up_inv body (fun r c => (toG1x8 r, c))
    (fun r (j : Fin longest.val) => joinEntry r (entries j.val)) toG1x8 (fun _ => True)
    (by intros; trivial) hd hs running 0#usize (by simp) trivial
  have hf : (List.finRange longest.val).foldl (fun r j => joinEntry r (entries j.val)) running =
      joinBucket entries longest.val running := by
    unfold joinBucket
    rw [← List.map_coe_finRange_eq_range, List.foldl_map]
  simpa only [msm8.buckets.Buckets.window_sums_loop0_loop0, body, UScalar.ofNatCore_val_eq,
    List.drop_zero, hf] using hloop

structure WindowCalls (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : Usize) (maximum : ℕ) (entries : ℕ → ℕ → Entry) (lengths : ℕ → Usize) : Prop where
  longest : ∀ bucket : Usize, 0 < bucket.val → bucket.val ≤ maximum →
    msm8.buckets.Buckets.longest state group bucket = ok (lengths bucket.val)
  entries : ∀ bucket : Usize, 0 < bucket.val → bucket.val ≤ maximum → ∀ cursor : Usize,
    cursor.val < (lengths bucket.val).val →
      EntryCall state store group bucket cursor (entries bucket.val cursor.val)

theorem windowSum_loop_refines (self : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group bucket : Usize) (entries : ℕ → ℕ → Entry) (lengths : ℕ → Usize)
    (hc : WindowCalls self store group bucket.val entries lengths) (running sum : G1x8) :
    msm8.buckets.Buckets.window_sums_loop0 self.window_bits self.windows self.refs self.starts
      self.lens store group (toG1x8 running) (toG1x8 sum) bucket =
      ok (toG1x8 (windowSum entries (fun b => (lengths b).val) bucket.val running sum)) := by
  induction hb : bucket.val generalizing bucket running sum with
  | zero =>
    unfold msm8.buckets.Buckets.window_sums_loop0
    rw [loop.eq_1]
    simp only [msm8.buckets.Buckets.window_sums_loop0.body, UScalar.lt_equiv, hb,
      UScalar.ofNatCore_val_eq, Nat.lt_irrefl, if_false, windowSum_zero]
  | succ b ih =>
    have hpos : 0 < bucket.val := by omega
    have hlong := hc.longest bucket hpos (by omega)
    have hjoin := joinBucket_refines self store group bucket (lengths bucket.val) (entries bucket.val)
      (hc.entries bucket hpos (by omega)) running
    let next : Usize := UScalar.ofNatCore (bucket.val - 1) (by have := bucket.hBounds; omega)
    have hnext : next.val = b := by simp [next]; omega
    have hc' : WindowCalls self store group next.val entries lengths := by
      constructor
      · intro k hk hkb; exact hc.longest k hk (by omega)
      · intro k hk hkb; exact hc.entries k hk (by omega)
    have htail := ih next hc' (joinBucket (entries bucket.val) (lengths bucket.val).val running)
      (sum.add_complete (joinBucket (entries bucket.val) (lengths bucket.val).val running)) hnext
    have hbody : msm8.buckets.Buckets.window_sums_loop0.body self.window_bits self.windows
        self.refs self.starts self.lens store group (toG1x8 running) (toG1x8 sum) bucket =
        ok (cont (toG1x8 (joinBucket (entries bucket.val) (lengths bucket.val).val running),
          toG1x8 (sum.add_complete (joinBucket (entries bucket.val) (lengths bucket.val).val running)), next)) := by
      simp only [msm8.buckets.Buckets.window_sums_loop0.body, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, hpos, if_true, hlong, bind_tc_ok, hjoin,
        G1x8.add_complete_refines, ofG1x8_toG1x8]
      rw [sub_ok bucket 1#usize (by change 1 ≤ bucket.val; omega)]
      rfl
    unfold msm8.buckets.Buckets.window_sums_loop0
    change loop (fun p => msm8.buckets.Buckets.window_sums_loop0.body self.window_bits self.windows
      self.refs self.starts self.lens store group p.1 p.2.1 p.2.2)
      (toG1x8 running, toG1x8 sum, bucket) = _
    rw [loop.eq_1, hbody]
    change msm8.buckets.Buckets.window_sums_loop0 self.window_bits self.windows self.refs self.starts
      self.lens store group _ _ next = _
    rw [htail, hb, windowSum_succ]

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open EthCryptographySpecs.Bls

theorem bucketCount_refines (bits : Usize) (hlo : 1 ≤ bits.val) (hhi : bits.val ≤ 8) :
    ∃ maximum : Usize, maximum.val = 2 ^ (bits.val - 1) ∧
      (do let shift ← bits - 1#usize; 1#usize <<< shift) = ok maximum := by
  have hsmall : 2 ^ (bits.val - 1) < 2 ^ UScalarTy.Usize.numBits := by
    have h := Nat.pow_le_pow_right (by decide : 0 < (2 : ℕ)) (show bits.val - 1 ≤ 7 by omega)
    have := two_pow_32_le_usize
    norm_num at h
    omega
  let maximum : Usize := UScalar.ofNatCore (2 ^ (bits.val - 1)) hsmall
  refine ⟨maximum, by simp [maximum], ?_⟩
  rw [sub_ok bits 1#usize hlo]
  simp only [bind_tc_ok]
  rw [shiftLeft_ok _ _ (by
    have h : 32 ≤ UScalarTy.Usize.numBits := by
      rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
    simp only [UScalar.ofNatCore_val_eq]
    change bits.val - 1 < _
    omega)]
  congr 1
  apply UScalar.eq_of_val_eq
  change (BitVec.shiftLeft _ (bits.val - 1)).toNat = 2 ^ (bits.val - 1)
  rw [show (BitVec.shiftLeft (1#usize).bv (bits.val - 1)).toNat =
    ((1#usize).bv.toNat <<< (bits.val - 1)) % 2 ^ UScalarTy.Usize.numBits from BitVec.toNat_shiftLeft]
  change (1 <<< (bits.val - 1)) % 2 ^ UScalarTy.Usize.numBits = _
  rw [Nat.shiftLeft_eq, Nat.one_mul, Nat.mod_eq_of_lt hsmall]

theorem infinity_pointRep (l : Fin 8) : G1x8.infinity.PointRep l 0 :=
  ⟨G1.zero, G1x8.infinity_holds l, G1.valid_zero, G1.toPoint_zero⟩

theorem window_sums_refines (self : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : Usize) (entries : ℕ → ℕ → Entry) (lengths : ℕ → Usize)
    (hlo : 1 ≤ self.window_bits.val) (hhi : self.window_bits.val ≤ 8)
    (hc : WindowCalls self store group (2 ^ (self.window_bits.val - 1)) entries lengths) :
    msm8.buckets.Buckets.window_sums self store group =
      ok (toG1x8 (windowSum entries (fun b => (lengths b).val)
        (2 ^ (self.window_bits.val - 1)) G1x8.infinity G1x8.infinity)) := by
  obtain ⟨maximum, hm, hinit⟩ := bucketCount_refines self.window_bits hlo hhi
  have hc' : WindowCalls self store group maximum.val entries lengths := hm.symm ▸ hc
  have hloop := windowSum_loop_refines self store group maximum entries lengths hc' G1x8.infinity G1x8.infinity
  simp only [msm8.buckets.Buckets.window_sums, G1x8.infinity_refines, bind_tc_ok]
  rw [← bind_assoc_eq, hinit]
  simpa only [bind_tc_ok, hm] using hloop

theorem window_sums_correct (self : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : Usize) (entries : ℕ → ℕ → Entry) (lengths : ℕ → Usize)
    (hlo : 1 ≤ self.window_bits.val) (hhi : self.window_bits.val ≤ 8)
    (hc : WindowCalls self store group (2 ^ (self.window_bits.val - 1)) entries lengths)
    (Q : ℕ → ℕ → Fin 8 → G1.curve.toAffine.Point)
    (hq : ∀ b, 1 ≤ b → b ≤ 2 ^ (self.window_bits.val - 1) →
      ∀ j, j < (lengths b).val → ∀ l, EntryRep (entries b j) l (Q b j l)) :
    ∃ out, msm8.buckets.Buckets.window_sums self store group = ok (toG1x8 out) ∧
      ∀ l, out.PointRep l (∑ b ∈ Finset.range (2 ^ (self.window_bits.val - 1)),
        (b + 1) • ∑ j ∈ Finset.range (lengths (b + 1)).val, Q (b + 1) j l) := by
  refine ⟨_, window_sums_refines self store group entries lengths hlo hhi hc, ?_⟩
  intro l
  have h := windowSum_correct entries (fun b => (lengths b).val) _ G1x8.infinity G1x8.infinity
    l 0 0 (fun b j => Q b j l) (infinity_pointRep l) (infinity_pointRep l)
    (fun b hb hbm j hj => hq b hb hbm j hj l)
  simpa only [nsmul_zero, zero_add] using h

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open EthCryptographySpecs.Bls

def groupStep (vectors : ℕ → G1x8) (bits group : ℕ) (total : G1x8) : G1x8 :=
  (total.times_two_pow (8 * bits)).add_complete (vectors (group - 1))

def groupSum (vectors : ℕ → G1x8) (bits group : ℕ) (total : G1x8) : G1x8 :=
  descendingFold (groupStep vectors bits) group total

theorem groupSum_zero (vectors : ℕ → G1x8) (bits : ℕ) (total : G1x8) :
    groupSum vectors bits 0 total = total := rfl

theorem groupSum_succ (vectors : ℕ → G1x8) (bits group : ℕ) (total : G1x8) :
    groupSum vectors bits (group + 1) total =
      groupSum vectors bits group ((total.times_two_pow (8 * bits)).add_complete (vectors group)) := by
  unfold groupSum
  rw [descendingFold]
  simp only [groupStep, Nat.add_sub_cancel]

theorem horner_step {A : Type} [AddCommGroup A] (T B S : A) (b k : ℕ) :
    2 ^ ((b + 1) * k) • T + (S + 2 ^ (b * k) • B) =
      2 ^ (b * k) • (2 ^ k • T + B) + S := by
  rw [Nat.add_mul, Nat.one_mul, pow_add, mul_nsmul, nsmul_add]
  rw [smul_comm (2 ^ k) (2 ^ (b * k)) T]
  abel

theorem groupSum_correct (vectors : ℕ → G1x8) (bits group : ℕ) (total : G1x8)
    (l : Fin 8) (T : G1.curve.toAffine.Point) (Q : ℕ → G1.curve.toAffine.Point)
    (ht : total.PointRep l T) (hq : ∀ g, g < group → (vectors g).PointRep l (Q g)) :
    (groupSum vectors bits group total).PointRep l
      (2 ^ (group * (8 * bits)) • T + ∑ g ∈ Finset.range group, 2 ^ (g * (8 * bits)) • Q g) := by
  induction group generalizing total T with
  | zero => simpa only [groupSum_zero, Nat.zero_mul, pow_zero, one_nsmul, Finset.sum_range_zero, add_zero] using ht
  | succ g ih =>
    have next := (ht.times_two_pow (8 * bits)).add_complete (hq g (by omega))
    have h := ih _ _ next (fun k hk => hq k (by omega))
    rw [groupSum_succ, Finset.sum_range_succ, horner_step]
    exact h

theorem bucketSum_correct (vectors : ℕ → G1x8) (bits top : ℕ)
    (Q : ℕ → Fin 8 → G1.curve.toAffine.Point)
    (hq : ∀ g, g ≤ top → ∀ l, (vectors g).PointRep l (Q g l)) :
    ((groupSum vectors bits top (vectors top)).sum_lanes_shifted bits).PointRep 0
      (∑ l : Fin 8, 2 ^ (l.val * bits) •
        ∑ g ∈ Finset.range (top + 1), 2 ^ (g * (8 * bits)) • Q g l) := by
  apply G1x8.sum_lanes_shifted_correct
  intro l
  have h := groupSum_correct vectors bits top (vectors top) l (Q top l) (fun g => Q g l)
    (hq top (by omega) l) (fun g hg => hq g (by omega) l)
  rw [Finset.sum_range_succ, add_comm]
  exact h

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open EthCryptographySpecs.Bls

theorem groupSum_refines (self : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : Usize) (total : G1x8) (vectors : ℕ → G1x8) (hbits : self.window_bits.val ≤ 255)
    (hw : ∀ g : Usize, g.val < group.val →
      msm8.buckets.Buckets.window_sums self store g = ok (toG1x8 (vectors g.val))) :
    msm8.buckets.Buckets.sum_loop self.window_bits self.windows self.refs self.starts self.lens
      store group (toG1x8 total) = ok (toG1x8 (groupSum vectors self.window_bits.val group.val total)) := by
  induction hg : group.val generalizing group total with
  | zero =>
    unfold msm8.buckets.Buckets.sum_loop
    rw [loop.eq_1]
    simp only [msm8.buckets.Buckets.sum_loop.body, UScalar.lt_equiv, hg,
      UScalar.ofNatCore_val_eq, Nat.lt_irrefl, if_false, groupSum_zero]
  | succ g ih =>
    have hpos : 0 < group.val := by omega
    let next : Usize := UScalar.ofNatCore (group.val - 1) (by have := group.hBounds; omega)
    have hn : next.val = g := by simp [next]; omega
    have hwindow := hw next (by omega)
    have hmul : (8#usize).val * self.window_bits.val < 2 ^ UScalarTy.Usize.numBits := by
      have := two_pow_32_le_usize
      change 8 * self.window_bits.val < _
      omega
    have hbody : msm8.buckets.Buckets.sum_loop.body self.window_bits self.windows self.refs
        self.starts self.lens store group (toG1x8 total) =
        ok (cont (next, toG1x8 ((total.times_two_pow (8 * self.window_bits.val)).add_complete (vectors next.val)))) := by
      simp only [msm8.buckets.Buckets.sum_loop.body, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
        hpos, if_true, fp8.LANES]
      rw [sub_ok group 1#usize (by change 1 ≤ group.val; omega)]
      simp only [bind_tc_ok]
      rw [mul_ok _ _ hmul]
      simp only [bind_tc_ok, G1x8.times_two_pow_refines, ofG1x8_toG1x8, UScalar.ofNatCore_val_eq]
      change (do
        let window ← msm8.buckets.Buckets.window_sums self store next
        g1x8.G1x8.add_complete (toG1x8 (total.times_two_pow (8 * self.window_bits.val))) window >>= fun v =>
          ok (cont (next, v))) = _
      rw [hwindow]
      simp only [bind_tc_ok, G1x8.add_complete_refines, ofG1x8_toG1x8]
    have htail := ih next ((total.times_two_pow (8 * self.window_bits.val)).add_complete (vectors next.val))
      (fun k hk => hw k (by omega)) hn
    unfold msm8.buckets.Buckets.sum_loop
    change loop (fun p => msm8.buckets.Buckets.sum_loop.body self.window_bits self.windows self.refs
      self.starts self.lens store p.1 p.2) (group, toG1x8 total) = _
    rw [loop.eq_1, hbody]
    change msm8.buckets.Buckets.sum_loop self.window_bits self.windows self.refs self.starts self.lens
      store next _ = _
    rw [htail, hn, groupSum_succ]

theorem topGroup_refines (windows : Usize) (hw : 1 ≤ windows.val) :
    ∃ group : Usize, group.val = (windows.val - 1) / 8 ∧
      (do
        let n ← windows - 1#usize
        let q ← n / 8#usize
        let groups ← q + 1#usize
        groups - 1#usize) = ok group := by
  have hq : (windows.val - 1) / 8 + 1 < 2 ^ UScalarTy.Usize.numBits := by
    have := windows.hBounds
    omega
  let group : Usize := UScalar.ofNatCore ((windows.val - 1) / 8) (by omega)
  refine ⟨group, by simp [group], ?_⟩
  rw [sub_ok windows 1#usize hw]
  simp only [bind_tc_ok]
  rw [div_ok _ 8#usize (by decide)]
  simp only [bind_tc_ok]
  rw [add_ok _ 1#usize (by simpa only [UScalar.ofNatCore_val_eq] using hq)]
  simp only [bind_tc_ok]
  rw [sub_ok _ 1#usize (by simp only [UScalar.ofNatCore_val_eq]; omega)]
  congr 1

theorem buckets_sum_refines (self : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (vectors : ℕ → G1x8) (hbits : self.window_bits.val ≤ 255) (hwin : 1 ≤ self.windows.val)
    (hw : ∀ g : Usize, g.val ≤ (self.windows.val - 1) / 8 →
      msm8.buckets.Buckets.window_sums self store g = ok (toG1x8 (vectors g.val))) :
    msm8.buckets.Buckets.sum self store =
      ok (toG1x8 ((groupSum vectors self.window_bits.val ((self.windows.val - 1) / 8)
        (vectors ((self.windows.val - 1) / 8))).sum_lanes_shifted self.window_bits.val)) := by
  obtain ⟨group, hg, hinit⟩ := topGroup_refines self.windows hwin
  have hwindow := hw group (by omega)
  have hloop := groupSum_refines self store group (vectors group.val) vectors hbits (fun g h => hw g (by omega))
  simp only [msm8.buckets.Buckets.sum, fp8.LANES]
  rw [← bind_assoc_eq, ← bind_assoc_eq] at hinit
  rw [← bind_assoc_eq, ← bind_assoc_eq, ← bind_assoc_eq, hinit]
  simp only [bind_tc_ok, hwindow]
  rw [hloop]
  simp only [bind_tc_ok, G1x8.sum_lanes_shifted_refines _ _ hbits, ofG1x8_toG1x8, hg]

theorem buckets_sum_correct (self : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (vectors : ℕ → G1x8) (hbits : self.window_bits.val ≤ 255) (hwin : 1 ≤ self.windows.val)
    (hw : ∀ g : Usize, g.val ≤ (self.windows.val - 1) / 8 →
      msm8.buckets.Buckets.window_sums self store g = ok (toG1x8 (vectors g.val)))
    (Q : ℕ → Fin 8 → G1.curve.toAffine.Point)
    (hq : ∀ g, g ≤ (self.windows.val - 1) / 8 → ∀ l, (vectors g).PointRep l (Q g l)) :
    ∃ out, msm8.buckets.Buckets.sum self store = ok (toG1x8 out) ∧
      out.PointRep 0 (∑ l : Fin 8, 2 ^ (l.val * self.window_bits.val) •
        ∑ g ∈ Finset.range ((self.windows.val - 1) / 8 + 1),
          2 ^ (g * (8 * self.window_bits.val)) • Q g l) :=
  ⟨_, buckets_sum_refines self store vectors hbits hwin hw, bucketSum_correct vectors _ _ Q hq⟩

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open BucketsRefines

def bucketLength (state : msm8.buckets.Buckets) (window bucket : ℕ) : U32 :=
  if window < state.windows.val then
    state.lens.val[listIndex state.window_bits.val window bucket]!
  else 0#u32

structure BucketShape (state : msm8.buckets.Buckets) : Prop where
  width_lower : 1 ≤ state.window_bits.val
  width_upper : state.window_bits.val ≤ 8
  total_bound : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32
  lengths_bound : state.windows.val * 2 ^ (state.window_bits.val - 1) ≤ state.lens.val.length
  starts_bound : state.windows.val * 2 ^ (state.window_bits.val - 1) ≤ state.starts.val.length
  refs_bound : ∀ i, i < state.windows.val * 2 ^ (state.window_bits.val - 1) →
    state.starts.val[i]!.val + state.lens.val[i]!.val ≤ state.refs.val.length

theorem len_refines (state : msm8.buckets.Buckets) (window bucket : Usize)
    (hshape : BucketShape state) (hb : 1 ≤ bucket.val)
    (hbmax : bucket.val ≤ 2 ^ (state.window_bits.val - 1)) :
    msm8.buckets.Buckets.len state window bucket =
      ok (UScalar.cast .Usize (bucketLength state window.val bucket.val)) := by
  by_cases hw : window.val < state.windows.val
  · have hmul : (window.val + 1) * 2 ^ (state.window_bits.val - 1) ≤
        state.windows.val * 2 ^ (state.window_bits.val - 1) :=
      Nat.mul_le_mul_right _ (by omega)
    obtain ⟨index, hindex, hiv⟩ := list_refines state window bucket hshape.width_lower hshape.width_upper
      hb hbmax (by have := hshape.total_bound; omega)
    have hil : index.val < state.lens.val.length := by
      have := hshape.lengths_bound
      unfold listIndex at hiv
      rw [Nat.add_mul, Nat.one_mul] at hmul
      omega
    simp only [msm8.buckets.Buckets.len, UScalar.lt_equiv, hw, if_true, hindex, bind_tc_ok,
      vec_index_eq _ _ hil, bucketLength]
    simp only [← hiv, getElem!_pos state.lens.val index.val hil]
  · simp only [msm8.buckets.Buckets.len, UScalar.lt_equiv, hw, if_false, bucketLength]
    congr 1
    apply UScalar.eq_of_val_eq
    simp only [UScalar.ofNatCore_val_eq, cast_Usize_val]

def maxScalar (a b : Usize) : Usize := if a < b then b else a

def longestModel (state : msm8.buckets.Buckets) (group bucket : ℕ) : Usize :=
  (List.finRange 8).foldl (fun longest l => maxScalar longest
    (UScalar.cast .Usize (bucketLength state (group * 8 + l.val) bucket))) 0#usize

theorem longest_refines (state : msm8.buckets.Buckets) (group bucket : Usize)
    (hshape : BucketShape state) (hb : 1 ≤ bucket.val)
    (hbmax : bucket.val ≤ 2 ^ (state.window_bits.val - 1))
    (hg : group.val * 8 + 7 < 2 ^ UScalarTy.Usize.numBits) :
    msm8.buckets.Buckets.longest state group bucket = ok (longestModel state group.val bucket.val) := by
  let body := fun p : Usize × Usize => msm8.buckets.Buckets.longest_loop.body state group bucket p.1 p.2
  let step := fun (m : Usize) (l : Fin 8) => maxScalar m
    (UScalar.cast .Usize (bucketLength state (group.val * 8 + l.val) bucket.val))
  have hd (m c : Usize) (hc : c.val = 8) (_ : True) : body (m,c) = ok (done m) := by
    simp [body, msm8.buckets.Buckets.longest_loop.body, fp8.LANES, UScalar.lt_equiv, hc]
  have hs (m c : Usize) (l : Fin 8) (hc : c.val = l.val) (_ : True) :
      ∃ next, next.val = l.val + 1 ∧ body (m,c) = ok (cont (step m l,next)) := by
    have hl : c.val < 8 := by omega
    have hmul : group.val * (8#usize).val < 2 ^ UScalarTy.Usize.numBits := by change group.val * 8 < _; omega
    have hadd : group.val * 8 + c.val < 2 ^ UScalarTy.Usize.numBits := by omega
    let window : Usize := UScalar.ofNatCore (group.val * 8 + c.val) hadd
    have hwindow : (do let g ← group * 8#usize; g + c) = ok window := by
      rw [mul_ok _ _ hmul]
      simp only [bind_tc_ok]
      rw [add_ok _ _ (by simpa only [UScalar.ofNatCore_val_eq] using hadd)]
      rfl
    have hnext : c.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := two_pow_32_le_usize
      omega
    refine ⟨UScalar.ofNatCore (c.val + 1) hnext, by simp [hc], ?_⟩
    simp only [body, msm8.buckets.Buckets.longest_loop.body, fp8.LANES, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
      hl, if_true]
    rw [← bind_assoc_eq, hwindow]
    simp only [bind_tc_ok, len_refines state window bucket hshape hb hbmax]
    split <;> simp only [bind_tc_ok] <;> rw [add_ok _ _ hnext] <;>
      simp_all only [bind_tc_ok, step, maxScalar, UScalar.lt_equiv, window, UScalar.ofNatCore_val_eq, if_true, if_false]
  have h := loop_up_inv body (fun m c => (m,c)) step id (fun _ => True) (by intros; trivial)
    hd hs 0#usize 0#usize (by simp) trivial
  simpa only [msm8.buckets.Buckets.longest, msm8.buckets.Buckets.longest_loop, body,
    UScalar.ofNatCore_val_eq, List.drop_zero, id_eq, longestModel, step] using h

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open BucketsRefines

def referenceAt (state : msm8.buckets.Buckets) (window bucket cursor : ℕ) : U32 :=
  if cursor < (bucketLength state window bucket).val then
    state.refs.val[state.starts.val[listIndex state.window_bits.val window bucket]!.val + cursor]!
  else 0#u32

theorem reference_branch_refines (state : msm8.buckets.Buckets) (window bucket cursor : Usize)
    (hshape : BucketShape state) (hb : 1 ≤ bucket.val)
    (hbmax : bucket.val ≤ 2 ^ (state.window_bits.val - 1)) :
    (if cursor < UScalar.cast .Usize (bucketLength state window.val bucket.val) then do
      let index ← msm8.buckets.Buckets.list state window bucket
      let start ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice U32) state.starts index
      let offset ← lift (UScalar.cast .Usize start)
      let at1 ← offset + cursor
      let reference ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice U32) state.refs at1
      ok (state, true, reference)
    else ok (state, false, 0#u32)) =
      ok (state, decide (cursor.val < (bucketLength state window.val bucket.val).val),
        referenceAt state window.val bucket.val cursor.val) := by
  simp only [UScalar.lt_equiv, cast_Usize_val]
  by_cases here : cursor.val < (bucketLength state window.val bucket.val).val
  · have hw : window.val < state.windows.val := by
      by_contra h
      simp only [bucketLength, h, if_false, UScalar.ofNatCore_val_eq] at here
      omega
    have hmul : (window.val + 1) * 2 ^ (state.window_bits.val - 1) ≤
        state.windows.val * 2 ^ (state.window_bits.val - 1) := Nat.mul_le_mul_right _ (by omega)
    obtain ⟨index, hindex, hiv⟩ := list_refines state window bucket hshape.width_lower hshape.width_upper
      hb hbmax (by have := hshape.total_bound; omega)
    have hin : index.val < state.windows.val * 2 ^ (state.window_bits.val - 1) := by
      unfold listIndex at hiv
      rw [Nat.add_mul, Nat.one_mul] at hmul
      omega
    have hist : index.val < state.starts.val.length := by have := hshape.starts_bound; omega
    have hlen : (bucketLength state window.val bucket.val).val = state.lens.val[index.val]!.val := by
      simp only [bucketLength, hw, if_true, hiv]
    have hstart : state.starts.val[index.val] = state.starts.val[index.val]! :=
      (getElem!_pos state.starts.val index.val hist).symm
    have hbounds : state.starts.val[index.val].val + cursor.val < state.refs.val.length := by
      have := hshape.refs_bound index.val hin
      rw [hstart]
      omega
    have hadd : (UScalar.cast .Usize state.starts.val[index.val]).val + cursor.val <
        2 ^ UScalarTy.Usize.numBits := by
      rw [cast_Usize_val]
      exact lt_trans hbounds (vec_length_bound state.refs)
    simp only [here, if_true, decide_true, hindex, bind_tc_ok, vec_index_eq _ _ hist, lift]
    rw [add_ok _ _ hadd]
    simp only [bind_tc_ok, vec_index_eq state.refs (UScalar.ofNatCore _ hadd) (by simpa only [UScalar.ofNatCore_val_eq, cast_Usize_val] using hbounds)]
    simp only [referenceAt, here, if_true]
    simp only [UScalar.ofNatCore_val_eq, cast_Usize_val, ← hiv, ← hstart,
      getElem!_pos state.refs.val (state.starts.val[index.val].val + cursor.val) hbounds]
  · simp only [here, if_false, decide_false, referenceAt]

structure EntryAccumulator where
  indices : Vector U32 8
  present : U8
  negated : U8

def encodeEntries (entry : EntryAccumulator) : msm8.buckets.Entries :=
  ⟨toArray id entry.indices, entry.present, entry.negated⟩

def emptyEntries : EntryAccumulator := ⟨Vector.replicate 8 0#u32, 0#u8, 0#u8⟩

def clearSign (reference : U32) : U32 := reference &&& 2147483647#u32

def referenceSign (reference : U32) : U8 := UScalar.cast .U8 (⟨reference.bv.ushiftRight 31⟩ : U32)

def entriesStep (state : msm8.buckets.Buckets) (group bucket cursor : ℕ)
    (entry : EntryAccumulator) (lane : Fin 8) : EntryAccumulator :=
  let window := group * 8 + lane.val
  let reference := referenceAt state window bucket cursor
  let here := decide (cursor < (bucketLength state window bucket).val)
  ⟨entry.indices.set lane (clearSign reference),
   entry.present ||| ⟨(UScalar.cast_fromBool .U8 here).bv.shiftLeft lane.val⟩,
   entry.negated ||| ⟨(referenceSign reference).bv.shiftLeft lane.val⟩⟩

def entriesModel (state : msm8.buckets.Buckets) (group bucket cursor : ℕ) : EntryAccumulator :=
  (List.finRange 8).foldl (entriesStep state group bucket cursor) emptyEntries

end LeanBlsSimd.WindowSums

namespace LeanBlsSimd.WindowSums

theorem entries_body (state : msm8.buckets.Buckets) (group bucket cursor lane : Usize)
    (hshape : BucketShape state) (hb : 1 ≤ bucket.val)
    (hbmax : bucket.val ≤ 2 ^ (state.window_bits.val - 1))
    (hg : group.val * 8 + 7 < 2 ^ UScalarTy.Usize.numBits)
    (entry : EntryAccumulator) (l : Fin 8) (hl : lane.val = l.val) :
    ∃ next, next.val = l.val + 1 ∧
      msm8.buckets.Buckets.entries_loop.body group bucket cursor state
        (toArray id entry.indices) entry.present entry.negated lane =
      ok (cont (state, (encodeEntries (entriesStep state group.val bucket.val cursor.val entry l)).indices,
        (entriesStep state group.val bucket.val cursor.val entry l).present,
        (entriesStep state group.val bucket.val cursor.val entry l).negated, next)) := by
  have hlt : lane.val < 8 := by omega
  have hmul : group.val * (8#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    change group.val * 8 < _
    omega
  have hadd : group.val * 8 + lane.val < 2 ^ UScalarTy.Usize.numBits := by omega
  let window : Usize := UScalar.ofNatCore (group.val * 8 + lane.val) hadd
  have hwindow : (do let g ← group * 8#usize; g + lane) = ok window := by
    rw [mul_ok _ _ hmul]
    simp only [bind_tc_ok]
    rw [add_ok _ _ (by simpa only [UScalar.ofNatCore_val_eq] using hadd)]
    rfl
  have hnext : lane.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    omega
  have hmask : msm8.pairs.NEGATED = ok 2147483648#u32 := by unfold msm8.pairs.NEGATED; rfl
  have hshift (r : U32) : r >>> 31#i32 = ok (⟨r.bv.ushiftRight 31⟩ : U32) := rfl
  refine ⟨UScalar.ofNatCore (lane.val + 1) hnext, by simp [hl], ?_⟩
  simp only [msm8.buckets.Buckets.entries_loop.body, fp8.LANES, UScalar.lt_equiv,
    UScalar.ofNatCore_val_eq, hlt, if_true]
  rw [← bind_assoc_eq, hwindow]
  simp only [bind_tc_ok, len_refines state window bucket hshape hb hbmax]
  have href := reference_branch_refines state window bucket cursor hshape hb hbmax
  simp only [UScalar.lt_equiv] at href
  rw [href]
  simp only [bind_tc_ok, hmask, lift, show (~~~2147483648#u32) = 2147483647#u32 from rfl,
    ]
  change (do
    let a1 ← (toArray (n := 8#usize) id entry.indices).update lane
      (referenceAt state window.val bucket.val cursor.val &&& 2147483647#u32)
    let i8 ← UScalar.cast_fromBool .U8 (decide (cursor.val < (bucketLength state window.val bucket.val).val)) <<< lane
    let i10 ← referenceAt state window.val bucket.val cursor.val >>> 31#i32
    let i12 ← UScalar.cast .U8 i10 <<< lane
    let next ← lane + 1#usize
    ok (cont (state, a1, entry.present ||| i8, entry.negated ||| i12, next))) = _
  rw [update_eq (toArray (n := 8#usize) id entry.indices) lane _ hlt]
  simp only [bind_tc_ok]
  rw [shiftLeft_ok _ lane (by change lane.val < 8; exact hlt)]
  simp only [bind_tc_ok, hshift]
  rw [shiftLeft_ok _ lane (by change lane.val < 8; exact hlt)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ hnext]
  simp only [bind_tc_ok, entriesStep, encodeEntries, window, UScalar.ofNatCore_val_eq, hl,
    clearSign, referenceSign]
  rw [toArray_set_of_eq (n := 8#usize) id entry.indices rfl lane l.val l.isLt
    (referenceAt state (group.val * 8 + l.val) bucket.val cursor.val &&& 2147483647#u32)
    (referenceAt state (group.val * 8 + l.val) bucket.val cursor.val &&& 2147483647#u32) hl rfl]
  rfl

theorem entries_refines (state : msm8.buckets.Buckets) (group bucket cursor : Usize)
    (hshape : BucketShape state) (hb : 1 ≤ bucket.val)
    (hbmax : bucket.val ≤ 2 ^ (state.window_bits.val - 1))
    (hg : group.val * 8 + 7 < 2 ^ UScalarTy.Usize.numBits) :
    msm8.buckets.Buckets.entries state group bucket cursor =
      ok (encodeEntries (entriesModel state group.val bucket.val cursor.val)) := by
  let enc := fun (e : EntryAccumulator) (c : Usize) =>
    (state, toArray (n := 8#usize) id e.indices, e.present, e.negated, c)
  let body := fun p : msm8.buckets.Buckets × Std.Array U32 8#usize × U8 × U8 × Usize => msm8.buckets.Buckets.entries_loop.body group bucket cursor
    p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
  let finish := fun e : EntryAccumulator => (toArray (n := 8#usize) id e.indices,e.present,e.negated)
  have h := loop_up_inv (n := 8) body enc (entriesStep state group.val bucket.val cursor.val)
    finish (fun _ => True) (by intros; trivial)
    (fun e c hc _ => by
      simp [body, enc, finish, msm8.buckets.Buckets.entries_loop.body, fp8.LANES, UScalar.lt_equiv, hc])
    (fun e c l hl _ => entries_body state group bucket cursor c hshape hb hbmax hg e l hl)
    emptyEntries 0#usize (by simp) trivial
  simp only [msm8.buckets.Buckets.entries, msm8.buckets.Buckets.entries_loop]
  change (do
    let result ← loop body (enc emptyEntries 0#usize)
    ok ({ indices := result.1, present := result.2.1, negated := result.2.2 } : msm8.buckets.Entries)) = _
  rw [h]
  rfl

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open EthCryptographySpecs.Bls

def loadedEntry (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group bucket cursor : ℕ) : Entry :=
  let raw := encodeEntries (entriesModel state group bucket cursor)
  ⟨loadedCoordinate store raw.indices 0,
    Fp8.select (ofU8 raw.negated) (loadedCoordinate store raw.indices 1)
      (loadedCoordinate store raw.indices 1).neg,
    ofU8 raw.present⟩

def GroupLoads (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : ℕ) : Prop :=
  ∀ b, 1 ≤ b → b ≤ 2 ^ (state.window_bits.val - 1) →
    ∀ j, j < (longestModel state group b).val →
      indicesInBounds store (encodeEntries (entriesModel state group b j)).indices

theorem concrete_windowCalls (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : Usize) (hshape : BucketShape state)
    (hg : group.val * 8 + 7 < 2 ^ UScalarTy.Usize.numBits)
    (hload : GroupLoads state store group.val) :
    WindowCalls state store group (2 ^ (state.window_bits.val - 1))
      (loadedEntry state store group.val) (longestModel state group.val) := by
  constructor
  · intro b hb hbm
    exact longest_refines state group b hshape hb hbm hg
  · intro b hb hbm j hj
    refine ⟨encodeEntries (entriesModel state group.val b.val j.val),
      entries_refines state group b j hshape hb hbm hg, ?_, rfl⟩
    exact load_signed_refines store _ _ (hload b.val hb hbm j.val hj)

def windowVector (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : ℕ) : G1x8 :=
  windowSum (loadedEntry state store group) (fun b => (longestModel state group b).val)
    (2 ^ (state.window_bits.val - 1)) G1x8.infinity G1x8.infinity

theorem concrete_window_refines (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : Usize) (hshape : BucketShape state)
    (hg : group.val * 8 + 7 < 2 ^ UScalarTy.Usize.numBits)
    (hload : GroupLoads state store group.val) :
    msm8.buckets.Buckets.window_sums state store group =
      ok (toG1x8 (windowVector state store group.val)) :=
  window_sums_refines state store group _ _ hshape.width_lower hshape.width_upper
    (concrete_windowCalls state store group hshape hg hload)

theorem concrete_sum_refines (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (hshape : BucketShape state) (hwin : 1 ≤ state.windows.val)
    (hgroups : (state.windows.val - 1) / 8 * 8 + 7 < 2 ^ UScalarTy.Usize.numBits)
    (hload : ∀ g, g ≤ (state.windows.val - 1) / 8 → GroupLoads state store g) :
    msm8.buckets.Buckets.sum state store =
      ok (toG1x8 ((groupSum (windowVector state store) state.window_bits.val
        ((state.windows.val - 1) / 8) (windowVector state store ((state.windows.val - 1) / 8))).sum_lanes_shifted state.window_bits.val)) := by
  apply buckets_sum_refines state store _ (by have := hshape.width_upper; omega) hwin
  intro g hg
  exact concrete_window_refines state store g hshape (by omega) (hload g.val hg)

def windowWeight (state : msm8.buckets.Buckets)
    (Q : ℕ → ℕ → ℕ → Fin 8 → G1.curve.toAffine.Point) (g : ℕ) (l : Fin 8) :=
  ∑ b ∈ Finset.range (2 ^ (state.window_bits.val - 1)),
    (b + 1) • ∑ j ∈ Finset.range (longestModel state g (b + 1)).val, Q g (b + 1) j l

theorem concrete_sum_correct (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (hshape : BucketShape state) (hwin : 1 ≤ state.windows.val)
    (hgroups : (state.windows.val - 1) / 8 * 8 + 7 < 2 ^ UScalarTy.Usize.numBits)
    (hload : ∀ g, g ≤ (state.windows.val - 1) / 8 → GroupLoads state store g)
    (Q : ℕ → ℕ → ℕ → Fin 8 → G1.curve.toAffine.Point)
    (hq : ∀ g, g ≤ (state.windows.val - 1) / 8 →
      ∀ b, 1 ≤ b → b ≤ 2 ^ (state.window_bits.val - 1) →
      ∀ j, j < (longestModel state g b).val → ∀ l,
        EntryRep (loadedEntry state store g b j) l (Q g b j l)) :
    ∃ out, msm8.buckets.Buckets.sum state store = ok (toG1x8 out) ∧
      out.PointRep 0 (∑ l : Fin 8, 2 ^ (l.val * state.window_bits.val) •
        ∑ g ∈ Finset.range ((state.windows.val - 1) / 8 + 1),
          2 ^ (g * (8 * state.window_bits.val)) • windowWeight state Q g l) := by
  apply buckets_sum_correct state store (windowVector state store)
    (by have := hshape.width_upper; omega) hwin
  · intro g hg
    exact concrete_window_refines state store g hshape (by omega) (hload g.val hg)
  · intro g hg l
    have h := windowSum_correct (loadedEntry state store g)
      (fun b => (longestModel state g b).val) _ G1x8.infinity G1x8.infinity l 0 0
      (fun b j => Q g b j l) (infinity_pointRep l) (infinity_pointRep l)
      (fun b hb hbm j hj => hq g hg b hb hbm j hj l)
    simpa only [windowVector, windowWeight, nsmul_zero, zero_add] using h

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums

theorem entriesModel_indices (state : msm8.buckets.Buckets) (group bucket cursor : ℕ) :
    (entriesModel state group bucket cursor).indices =
      Vector.ofFn (fun l => clearSign (referenceAt state (group * 8 + l.val) bucket cursor)) := by
  have h (ls : List (Fin 8)) (e : EntryAccumulator) :
      (ls.foldl (entriesStep state group bucket cursor) e).indices =
        ls.foldl (fun a l => a.set l (clearSign (referenceAt state (group * 8 + l.val) bucket cursor))) e.indices := by
    induction ls generalizing e with
    | nil => rfl
    | cons l ls ih => simpa only [List.foldl_cons, entriesStep] using ih (entriesStep state group bucket cursor e l)
  rw [entriesModel, h, foldl_set_ofFn]

theorem entriesModel_indices_lane (state : msm8.buckets.Buckets) (group bucket cursor : ℕ)
    (l : Fin 8) :
    (entriesModel state group bucket cursor).indices[l] =
      clearSign (referenceAt state (group * 8 + l.val) bucket cursor) := by
  change (entriesModel state group bucket cursor).indices[l.val] = _
  rw [entriesModel_indices]
  simp only [Vector.getElem_ofFn]

theorem groupLoads_of_references (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (group : ℕ)
    (href : ∀ b, 1 ≤ b → b ≤ 2 ^ (state.window_bits.val - 1) →
      ∀ j, j < (longestModel state group b).val → ∀ l : Fin 8,
      2 * (clearSign (referenceAt state (group * 8 + l.val) b j)).val + 1 < store.rows.val.length) :
    GroupLoads state store group := by
  intro b hb hbm j hj l
  have h := href b hb hbm j hj l
  change 2 * (pointIndices (encodeEntries (entriesModel state group b j)).indices)[l.val] + 1 < _
  simpa only [encodeEntries, pointIndices, getElem_ofArray, toArray, List.getElem_map, Vector.getElem_toList, id_eq,
    entriesModel_indices, Vector.getElem_ofFn] using h

@[simp] theorem ofU8_or (a b : U8) : ofU8 (a ||| b) = ofU8 a ||| ofU8 b := rfl

theorem present_singleton (present : Bool) (i l : Fin 8) :
    (ofU8 (⟨(UScalar.cast_fromBool .U8 present).bv.shiftLeft i⟩ : U8)).toNat.testBit l =
      (decide (l = i) && present) := by
  revert present i l
  decide

theorem entries_fold_present (state : msm8.buckets.Buckets) (group bucket cursor : ℕ)
    (lanes : List (Fin 8)) (e : EntryAccumulator) (l : Fin 8) :
    (ofU8 (lanes.foldl (entriesStep state group bucket cursor) e).present).toNat.testBit l =
      ((ofU8 e.present).toNat.testBit l || (decide (l ∈ lanes) &&
        decide (cursor < (bucketLength state (group * 8 + l.val) bucket).val))) := by
  induction lanes generalizing e with
  | nil => simp
  | cons j lanes ih =>
    rw [List.foldl_cons, ih]
    simp only [entriesStep, ofU8_or, Mmask8.testBit_or, present_singleton,
      List.mem_cons, Bool.decide_or]
    by_cases h : l = j
    · subst j
      simp only [decide_true, Bool.true_and, Bool.true_or]
      cases (ofU8 e.present).toNat.testBit l <;>
        cases decide (cursor < (bucketLength state (group * 8 + l.val) bucket).val) <;> simp
    · simp only [h, decide_false, Bool.false_and, Bool.false_or, Bool.or_false]

theorem entriesModel_present (state : msm8.buckets.Buckets) (group bucket cursor : ℕ)
    (l : Fin 8) :
    (ofU8 (entriesModel state group bucket cursor).present).toNat.testBit l =
      decide (cursor < (bucketLength state (group * 8 + l.val) bucket).val) := by
  rw [entriesModel, entries_fold_present]
  simp [emptyEntries]

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums

theorem maxScalar_val (a b : Usize) : (maxScalar a b).val = max a.val b.val := by
  unfold maxScalar
  split <;> simp_all only [UScalar.lt_equiv] <;> omega

theorem fold_max_ge {α : Type} (values : α → Usize) (ls : List α) (initial : Usize) :
    initial.val ≤ (ls.foldl (fun a i => maxScalar a (values i)) initial).val := by
  induction ls generalizing initial with
  | nil => exact le_refl _
  | cons i ls ih =>
    exact le_trans (by rw [maxScalar_val]; omega) (ih (maxScalar initial (values i)))

theorem fold_max_ge_member {α : Type} (values : α → Usize) (ls : List α) (initial : Usize)
    (i : α) (hi : i ∈ ls) :
    (values i).val ≤ (ls.foldl (fun a j => maxScalar a (values j)) initial).val := by
  induction ls generalizing initial with
  | nil => simp at hi
  | cons j ls ih =>
    simp only [List.mem_cons] at hi
    rcases hi with rfl | hi
    · exact le_trans (by rw [maxScalar_val]; omega) (fold_max_ge values ls (maxScalar initial (values i)))
    · exact ih _ hi

theorem longest_ge_lane (state : msm8.buckets.Buckets) (group bucket : ℕ) (l : Fin 8) :
    (bucketLength state (group * 8 + l.val) bucket).val ≤ (longestModel state group bucket).val := by
  have h := fold_max_ge_member
    (fun l : Fin 8 => UScalar.cast .Usize (bucketLength state (group * 8 + l.val) bucket))
    (List.finRange 8) 0#usize l (List.mem_finRange l)
  simpa only [cast_Usize_val] using h

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums

theorem clearSign_val (reference : U32) : (clearSign reference).val = reference.val % 2 ^ 31 := by
  unfold clearSign
  rw [UScalar.val_and]
  change reference.val &&& (2 ^ 31 - 1) = _
  exact Nat.and_two_pow_sub_one_eq_mod _ _

theorem referenceSign_val (reference : U32) : (referenceSign reference).val = reference.val / 2 ^ 31 := by
  have h : reference.val / 2 ^ 31 < 2 := by have := reference.hBounds; change reference.val < 2 ^ 32 at this; omega
  unfold referenceSign
  rw [UScalar.cast_val_eq]
  change (reference.bv.ushiftRight 31).toNat % 256 = _
  rw [show (reference.bv.ushiftRight 31).toNat = reference.val >>> 31 from BitVec.toNat_ushiftRight _ _, Nat.shiftRight_eq_div_pow]
  exact Nat.mod_eq_of_lt (by omega)

theorem referenceSign_bool (reference : U32) :
    referenceSign reference = UScalar.cast_fromBool .U8 (decide (2 ^ 31 ≤ reference.val)) := by
  apply UScalar.eq_of_val_eq
  rw [referenceSign_val]
  have h := reference.hBounds
  change reference.val < 2 ^ 32 at h
  by_cases hn : 2 ^ 31 ≤ reference.val
  · simp only [hn, decide_true]
    change reference.val / 2 ^ 31 = 1
    omega
  · simp only [hn, decide_false]
    change reference.val / 2 ^ 31 = 0
    omega

theorem negated_singleton (reference : U32) (i l : Fin 8) :
    (ofU8 (⟨(referenceSign reference).bv.shiftLeft i.val⟩ : U8)).toNat.testBit l =
      (decide (l = i) && decide (2 ^ 31 ≤ reference.val)) := by
  rw [referenceSign_bool]
  exact present_singleton _ i l

theorem entries_fold_negated (state : msm8.buckets.Buckets) (group bucket cursor : ℕ)
    (lanes : List (Fin 8)) (e : EntryAccumulator) (l : Fin 8) :
    (ofU8 (lanes.foldl (entriesStep state group bucket cursor) e).negated).toNat.testBit l =
      ((ofU8 e.negated).toNat.testBit l || (decide (l ∈ lanes) &&
        decide (2 ^ 31 ≤ (referenceAt state (group * 8 + l.val) bucket cursor).val))) := by
  induction lanes generalizing e with
  | nil => simp
  | cons j lanes ih =>
    rw [List.foldl_cons, ih]
    simp only [entriesStep, ofU8_or, Mmask8.testBit_or, negated_singleton,
      List.mem_cons, Bool.decide_or]
    by_cases h : l = j
    · subst j
      simp only [decide_true, Bool.true_and, Bool.true_or]
      cases (ofU8 e.negated).toNat.testBit l <;>
        cases decide (2 ^ 31 ≤ (referenceAt state (group * 8 + l.val) bucket cursor).val) <;> simp
    · simp only [h, decide_false, Bool.false_and, Bool.false_or, Bool.or_false]

theorem entriesModel_negated (state : msm8.buckets.Buckets) (group bucket cursor : ℕ)
    (l : Fin 8) :
    (ofU8 (entriesModel state group bucket cursor).negated).toNat.testBit l =
      decide (2 ^ 31 ≤ (referenceAt state (group * 8 + l.val) bucket cursor).val) := by
  rw [entriesModel, entries_fold_negated]
  simp [emptyEntries]

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open BucketsRefines

theorem listIndex_lt (width window windows bucket : ℕ) (hw : window < windows)
    (hb : 1 ≤ bucket) (hbm : bucket ≤ 2 ^ (width - 1)) :
    listIndex width window bucket < windows * 2 ^ (width - 1) := by
  have hmul := Nat.mul_le_mul_right (2 ^ (width - 1)) (show window + 1 ≤ windows by omega)
  rw [Nat.add_mul, Nat.one_mul] at hmul
  unfold listIndex
  omega

theorem packed_shape (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (hlo : 1 ≤ state.window_bits.val) (hhi : state.window_bits.val ≤ 8)
    (hn : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32) :
    BucketShape state := by
  refine ⟨hlo, hhi, hn, le_of_eq hp.counts.length.symm, le_of_eq hp.starts_length.symm, ?_⟩
  intro i hi
  rw [hp.starts_values i hi, hp.counts.values i hi]
  exact le_trans (Nat.add_le_add_left (hp.capacity_bound i hi) _) (hp.regions i hi)

def windowReferences (state : msm8.buckets.Buckets) (contents : BucketLists)
    (window bucket : ℕ) : List U32 :=
  if window < state.windows.val then contents (listIndex state.window_bits.val window bucket) else []

theorem packed_bucketLength (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (window bucket : ℕ) (hb : 1 ≤ bucket) (hbm : bucket ≤ 2 ^ (state.window_bits.val - 1)) :
    (bucketLength state window bucket).val = (windowReferences state contents window bucket).length := by
  by_cases hw : window < state.windows.val
  · simp only [bucketLength, windowReferences, hw, if_true]
    exact hp.counts.values _ (listIndex_lt _ _ _ _ hw hb hbm)
  · simp only [bucketLength, windowReferences, hw, if_false, List.length_nil, UScalar.ofNatCore_val_eq]

theorem packed_referenceAt (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (window bucket cursor : ℕ) (hb : 1 ≤ bucket) (hbm : bucket ≤ 2 ^ (state.window_bits.val - 1)) :
    referenceAt state window bucket cursor =
      if cursor < (windowReferences state contents window bucket).length then
        (windowReferences state contents window bucket)[cursor]! else 0#u32 := by
  unfold referenceAt
  rw [packed_bucketLength state base capacity contents hp window bucket hb hbm]
  by_cases hw : window < state.windows.val
  · simp only [windowReferences, hw, if_true]
    have hi := listIndex_lt state.window_bits.val window state.windows.val bucket hw hb hbm
    rw [hp.starts_values _ hi]
    split
    · exact hp.entries _ hi cursor (by assumption)
    · rfl
  · simp only [windowReferences, hw, if_false, List.length_nil, Nat.not_lt_zero, if_false]

theorem packed_groupLoads (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (base capacity : ℕ → ℕ) (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (hzero : 1 < store.rows.val.length)
    (href : ∀ i, i < state.windows.val * 2 ^ (state.window_bits.val - 1) →
      ∀ r ∈ contents i, 2 * (r.val % 2 ^ 31) + 1 < store.rows.val.length)
    (group : ℕ) : GroupLoads state store group := by
  apply groupLoads_of_references state store group
  intro b hb hbm j _ l
  rw [clearSign_val, packed_referenceAt state base capacity contents hp _ b j hb hbm]
  split
  · rename_i hj
    have hw : group * 8 + l.val < state.windows.val := by
      by_contra h
      simp only [windowReferences, h, if_false, List.length_nil] at hj
      omega
    simp only [windowReferences, hw, if_true] at hj ⊢
    apply href _ (listIndex_lt _ _ _ _ hw hb hbm) _
    rw [getElem!_pos (contents (listIndex state.window_bits.val (group * 8 + l.val) b)) j hj]
    exact List.getElem_mem hj
  · simpa only [UScalar.ofNatCore_val_eq, Nat.zero_mod, Nat.mul_zero, Nat.zero_add] using hzero

end LeanBlsSimd.WindowSums
