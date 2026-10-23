import LeanBlsSimd.Msm8.Complete
import LeanBlsSimd.Refines.Transpose

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.G1x8
open EthLib.Cryptography.Bls


theorem times_two_pow_succ (self : G1x8) (k : ℕ) :
    self.times_two_pow (k + 1) = self.double_complete.times_two_pow k := by
  simp only [times_two_pow, List.foldl_const, List.length_range, Function.iterate_succ_apply]

theorem times_two_pow_holds (self : G1x8) (k : ℕ) (l : Fin 8) (P : G1)
    (h : self.Holds l P) : (self.times_two_pow k).Holds l ((G1.double^[k]) P) := by
  induction k generalizing self P with
  | zero => exact h
  | succ k ih =>
    rw [times_two_pow_succ, Function.iterate_succ_apply]
    exact ih self.double_complete (G1.double P) (double_complete_correct self l P h)

theorem times_two_pow_correct (self : G1x8) (k : ℕ) (l : Fin 8) (P : G1)
    (h : self.Holds l P) (hP : G1.Valid P) :
    ∃ Q, (self.times_two_pow k).Holds l Q ∧ G1.Valid Q ∧
      G1.toPoint Q = 2 ^ k • G1.toPoint P := by
  induction k generalizing self P with
  | zero => exact ⟨P, h, hP, by simp⟩
  | succ k ih =>
    obtain ⟨Q, hQ, hv, heq⟩ := ih self.double_complete (G1.double P)
      (double_complete_correct self l P h) (G1.valid_double hP)
    refine ⟨Q, ?_, hv, ?_⟩
    · simpa only [times_two_pow_succ] using hQ
    · rw [heq, G1.toPoint_double hP, pow_succ, mul_nsmul]
      simp only [nsmul_add, two_nsmul]

theorem times_two_pow_loop_refines (k i : Usize) (r : G1x8) (hi : i.val ≤ k.val) :
    g1x8.G1x8.times_two_pow_loop k (toG1x8 r) i =
      ok (toG1x8 (r.times_two_pow (k.val - i.val))) := by
  unfold g1x8.G1x8.times_two_pow_loop
  induction hn : k.val - i.val generalizing i r with
  | zero =>
    have hge : ¬i < k := by simp only [UScalar.lt_equiv]; omega
    rw [loop.eq_1]
    simp [g1x8.G1x8.times_two_pow_loop.body, hge, times_two_pow]
  | succ n ih =>
    have hlt : i < k := by simp only [UScalar.lt_equiv]; omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by have := k.hBounds; omega)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hb : g1x8.G1x8.times_two_pow_loop.body k (toG1x8 r) i =
        ok (cont (toG1x8 r.double_complete, i')) := by
      simp only [g1x8.G1x8.times_two_pow_loop.body, hlt, ↓reduceIte,
        double_complete_refines, ofG1x8_toG1x8, bind_tc_ok]
      rw [add_ok _ _ (by have := k.hBounds; simp at *; omega)]
      rfl
    rw [loop.eq_1]
    simp only [hb]
    change loop _ (toG1x8 r.double_complete, i') = _
    rw [ih i' r.double_complete (by omega) (by omega)]
    rw [times_two_pow_succ]

theorem times_two_pow_refines (self : g1x8.G1x8) (k : Usize) :
    g1x8.G1x8.times_two_pow self k = ok (toG1x8 ((ofG1x8 self).times_two_pow k.val)) := by
  simpa only [g1x8.G1x8.times_two_pow, toG1x8_ofG1x8, UScalar.ofNatCore_val_eq,
    Nat.sub_zero] using times_two_pow_loop_refines k 0#usize (ofG1x8 self) (by simp)

end LeanBlsSimd.G1x8

namespace LeanBlsSimd

namespace Fp8


theorem lane_permute (self : Fp8) (indices : Vector Int64 8) (l : Fin 8) :
    (self.permute indices).lane l =
      self.lane ⟨indices[l].toUInt64.toNat % 8, Nat.mod_lt _ (by decide)⟩ := by
  ext j hj
  simp [permute, lane, _mm512_permutex2var_epi64]

theorem permute_holds (self : Fp8) (indices : Vector Int64 8) (l : Fin 8)
    (a : ZMod EthLib.Cryptography.Bls.Fp.modulus)
    (h : self.Holds ⟨indices[l].toUInt64.toNat % 8, Nat.mod_lt _ (by decide)⟩ a) :
    (self.permute indices).Holds l a := by
  constructor <;> rw [lane_permute]
  exacts [h.inv, h.eq]

end Fp8

namespace G1x8


theorem permute_holds (self : G1x8) (indices : Vector Int64 8) (l : Fin 8)
    (P : EthLib.Cryptography.Bls.G1)
    (h : self.Holds ⟨indices[l].toUInt64.toNat % 8, Nat.mod_lt _ (by decide)⟩ P) :
    (self.permute indices).Holds l P :=
  ⟨Fp8.permute_holds _ _ _ _ (Holds.x h), Fp8.permute_holds _ _ _ _ (Holds.y h),
    Fp8.permute_holds _ _ _ _ (Holds.z h)⟩

end G1x8

theorem index_vector_refines (indices : Array I64 8#usize) :
    fp8.index_vector indices = ok ((ofArray (fun i => Int64.ofBitVec i.bv) indices).map Int64.toUInt64) := by
  simp only [fp8.index_vector,
    index_usize_eq (n := 8#usize) _ 0#usize (by decide), index_usize_eq (n := 8#usize) _ 1#usize (by decide),
    index_usize_eq (n := 8#usize) _ 2#usize (by decide), index_usize_eq (n := 8#usize) _ 3#usize (by decide),
    index_usize_eq (n := 8#usize) _ 4#usize (by decide), index_usize_eq (n := 8#usize) _ 5#usize (by decide),
    index_usize_eq (n := 8#usize) _ 6#usize (by decide), index_usize_eq (n := 8#usize) _ 7#usize (by decide),
    bind_tc_ok, core.core_arch.x86.avx512f._mm512_set_epi64]
  congr 1
  ext l hl
  interval_cases l <;> simp [ofArray, _mm512_set_epi64]

namespace Fp8

theorem permute_loop_refines (self : fp8.Fp8) (index : M512)
    (v : Vector M512 8) (i : Usize) (hi : i.val ≤ 8)
    (hv : ∀ j : Fin 8, j.val < i.val → v[j] =
      _mm512_permutex2var_epi64 (ofArray id self)[j] index (ofArray id self)[j]) :
    fp8.Fp8.permute_loop self index (toArray id v) i =
      ok (toArray id ((ofArray id self).map fun row => _mm512_permutex2var_epi64 row index row)) := by
  unfold fp8.Fp8.permute_loop
  induction hn : 8 - i.val generalizing i v with
  | zero =>
    have hi8 : i.val = 8 := by omega
    have hb : fp8.Fp8.permute_loop.body index self (toArray id v) i = ok (done (toArray id v)) := by
      simp only [fp8.Fp8.permute_loop.body, LIMBS_refines, UScalar.lt_equiv,
        hi8, UScalar.ofNatCore_val_eq, Nat.lt_irrefl, ↓reduceIte]
    rw [loop.eq_1]
    simp only [hb]
    apply congrArg ok
    apply congrArg (toArray id)
    apply Vector.ext
    intro j hj
    exact (hv ⟨j, hj⟩ (by omega)).trans
      (Vector.getElem_map (fun row => _mm512_permutex2var_epi64 row index row)
        (xs := (ofArray id self : Vector M512 8)) hj).symm
  | succ n ih =>
    have hlt : i.val < 8 := by omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by scalar_tac)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    let value := _mm512_permutex2var_epi64 (ofArray id self)[i.val] index (ofArray id self)[i.val]
    let v' := v.set i.val value
    have hb : fp8.Fp8.permute_loop.body index self (toArray id v) i =
        ok (cont (self, toArray id v', i')) := by
      simp only [fp8.Fp8.permute_loop.body, LIMBS_refines, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, hlt, ↓reduceIte,
        index_usize_eq self i hlt, bind_tc_ok,
        core.core_arch.x86.avx512f._mm512_permutex2var_epi64, update_eq (n := 8#usize) _ i _ hlt]
      rw [add_ok _ _ (by scalar_tac)]
      simp [v', value, i']
      exact set_toArray id v rfl i _ hlt
    rw [loop.eq_1]
    simp only [hb]
    apply ih v' i' (by omega) ?_ (by omega)
    intro j hj
    by_cases hji : j.val = i.val
    · simp [v', value, hji]
    · simpa [v', Vector.getElem_set, hji, Ne.symm hji] using hv j (by omega)

theorem permute_refines (self : fp8.Fp8) (indices : Array I64 8#usize) :
    fp8.Fp8.permute self indices =
      ok (toFp8 ((ofFp8 self).permute (ofArray (fun i => Int64.ofBitVec i.bv) indices))) := by
  simp only [fp8.Fp8.permute, index_vector_refines, Simd.zero_refines, bind_tc_ok]
  have hre : Array.repeat 8#usize Simd.zero = toArray id (Vector.replicate 8 Simd.zero) :=
    (toArray_replicate id Simd.zero rfl).symm
  rw [hre]
  rw [permute_loop_refines self _ _ 0#usize (by decide) (by simp)]
  rfl

end Fp8

namespace G1x8

theorem permute_refines (self : g1x8.G1x8) (indices : Array I64 8#usize) :
    g1x8.G1x8.permute self indices =
      ok (toG1x8 ((ofG1x8 self).permute (ofArray (fun i => Int64.ofBitVec i.bv) indices))) := by
  simp [g1x8.G1x8.permute, Fp8.permute_refines, permute, toG1x8]

end G1x8
end LeanBlsSimd

namespace LeanBlsSimd.G1x8
open EthLib.Cryptography.Bls


theorem lanesAbove_index (distance : ℕ) (l : Fin 8) :
    (lanesAbove distance)[l].toUInt64.toNat % 8 = (l.val + distance) % 8 := by
  simp [lanesAbove, Int64.ofNat, UInt64.toNat_ofNat]



def PointRep (self : G1x8) (l : Fin 8) (P : G1.curve.toAffine.Point) : Prop :=
  ∃ Q, self.Holds l Q ∧ G1.Valid Q ∧ G1.toPoint Q = P

theorem PointRep.add_complete {self q : G1x8} {l : Fin 8}
    {P Q : G1.curve.toAffine.Point} (hp : self.PointRep l P) (hq : q.PointRep l Q) :
    (self.add_complete q).PointRep l (P + Q) := by
  obtain ⟨p, hp, hvp, rfl⟩ := hp
  obtain ⟨q, hq, hvq, rfl⟩ := hq
  exact ⟨G1.add p q, add_complete_correct _ _ _ _ _ hp hq hvp hvq,
    G1.valid_add hvp hvq, G1.toPoint_add hvp hvq⟩

theorem PointRep.times_two_pow {self : G1x8} {l : Fin 8}
    {P : G1.curve.toAffine.Point} (hp : self.PointRep l P) (k : ℕ) :
    (self.times_two_pow k).PointRep l (2 ^ k • P) := by
  obtain ⟨p, hp, hvp, rfl⟩ := hp
  exact times_two_pow_correct _ _ _ _ hp hvp

theorem PointRep.lanesAbove {self : G1x8} {l : Fin 8} {distance : ℕ}
    {P : G1.curve.toAffine.Point}
    (hp : self.PointRep ⟨(l.val + distance) % 8, Nat.mod_lt _ (by decide)⟩ P) :
    (self.permute (lanesAbove distance)).PointRep l P := by
  obtain ⟨p, hp, hvp, heq⟩ := hp
  refine ⟨p, ?_, hvp, heq⟩
  apply permute_holds
  simpa only [lanesAbove_index] using hp

theorem joinLanes_correct (self : G1x8) (bits distance : ℕ)
    (P : Fin 8 → G1.curve.toAffine.Point) (hP : ∀ l, self.PointRep l (P l)) (l : Fin 8) :
    (self.joinLanes bits distance).PointRep l
      (P l + 2 ^ (distance * bits) • P ⟨(l.val + distance) % 8, Nat.mod_lt _ (by decide)⟩) :=
  (hP l).add_complete ((hP _).times_two_pow _).lanesAbove

theorem sum_lanes_shifted_correct (self : G1x8) (bits : ℕ)
    (P : Fin 8 → G1.curve.toAffine.Point) (hP : ∀ l, self.PointRep l (P l)) :
    (self.sum_lanes_shifted bits).PointRep 0 (∑ l : Fin 8, 2 ^ (l.val * bits) • P l) := by
  have h1 := joinLanes_correct self bits 1 P hP
  have h2 := joinLanes_correct (self.joinLanes bits 1) bits 2 _ h1
  have h3 := joinLanes_correct ((self.joinLanes bits 1).joinLanes bits 2) bits 4 _ h2 0
  change (self.sum_lanes_shifted bits).PointRep 0 _ at h3
  convert h3 using 1
  have hp (n : ℕ) : 2 ^ (n * bits) = (2 ^ bits) ^ n := by rw [Nat.mul_comm, pow_mul]
  simp only [Fin.sum_univ_succ, Fin.val_zero, Fin.val_succ, hp]
  norm_num
  change P 0 + (2 ^ bits • P 1 + ((2 ^ bits) ^ 2 • P 2 +
    ((2 ^ bits) ^ 3 • P 3 + ((2 ^ bits) ^ 4 • P 4 +
    ((2 ^ bits) ^ 5 • P 5 + ((2 ^ bits) ^ 6 • P 6 + (2 ^ bits) ^ 7 • P 7)))))) =
    P 0 + 2 ^ bits • P 1 + (2 ^ bits) ^ 2 • (P 2 + 2 ^ bits • P 3) +
    (2 ^ bits) ^ 4 • (P 4 + 2 ^ bits • P 5 + (2 ^ bits) ^ 2 • (P 6 + 2 ^ bits • P 7))
  module

end LeanBlsSimd.G1x8

namespace LeanBlsSimd.G1x8

abbrev toI64 (x : Int64) : I64 := ⟨x.toBitVec⟩

theorem hcast_usize_i64 (x : Usize) :
    UScalar.hcast .I64 x = toI64 (Int64.ofNat x.val) := by
  apply congrArg IScalar.mk
  simp [Int64.toBitVec, Int64.ofNat]

theorem lanesAbove_loop_refines (distance : Usize) (hd : distance.val ≤ 4)
    (v : Vector Int64 8) (i : Usize) (hi : i.val ≤ 8)
    (hv : ∀ j : Fin 8, j.val < i.val → v[j] = (lanesAbove distance.val)[j]) :
    g1x8.lanes_above_loop distance (toArray toI64 v) i =
      ok (toArray toI64 (lanesAbove distance.val)) := by
  have hs := two_pow_32_le_usize
  unfold g1x8.lanes_above_loop
  induction hn : 8 - i.val generalizing i v with
  | zero =>
    have hi8 : i.val = 8 := by omega
    have hb : g1x8.lanes_above_loop.body distance (toArray toI64 v) i =
        ok (done (toArray toI64 v)) := by
      simp [g1x8.lanes_above_loop.body, fp8.LANES, UScalar.lt_equiv, hi8]
    rw [loop.eq_1]
    simp only [hb]
    congr 2
    ext j hj
    exact hv ⟨j, hj⟩ (by omega)
  | succ n ih =>
    have hlt : i.val < 8 := by omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by omega)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    let v' := v.set i.val ((lanesAbove distance.val)[i.val])
    have hb : g1x8.lanes_above_loop.body distance (toArray toI64 v) i =
        ok (cont (toArray toI64 v', i')) := by
      simp only [g1x8.lanes_above_loop.body, fp8.LANES, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, hlt, ↓reduceIte]
      rw [add_ok _ _ (by omega)]
      simp only [bind_tc_ok]
      rw [rem_ok _ _ (by decide)]
      simp only [bind_tc_ok, lift, hcast_usize_i64, UScalar.ofNatCore_val_eq]
      rw [update_eq _ _ _ hlt,
        add_ok _ _ (by simp only [UScalar.ofNatCore_val_eq]; omega)]
      simp only [bind_tc_ok]
      congr 2
      apply Prod.ext
      · simpa [v', lanesAbove] using (set_toArray (n := 8#usize) toI64 v rfl i
          (Int64.ofNat ((i.val + distance.val) % 8)) hlt)
      · rfl
    rw [loop.eq_1]
    simp only [hb]
    apply ih v' i' (by omega) ?_ (by omega)
    intro j hj
    by_cases hji : j.val = i.val
    · simp [v', hji]
    · simpa [v', Vector.getElem_set, hji, Ne.symm hji] using hv j (by omega)

theorem lanesAbove_refines (distance : Usize) (hd : distance.val ≤ 4) :
    g1x8.lanes_above distance = ok (toArray toI64 (lanesAbove distance.val)) := by
  unfold g1x8.lanes_above
  rw [show Array.repeat 8#usize 0#i64 = toArray toI64 (Vector.replicate 8 0) from
    (toArray_replicate toI64 0 rfl).symm]
  exact lanesAbove_loop_refines distance hd _ 0#usize (by decide) (by simp)

private theorem sum_body_refines (bits : Usize) (hb : bits.val ≤ 255)
    (r : G1x8) (distance : Usize) (hd : distance.val ≤ 4) :
    g1x8.G1x8.sum_lanes_shifted_loop.body bits (toG1x8 r) distance =
      ok (cont (toG1x8 (r.joinLanes bits.val distance.val),
        UScalar.ofNatCore (distance.val * 2) (by have := two_pow_32_le_usize; omega))) := by
  have hs := two_pow_32_le_usize
  have hm : distance.val * bits.val < 2 ^ UScalarTy.Usize.numBits := by
    have := Nat.mul_le_mul hd hb
    omega
  simp only [g1x8.G1x8.sum_lanes_shifted_loop.body, fp8.LANES, UScalar.lt_equiv,
    UScalar.ofNatCore_val_eq, show distance.val < 8 by omega, ↓reduceIte]
  rw [mul_ok _ _ hm]
  simp only [bind_tc_ok, times_two_pow_refines, ofG1x8_toG1x8,
    UScalar.ofNatCore_val_eq, lanesAbove_refines distance hd, permute_refines,
    add_complete_refines]
  rw [mul_ok _ _ (by simp only [UScalar.ofNatCore_val_eq]; omega)]
  simp only [bind_tc_ok, joinLanes]
  rw [ofArray_toArray (f := fun i : I64 => Int64.ofBitVec i.bv) (g := toI64)
    (fun _ => rfl)]
  rfl

theorem sum_lanes_shifted_refines (self : g1x8.G1x8) (bits : Usize)
    (hb : bits.val ≤ 255) :
    g1x8.G1x8.sum_lanes_shifted self bits =
      ok (toG1x8 ((ofG1x8 self).sum_lanes_shifted bits.val)) := by
  unfold g1x8.G1x8.sum_lanes_shifted g1x8.G1x8.sum_lanes_shifted_loop
  rw [← toG1x8_ofG1x8 self]
  rw [loop.eq_1]
  dsimp only
  rw [sum_body_refines bits hb _ _ (by simp only [UScalar.ofNatCore_val_eq]; omega)]
  simp only
  rw [loop.eq_1]
  dsimp only
  rw [sum_body_refines bits hb _ _ (by simp only [UScalar.ofNatCore_val_eq]; omega)]
  simp only
  rw [loop.eq_1]
  dsimp only
  rw [sum_body_refines bits hb _ _ (by simp only [UScalar.ofNatCore_val_eq]; omega)]
  simp only
  rw [loop.eq_1]
  simp [g1x8.G1x8.sum_lanes_shifted_loop.body, fp8.LANES,
    sum_lanes_shifted]

end LeanBlsSimd.G1x8
