import LeanBlsSimd.Msm8.Infinity
import LeanBlsSimd.Refines.Loop

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.PairingProduct

noncomputable section

set_option exponentiation.threshold 512

private def pWord (p : blst.blst_p1_affine) (j : Fin 6) : U64 :=
  p.x.l.val[j.val]'(by rw [p.x.l.property]; exact j.isLt) |||
    p.y.l.val[j.val]'(by rw [p.y.l.property]; exact j.isLt)

private def qWord (q : blst.blst_p2_affine) (j : Fin 6) (c : Fin 2) : U64 :=
  let x := q.x.fp.val[c.val]'(by rw [q.x.fp.property]; exact c.isLt)
  let y := q.y.fp.val[c.val]'(by rw [q.y.fp.property]; exact c.isLt)
  x.l.val[j.val]'(by rw [x.l.property]; exact j.isLt) |||
    y.l.val[j.val]'(by rw [y.l.property]; exact j.isLt)

private def componentBits (q : blst.blst_p2_affine) (j : Fin 6) (b : U64) : U64 :=
  (List.finRange 2).foldl (fun b c => b ||| qWord q j c) b

private def pairBits (p : pairing_product.AffinePair) (b : U64 × U64) (j : Fin 6) : U64 × U64 :=
  (b.1 ||| pWord p.p j, componentBits p.q j b.2)

private theorem component_loop (q : blst.blst_p2_affine) (j : Usize) (hj : j.val < 6) (b : U64) :
    pairing_product.AffinePair.is_infinite_loop0_loop0
      { start := 0#usize, «end» := 2#usize } q b j =
        ok (q, componentBits q ⟨j.val, hj⟩ b) := by
  unfold pairing_product.AffinePair.is_infinite_loop0_loop0
  refine loop_range _ 2#usize rfl id (fun b c => b ||| qWord q ⟨j.val, hj⟩ c)
    (fun b => (q, b)) b _ ?_ ?_ rfl
  · intro r m he hs hn
    simp only [pairing_product.AffinePair.is_infinite_loop0_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    rfl
  · intro r r' m c he hs he' hs' hn
    simp only [pairing_product.AffinePair.is_infinite_loop0_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    try dsimp only
    have hc : r.start.val < 2 := by rw [hs]; exact c.isLt
    simp (disch := (simp only [UScalar.ofNatCore_val_eq]; omega)) only
      [index_usize_eq q.x.fp r.start hc, index_usize_eq q.y.fp r.start hc,
        index_usize_eq, bind_tc_ok, lift, hs]
    rfl

private theorem pair_loop (p : pairing_product.AffinePair) (b : U64 × U64) :
    pairing_product.AffinePair.is_infinite_loop0
      { start := 0#usize, «end» := pairing_product.BLST_LIMBS } p b.1 b.2 =
        ok ((List.finRange 6).foldl (pairBits p) b) := by
  unfold pairing_product.AffinePair.is_infinite_loop0
  refine loop_range _ pairing_product.BLST_LIMBS (by simp [pairing_product.BLST_LIMBS])
    (fun b : U64 × U64 => (p, b)) (pairBits p) id b _ ?_ ?_ rfl
  · intro r m he hs hn
    simp only [pairing_product.AffinePair.is_infinite_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    rfl
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < 6 := by omega
    simp only [pairing_product.AffinePair.is_infinite_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    try dsimp only
    rw [index_usize_eq p.p.x.l r.start hj]
    simp only [bind_tc_ok]
    rw [index_usize_eq p.p.y.l r.start hj]
    simp only [bind_tc_ok, lift]
    rw [component_loop p.q r.start hj]
    simp only [bind_tc_ok]
    try dsimp only
    simp only [pairBits, pWord, hs, Function.uncurry_apply_pair]

private theorem or_zero_iff (a b : U64) :
    (a ||| b) = 0#u64 ↔ a = 0#u64 ∧ b = 0#u64 := by
  rw [UScalar.eq_equiv_bv_eq (a ||| b) 0#u64, UScalar.eq_equiv_bv_eq a 0#u64,
    UScalar.eq_equiv_bv_eq b 0#u64]
  exact BitVec.or_eq_zero_iff

private theorem fold_or_zero {α : Type} (f : α → U64) (xs : List α) (b : U64) :
    xs.foldl (fun b x => b ||| f x) b = 0#u64 ↔ b = 0#u64 ∧ ∀ x ∈ xs, f x = 0#u64 := by
  induction xs generalizing b with
  | nil => simp
  | cons x xs ih => simp only [List.foldl_cons, ih, or_zero_iff, List.mem_cons, forall_eq_or_imp]; tauto

private theorem pair_bits_zero (p : pairing_product.AffinePair) (xs : List (Fin 6)) (b : U64 × U64) :
    ((xs.foldl (pairBits p) b).1 = 0#u64 ↔ b.1 = 0#u64 ∧ ∀ j ∈ xs, pWord p.p j = 0#u64) ∧
    ((xs.foldl (pairBits p) b).2 = 0#u64 ↔ b.2 = 0#u64 ∧ ∀ j ∈ xs, ∀ c, qWord p.q j c = 0#u64) := by
  induction xs generalizing b with
  | nil => simp
  | cons j xs ih =>
    obtain ⟨hp, hq⟩ := ih (pairBits p b j)
    rw [List.foldl_cons, hp, hq]
    simp only [pairBits, componentBits, fold_or_zero,
      List.mem_finRange, forall_true_left, or_zero_iff, List.mem_cons, forall_eq_or_imp]
    tauto

private def qZeroWords (q : blst.blst_p2_affine) : Prop := ∀ j c, qWord q j c = 0#u64

private instance (q : blst.blst_p2_affine) : Decidable (qZeroWords q) := by
  unfold qZeroWords
  infer_instance

private theorem infinity_raw (p : pairing_product.AffinePair) :
    pairing_product.AffinePair.is_infinite p =
      ok (decide (∀ j, Msm8.zeroWord p.p j) || decide (qZeroWords p.q)) := by
  obtain ⟨hp, hq⟩ := pair_bits_zero p (List.finRange 6) (0#u64, 0#u64)
  simp only [List.mem_finRange, forall_true_left, true_and] at hp hq
  simp only [pWord, or_zero_iff] at hp
  rw [pairing_product.AffinePair.is_infinite, pair_loop p (0#u64, 0#u64)]
  simp only [bind_tc_ok]
  change (if ((List.finRange 6).foldl (pairBits p) (0#u64, 0#u64)).1 = 0#u64
    then ok true else ok (decide (((List.finRange 6).foldl (pairBits p) (0#u64, 0#u64)).2 = 0#u64))) = _
  simp only [hp, hq, qZeroWords, Msm8.zeroWord]
  split <;> simp_all

private theorem fp2_ext (a b : blst.blst_fp2)
    (h : ∀ c : Fin 2, a.fp.val[c.val]'(by rw [a.fp.property]; exact c.isLt) =
      b.fp.val[c.val]'(by rw [b.fp.property]; exact c.isLt)) : a = b := by
  have he : a.fp = b.fp := by
    apply Subtype.ext
    apply List.ext_getElem
    · rw [a.fp.property, b.fp.property]
    · intro i hi hi'
      exact h ⟨i, by simpa only [a.fp.property] using hi⟩
  cases a
  cases b
  exact congrArg blst.blst_fp2.mk he

private theorem q_zero_iff (q : blst.blst_p2_affine) :
    qZeroWords q ↔ q = ⟨Kzg.fp2Encode Fp2.zero, Kzg.fp2Encode Fp2.zero⟩ := by
  have he : qZeroWords q ↔ ∀ c : Fin 2,
      (⟨q.x.fp.val[c.val]'(by rw [q.x.fp.property]; exact c.isLt),
        q.y.fp.val[c.val]'(by rw [q.y.fp.property]; exact c.isLt)⟩ : blst.blst_p1_affine) =
        ⟨Kzg.fpEncode Fp.zero, Kzg.fpEncode Fp.zero⟩ := by
    simp only [← Msm8.all_zero_words_iff, Msm8.zeroWord]
    unfold qZeroWords qWord
    simp only [or_zero_iff]
    exact forall_comm
  rw [he]
  constructor
  · intro h
    have hx : q.x = Kzg.fp2Encode Fp2.zero := by
      apply fp2_ext
      intro c
      have hc := congrArg blst.blst_p1_affine.x (h c)
      fin_cases c <;> simpa [Kzg.fp2Encode, Fp2.zero] using hc
    have hy : q.y = Kzg.fp2Encode Fp2.zero := by
      apply fp2_ext
      intro c
      have hc := congrArg blst.blst_p1_affine.y (h c)
      fin_cases c <;> simpa [Kzg.fp2Encode, Fp2.zero] using hc
    cases q
    exact congrArg₂ blst.blst_p2_affine.mk hx hy
  · intro h c
    subst q
    fin_cases c <;> rfl

private theorem q_zero_read_infinity (q : blst.blst_p2_affine)
    (hq : q = Kzg.g2Affine (Kzg.g2ReadAffine q)) :
    qZeroWords q ↔ (Kzg.g2ReadAffine q).isInfinity = true := by
  rw [q_zero_iff]
  constructor
  · intro h
    rw [h]
    simp only [Kzg.g2ReadAffine, Kzg.fp2Read_fp2Encode,
      show Fp2.zero.isZero = true from rfl, Bool.and_self, if_true]
    rfl
  · intro h
    calc
      q = Kzg.g2Affine (Kzg.g2ReadAffine q) := hq
      _ = _ := by
        unfold Kzg.g2Affine G2.toAffine
        rw [show (Kzg.g2ReadAffine q).z.isZero = true from h]
        rfl

theorem affinePair_is_infinite (p : pairing_product.AffinePair)
    (hp : Kzg.G1AffineValid p.p) (hq : Kzg.G2AffineValid p.q) :
    pairing_product.AffinePair.is_infinite p =
      ok ((Kzg.g1ReadAffine p.p).isInfinity || (Kzg.g2ReadAffine p.q).isInfinity) := by
  rw [infinity_raw]
  congr 1
  apply congrArg₂ Bool.or
  · apply Bool.eq_iff_iff.mpr
    simp only [decide_eq_true_eq]
    exact Msm8.all_zero_words_read_infinity p.p hp.1
  · apply Bool.eq_iff_iff.mpr
    simp only [decide_eq_true_eq]
    exact q_zero_read_infinity p.q hq.1

end

end LeanBlsSimd.PairingProduct
