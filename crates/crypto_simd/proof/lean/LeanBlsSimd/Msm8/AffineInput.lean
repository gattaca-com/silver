import LeanBlsSimd.Msm8.PointRowsRep
import LeanBlsSimd.Kzg.FpEncoding

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8

open EthLib.Cryptography Bls

theorem affine_read_finite (point : blst.blst_p1_affine)
    (hfinite : (Kzg.g1ReadAffine point).isInfinity ≠ true) :
    Kzg.g1ReadAffine point = ⟨Kzg.fpRead point.x, Kzg.fpRead point.y, Fp.one⟩ := by
  unfold Kzg.g1ReadAffine at hfinite ⊢
  dsimp only at hfinite ⊢
  split
  · rename_i h
    exact False.elim (hfinite (by simp only [h, if_true]; rfl))
  · rfl

theorem affine_finite_encoding (point : blst.blst_p1_affine)
    (hp : Kzg.G1AffineValid point)
    (hfinite : (Kzg.g1ReadAffine point).isInfinity ≠ true) :
    point.x = Kzg.fpEncode (Kzg.fpRead point.x) ∧
      point.y = Kzg.fpEncode (Kzg.fpRead point.y) := by
  have h := hp.1
  rw [affine_read_finite point hfinite] at h
  unfold Kzg.g1Affine at h
  rw [Kzg.g1_toAffine_of_one] at h
  exact ⟨congrArg blst.blst_p1_affine.x h, congrArg blst.blst_p1_affine.y h⟩

theorem val64_encoded_fp (a : ZMod Fp.modulus) :
    val64 (ofArray ofU64 (Kzg.fpEncode a).l) = (a * 2 ^ 384).val := by
  have hw : ofArray ofU64 (Kzg.fpEncode a).l = (DecompressG2.blstFp a).l := by
    have h := congrArg (fun f : blst.blst_fp => ofArray ofU64 f.l) (Kzg.fpEncode_eq_bls a)
    simpa only [DecompressG2.toBlstFp, ofArray_toArray_ofU64] using h
  rw [hw]
  exact DecompressG2.val64_blstFp a

theorem val64_fp_word (word : blst.blst_fp) (a : ZMod Fp.modulus)
    (h : word = Kzg.fpEncode a) :
    val64 (ofArray ofU64 word.l) = (a * 2 ^ 384).val := by
  subst word
  exact val64_encoded_fp a

theorem affine_finite_words (point : blst.blst_p1_affine)
    (hp : Kzg.G1AffineValid point)
    (hfinite : (Kzg.g1ReadAffine point).isInfinity ≠ true) :
    val64 (ofArray ofU64 point.x.l) =
      (fun a : ZMod Fp.modulus => (a * 2 ^ 384).val) (Kzg.fpRead point.x) ∧
    val64 (ofArray ofU64 point.y.l) =
      (fun a : ZMod Fp.modulus => (a * 2 ^ 384).val) (Kzg.fpRead point.y) := by
  obtain ⟨hx, hy⟩ := affine_finite_encoding point hp hfinite
  exact ⟨val64_fp_word point.x (show ZMod Fp.modulus from Kzg.fpRead point.x) hx,
    val64_fp_word point.y (show ZMod Fp.modulus from Kzg.fpRead point.y) hy⟩

theorem sigma_affine_valid (x y : ZMod Fp.modulus) (h : G1.Valid ⟨x, y, Fp.one⟩) :
    G1.Valid ⟨x * (beta : ZMod Fp.modulus), y, Fp.one⟩ := by
  change G1.curve.Nonsingular ![(x : ZMod Fp.modulus), y, 1] at h
  change G1.curve.Nonsingular ![(x : ZMod Fp.modulus) * (beta : ZMod Fp.modulus), y, 1]
  rw [WeierstrassCurve.Jacobian.nonsingular_some] at h ⊢
  simpa only [mul_comm] using G1Spec.nonsingular_sigma h

theorem sigma_affine_toPoint (x y : ZMod Fp.modulus) (h : G1.Valid ⟨x, y, Fp.one⟩) :
    G1.toPoint ⟨x * (beta : ZMod Fp.modulus), y, Fp.one⟩ = G1Spec.sigma (G1.toPoint ⟨x, y, Fp.one⟩) := by
  have hs := sigma_affine_valid x y h
  change WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![(x : ZMod Fp.modulus) * (beta : ZMod Fp.modulus), y, 1] =
    G1Spec.sigma (WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![(x : ZMod Fp.modulus), y, 1])
  rw [WeierstrassCurve.Jacobian.Point.toAffine_some hs,
    WeierstrassCurve.Jacobian.Point.toAffine_some h]
  simp only [G1Spec.sigma, mul_comm]

theorem transformed_affine_valid (x y : ZMod Fp.modulus) (endomorphism negative : Bool)
    (h : G1.Valid ⟨x, y, Fp.one⟩) :
    G1.Valid ⟨if endomorphism then x * (beta : ZMod Fp.modulus) else x, if negative then -y else y, Fp.one⟩ := by
  apply signed_affine_valid
  cases endomorphism
  · exact h
  · exact sigma_affine_valid x y h

theorem transformed_affine_toPoint (x y : ZMod Fp.modulus) (endomorphism negative : Bool)
    (h : G1.Valid ⟨x, y, Fp.one⟩) :
    G1.toPoint ⟨if endomorphism then x * (beta : ZMod Fp.modulus) else x, if negative then -y else y, Fp.one⟩ =
      let point := if endomorphism then G1Spec.sigma (G1.toPoint ⟨x, y, Fp.one⟩)
        else G1.toPoint ⟨x, y, Fp.one⟩
      if negative then -point else point := by
  have hv : G1.Valid ⟨if endomorphism then x * (beta : ZMod Fp.modulus) else x, y, Fp.one⟩ := by
    cases endomorphism
    · exact h
    · exact sigma_affine_valid x y h
  have hs := signed_affine_toPoint (if endomorphism then x * (beta : ZMod Fp.modulus) else x) y negative hv
  change G1.toPoint ⟨if endomorphism then x * (beta : ZMod Fp.modulus) else x,
      if negative then -y else y, Fp.one⟩ = _ at hs
  refine hs.trans ?_
  cases endomorphism
  · rfl
  · simp only [if_true, sigma_affine_toPoint x y h]

def transformedPoint (point : blst.blst_p1_affine) (endomorphism negative : Bool) :
    G1Spec.E.Point :=
  let P := G1.toPoint (Kzg.g1ReadAffine point)
  let Q := if endomorphism then G1Spec.sigma P else P
  if negative then -Q else Q

local instance affineInputAffineInhabited0 : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

theorem push_blst_rep (s : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool)
    (hn : negated.val.length = points.val.length)
    (h31 : s.len.val + points.val.length < 2 ^ 31)
    (hcap : s.len.val + points.val.length ≤ s.rows.val.length / 2)
    (hp : ∀ j, j < points.val.length → Kzg.G1AffineValid points.val[j]!)
    (hf : ∀ j, j < points.val.length → (Kzg.g1ReadAffine points.val[j]!).isInfinity ≠ true) :
    ∃ out, msm8.store.PointStore.push_blst s points negated endomorphism = ok out ∧
      out.len.val = s.len.val + points.val.length ∧
      ∀ j, j < points.val.length → RowRep (pointRows out) (s.len.val + j)
        (transformedPoint points.val[j]! endomorphism negated.val[j]!) := by
  let x (j : ℕ) : ZMod Fp.modulus := Kzg.fpRead points.val[j]!.x
  let y (j : ℕ) : ZMod Fp.modulus := Kzg.fpRead points.val[j]!.y
  have hw (j : ℕ) (hj : j < points.val.length) :
      (blstPointWords points)[j]! =
        (ofArray ofU64 points.val[j]!.x.l, ofArray ofU64 points.val[j]!.y.l) := by
    rw [getElem!_pos (blstPointWords points) j (by simpa using hj)]
    simp only [blstPointWords, List.getElem_map, getElem!_pos points.val j hj]
  obtain ⟨out, hout, hlen, hrows⟩ := push_blst_holds s points negated endomorphism hn h31 hcap x y
    (fun j hj => by rw [hw j hj]; exact (affine_finite_words _ (hp j hj) (hf j hj)).1)
    (fun j hj => by rw [hw j hj]; exact (affine_finite_words _ (hp j hj) (hf j hj)).2)
  refine ⟨out, hout, hlen, ?_⟩
  intro j hj
  have hvalid : G1.Valid ⟨x j, y j, Fp.one⟩ := by
    have h := Kzg.g1_groupValid_of_noninfinity (hp j hj).2 (hf j hj)
    rwa [affine_read_finite _ (hf j hj)] at h
  refine ⟨if endomorphism then x j * (beta : ZMod Fp.modulus) else x j,
    if negated.val[j]! then -y j else y j, hrows j hj,
    transformed_affine_valid (x j) (y j) endomorphism negated.val[j]! hvalid, ?_⟩
  have h := transformed_affine_toPoint (x j) (y j) endomorphism negated.val[j]! hvalid
  unfold transformedPoint
  rw [affine_read_finite _ (hf j hj)]
  exact h

theorem writePoints_read_before (rows : List Limbs) (base n : ℕ)
    (point : ℕ → Limbs × Limbs) (index : ℕ) (hi : index < base) :
    readPoint ((List.range n).foldl (fun rows j => writePoint rows (base + j) (point j)) rows) index =
      readPoint rows index := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [List.range_succ, List.foldl_append]
    simp only [List.foldl_cons, List.foldl_nil]
    rw [readPoint_writePoint_other _ _ _ _ (by omega), ih]

theorem push_blst_frame (s out : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool)
    (hn : negated.val.length = points.val.length)
    (h31 : s.len.val + points.val.length < 2 ^ 31)
    (hcap : s.len.val + points.val.length ≤ s.rows.val.length / 2)
    (hout : msm8.store.PointStore.push_blst s points negated endomorphism = ok out)
    (index : ℕ) (hi : index < s.len.val) :
    readPoint (pointRows out) index = readPoint (pointRows s) index := by
  obtain ⟨next, hnext, hrows, _, _⟩ := push_blst_flat_refines s points negated endomorphism hn h31 hcap
  have heq := Result.ok.inj (hnext.symm.trans hout)
  subst next
  rw [hrows]
  simp only [pushFlatModel, Nat.zero_add]
  exact writePoints_read_before _ _ _ _ index hi

end LeanBlsSimd.Msm8
