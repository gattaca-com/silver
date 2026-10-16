import LeanBlsSimd.Kzg.SpecExternals
import LeanBlsSimd.Kzg.G1Arithmetic
import LeanBlsSimd.Kzg.SetupValidity

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open scoped EthCryptographySpecs.Bls.Fr

namespace LeanBlsSimd.Kzg.Controls

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 512

private theorem encode_shift_ne (x : Fr) : frEncode (x + 1) ≠ frEncode x := by
  intro h
  have hr := congrArg frRead h
  rw [frRead_frEncode, frRead_frEncode] at hr
  exact one_ne_zero (add_left_cancel (hr.trans (add_zero x).symm))

@[reducible] def rejectG2Setup : KzgExternals :=
  { specExternals with uncompressG2 := fun _ => none }

theorem rejectG2Setup_rejected : ¬ BlstCorrect rejectG2Setup := by
  intro h
  have he := h.g2_decode trusted_setup.G2_MONOMIAL_0 (Or.inl rfl)
  have hv : specG2Verdict trusted_setup.G2_MONOMIAL_0 =
      some (g2Affine SetupPoints.g2Point0) := by
    simp [specG2Verdict, SetupPoints.g2_0_decoded, SetupPoints.g2_0_subgroup, Except.toOption]
  change ok none = ok (specG2Verdict trusted_setup.G2_MONOMIAL_0) at he
  rw [hv] at he
  cases he

def noncanonicalBytes : Aeneas.Std.Array U8 32#usize :=
  ⟨List.replicate 32 255#u8, by simp⟩

@[reducible] def acceptNoncanonical : KzgExternals :=
  { specExternals with frFromBytes := fun _ => ok (some (frEncode 0)) }

theorem acceptNoncanonical_rejected : ¬ BlstCorrect acceptNoncanonical := by
  intro h
  have he := h.fr_bytes noncanonicalBytes
  have hv : (bytesToBlsField (arrayBytes noncanonicalBytes)).toOption = none := by rfl
  change ok (some (frEncode 0)) = ok ((bytesToBlsField _).toOption.map frEncode) at he
  rw [hv] at he
  cases he

@[reducible] def shiftInteger : KzgExternals :=
  { specExternals with frFromU64 := fun x => ok (frEncode (Fr.ofNat x.val + 1)) }

theorem shiftInteger_rejected : ¬ BlstCorrect shiftInteger := by
  intro h
  exact encode_shift_ne _ (Result.ok.inj (h.fr_u64 0#u64))

@[reducible] def shiftAdd : KzgExternals :=
  { specExternals with frAdd := fun x y => ok (frEncode (frRead x + frRead y + 1)) }

theorem shiftAdd_rejected : ¬ BlstCorrect shiftAdd := by
  intro h
  have he := h.fr_add 0 0
  change ok (frEncode (frRead (frEncode 0) + frRead (frEncode 0) + 1)) =
    ok (frEncode ((0 : Fr) + 0)) at he
  simp only [frRead_frEncode] at he
  exact encode_shift_ne _ (Result.ok.inj he)

@[reducible] def shiftSub : KzgExternals :=
  { specExternals with frSub := fun x y => ok (frEncode (frRead x - frRead y + 1)) }

theorem shiftSub_rejected : ¬ BlstCorrect shiftSub := by
  intro h
  have he := h.fr_sub 0 0
  change ok (frEncode (frRead (frEncode 0) - frRead (frEncode 0) + 1)) =
    ok (frEncode ((0 : Fr) - 0)) at he
  simp only [frRead_frEncode] at he
  exact encode_shift_ne _ (Result.ok.inj he)

@[reducible] def shiftMul : KzgExternals :=
  { specExternals with frMul := fun x y => ok (frEncode (frRead x * frRead y + 1)) }

theorem shiftMul_rejected : ¬ BlstCorrect shiftMul := by
  intro h
  have he := h.fr_mul 0 0
  change ok (frEncode (frRead (frEncode 0) * frRead (frEncode 0) + 1)) =
    ok (frEncode ((0 : Fr) * 0)) at he
  simp only [frRead_frEncode] at he
  exact encode_shift_ne _ (Result.ok.inj he)

@[reducible] def shiftInverse : KzgExternals :=
  { specExternals with frInverse := fun x => ok (frEncode ((frRead x).inverse + 1)) }

theorem shiftInverse_rejected : ¬ BlstCorrect shiftInverse := by
  intro h
  have he := h.fr_inverse 1 (by decide)
  change ok (frEncode ((frRead (frEncode 1)).inverse + 1)) = ok (frEncode (1 : Fr).inverse) at he
  simp only [frRead_frEncode] at he
  exact encode_shift_ne _ (Result.ok.inj he)

@[reducible] def shiftHash : KzgExternals :=
  { specExternals with hashToFr := fun b => ok (frEncode (Fr.hashToBlsField (bytes b.val) + 1)) }

theorem shiftHash_rejected : ¬ BlstCorrect shiftHash := by
  intro h
  exact encode_shift_ne _ (Result.ok.inj (h.hash ⟨[], by simp⟩))

def wrongPoint : G1 := ⟨Fp.zero, Fp.zero, Fp.one⟩

private theorem zero_jacobian_valid : G1Valid (g1ReadJacobian (g1Jacobian G1.zero)) := by
  rw [g1ReadJacobian_g1Jacobian]
  exact g1Valid_zero

@[reducible] def nonzeroAffineAtZero : KzgExternals :=
  { specExternals with g1ToAffine := fun _ => ok ⟨fpEncode Fp.one, fpEncode Fp.one⟩ }

theorem nonzeroAffineAtZero_rejected : ¬ BlstCorrect nonzeroAffineAtZero := by
  intro h
  have he := h.g1_affine (g1Jacobian G1.zero) (g1Jacobian_reduced _) zero_jacobian_valid
  change ok (blst.blst_p1_affine.mk (fpEncode Fp.one) (fpEncode Fp.one)) =
    ok (g1Affine (g1ReadJacobian (g1Jacobian G1.zero))) at he
  rw [g1ReadJacobian_g1Jacobian] at he
  have hx := congrArg (fun p : blst.blst_p1_affine => fpRead p.x) (Result.ok.inj he)
  change fpRead (fpEncode Fp.one) = fpRead (fpEncode Fp.zero) at hx
  rw [fpRead_fpEncode, fpRead_fpEncode] at hx
  exact (by decide : Fp.one ≠ Fp.zero) hx

@[reducible] def nonzeroAddAtZero : KzgExternals :=
  { specExternals with g1Add := fun _ _ => ok (g1Jacobian wrongPoint) }

theorem nonzeroAddAtZero_rejected : ¬ BlstCorrect nonzeroAddAtZero := by
  intro h
  obtain ⟨result, he, hr⟩ := h.g1_add (g1Jacobian G1.zero) (g1Jacobian G1.zero)
    (g1Jacobian_reduced _) (g1Jacobian_reduced _) zero_jacobian_valid zero_jacobian_valid
  change ok (g1Jacobian wrongPoint) = ok result at he
  have he' := Result.ok.inj he
  subst result
  have hi := hr.2.1
  simp only [g1ReadJacobian_g1Jacobian] at hi
  change false = true at hi
  cases hi

@[reducible] def nonzeroNegAtZero : KzgExternals :=
  { specExternals with g1Neg := fun _ => ok (g1Jacobian wrongPoint) }

theorem nonzeroNegAtZero_rejected : ¬ BlstCorrect nonzeroNegAtZero := by
  intro h
  obtain ⟨result, he, hr⟩ := h.g1_neg (g1Jacobian G1.zero)
    (g1Jacobian_reduced _) zero_jacobian_valid
  change ok (g1Jacobian wrongPoint) = ok result at he
  have he' := Result.ok.inj he
  subst result
  have hi := hr.2.1
  rw [g1ReadJacobian_g1Jacobian, g1ReadJacobian_g1Jacobian] at hi
  change false = true at hi
  cases hi

@[reducible] def eraseG2Neg : KzgExternals :=
  { specExternals with g2Neg := fun _ => ok (g2Affine G2.zero) }

theorem eraseG2Neg_rejected : ¬ BlstCorrect eraseG2Neg := by
  intro h
  have he := h.g2_neg (g2Affine SetupPoints.g2Point0) setup_g2_zero_valid
  change ok (g2Affine G2.zero) =
    ok (g2Affine (G2.neg (g2ReadAffine (g2Affine SetupPoints.g2Point0)))) at he
  rw [setup_g2_zero_roundtrip] at he
  have hread := congrArg g2ReadAffine (Result.ok.inj he)
  rw [setup_g2_neg_zero_roundtrip] at hread
  have hz : g2ReadAffine (g2Affine G2.zero) = G2.zero := by
    simp only [g2ReadAffine, g2Affine, G2.toAffine, G2.zero, fp2Read_fp2Encode]
    rfl
  rw [hz] at hread
  have hi := congrArg G2.isInfinity hread
  have hn : (G2.neg SetupPoints.g2Point0).isInfinity = false := by decide +kernel
  rw [hn] at hi
  contradiction

@[reducible] def nonzeroEmptyLincomb : KzgExternals :=
  { specExternals with g1Lincomb := fun _ _ scratch => ok (g1Jacobian wrongPoint, scratch) }

theorem nonzeroEmptyLincomb_rejected : ¬ BlstCorrect nonzeroEmptyLincomb := by
  intro h
  let scratch : blst_ops.LincombScratch :=
    ⟨alloc.vec.Vec.new _, alloc.vec.Vec.new _, alloc.vec.Vec.new _⟩
  obtain ⟨result, scratch', he, hr⟩ := h.lincomb ⟨[], by simp⟩ ⟨[], by simp⟩ scratch
    rfl (by simp) (by simp)
  change ok (g1Jacobian wrongPoint, scratch) = ok (result, scratch') at he
  have he' := congrArg Prod.fst (Result.ok.inj he)
  dsimp only at he'
  subst result
  have hi := hr.2.1
  rw [g1ReadJacobian_g1Jacobian] at hi
  change false = true at hi
  cases hi

@[reducible] def flipPairing : KzgExternals :=
  { specExternals with
    pairingCheck := fun p q p' q' =>
      ok (Bool.not (Bls.pairingCheck #[(g1ReadAffine p, g2ReadAffine q),
        (g1ReadAffine p', g2ReadAffine q')])) }

theorem flipPairing_rejected : ¬ BlstCorrect flipPairing := by
  intro h
  have he := h.pairing (g1Affine G1.zero) (g2Affine SetupPoints.g2Point0)
    (g1Affine G1.zero) (g2Affine SetupPoints.g2Point0)
    (g1Affine_valid g1Valid_zero) setup_g2_zero_valid
    (g1Affine_valid g1Valid_zero) setup_g2_zero_valid
  have hb := Result.ok.inj he
  exact (Bool.not_eq_self _).mp hb

@[reducible] def wrongScalarG1 : KzgExternals :=
  { specExternals with simdAvailable := false, uncompressG1 := fun _ => some (g1Affine G1.zero) }

def invalidG1Bytes : Aeneas.Std.Array U8 48#usize :=
  ⟨List.replicate 48 0#u8, by simp⟩

theorem wrongScalarG1_rejected : ¬ G1DecoderCorrect wrongScalarG1 := by
  intro h
  let inputs : Slice (Aeneas.Std.Array U8 48#usize) := ⟨[invalidG1Bytes], by simp; scalar_tac⟩
  let out : Slice (Option blst.blst_p1_affine) := ⟨[none], by simp; scalar_tac⟩
  obtain ⟨result, hr, hv⟩ := h inputs out rfl
  obtain ⟨result', hr', _, hv'⟩ :=
    @UncompressG1.uncompress_in_g1_eq_spec_or_blst wrongScalarG1.toBlsExternals inputs out rfl
  rw [hr] at hr'
  cases hr'
  have h0 := hv' ⟨0, by simp [inputs]⟩
  have hk : @UncompressG1.usesKernelAt wrongScalarG1.toBlsExternals inputs 0 = false := by
    simp [UncompressG1.usesKernelAt, UncompressG1.usesKernel]
  rw [hk, hv] at h0
  have hn : specVerdict invalidG1Bytes = none := by rfl
  simp [inputs, hn] at h0

end LeanBlsSimd.Kzg.Controls
