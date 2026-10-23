import LeanBlsSimd.Proofs.Fp8Holds

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

def TWO_POW_448_MOD_P : List ℕ :=
  [0x7fde37dba9366, 0x4e27525bc342b, 0x1f5b1e9778489, 0xb872b2b91b9dc,
   0xb206f497dfcaf, 0x4137cc89a9b0b, 0xd9d20d7e39959, 0x000000000411c]

theorem two_pow_448_mod_p_value :
    val (.ofList TWO_POW_448_MOD_P) = 2 ^ 448 % Fp.modulus := by decide +kernel

theorem two_pow_448_mod_p_inv : Fp8Inv (.ofList TWO_POW_448_MOD_P) :=
  ⟨by decide, by decide +kernel⟩

theorem blst_conversion_exponents : 2 ^ 384 * 2 ^ 448 = R * R := by decide +kernel

namespace Fp8

theorem from_blst_holds (words : Vector (Vector UInt64 6) 8) (l : Fin 8)
    (a : ZMod Fp.modulus) (h : val64 words[l] = (a * 2 ^ 384).val) :
    ((load (words.map unpack52)).mul (splat_limbs (.ofList TWO_POW_448_MOD_P))).Holds l a := by
  have hw : val64 words[l] < Fp.modulus := by rw [h]; exact ZMod.val_lt _
  have hl : Fp8Inv ((load (words.map unpack52)).lane l) := by
    simp only [lane_load, Fin.getElem_fin, Vector.getElem_map]
    exact inv_unpack52 hw
  have hc : Fp8Inv ((splat_limbs (.ofList TWO_POW_448_MOD_P)).lane l) := by
    rw [lane_splat_limbs]
    exact two_pow_448_mod_p_inv
  simp only [Fin.getElem_fin] at h
  refine ⟨inv_mul hl hc, ?_⟩
  rw [decode_lane_mul hl hc, lane_load]
  simp only [Fin.getElem_fin, Vector.getElem_map]
  rw [lane_splat_limbs,
    decode, (unpack52_spec _).2, h, ZMod.natCast_zmod_val, decode,
    two_pow_448_mod_p_value, ZMod.natCast_mod, Nat.cast_pow, Nat.cast_ofNat]
  have hexp : (2 : ZMod Fp.modulus) ^ 384 * 2 ^ 448 = (R : ZMod Fp.modulus) * R := by
    simpa only [Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat] using
      congrArg (fun n : ℕ => (n : ZMod Fp.modulus)) blst_conversion_exponents
  calc
    (a * 2 ^ 384 * (R : ZMod Fp.modulus)⁻¹) * (2 ^ 448 * (R : ZMod Fp.modulus)⁻¹) =
        a * ((2 ^ 384 * 2 ^ 448) * ((R : ZMod Fp.modulus)⁻¹ * (R : ZMod Fp.modulus)⁻¹)) := by
      have rearrange (b c d : ZMod Fp.modulus) :
          (a * b * c) * (d * c) = a * ((b * d) * (c * c)) := by ring
      exact rearrange _ _ _
    _ = a := by rw [hexp]; field_simp [R_ne_zero]

end Fp8
end LeanBlsSimd
