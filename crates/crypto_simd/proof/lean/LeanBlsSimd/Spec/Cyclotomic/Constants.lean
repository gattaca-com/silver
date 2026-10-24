import LeanBlsSimd.Spec.Fp6Noncube
import LeanBlsSimd.Spec.Cyclotomic.Frobenius

namespace LeanBlsSimd.Cyclotomic.Bls

open LeanBlsSimd.Fp6Field (xi)
open LeanBlsSimd EthLib.Cryptography EthLib.Cryptography.Bls

abbrev K := LeanBlsSimd.Fp2Field

abbrev p := Fp.modulus

abbrev q := p ^ 2

theorem xi_power (e : ℕ) (he : e < 2 ^ 762) :
    toFp2 (QuadraticAlgebra.omega : K) (powBy mulFp2 (1, 0) 762 (1, 1) e) = xi ^ e := by
  exact map_powBy (toFp2 (QuadraticAlgebra.omega : K))
    (toFp2_mulFp2 Fp2Field.natCast_modulus Fp2Field.omega_sq)
    (by simp [toFp2]) 762 (1, 1) e he

def deltaWord : ℕ := 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620351

noncomputable def delta : K := deltaWord

theorem xi_sixth : xi ^ ((q - 1) / 6) = delta := by
  have h := xi_power ((q - 1) / 6) (by decide +kernel)
  rw [show powBy mulFp2 (1, 0) 762 (1, 1) ((q - 1) / 6) = (deltaWord, 0) by decide +kernel] at h
  simpa [toFp2, delta] using h.symm

theorem delta_polynomial : delta ^ 2 - delta + 1 = 0 := by
  have h : (deltaWord : ZMod p) ^ 2 - deltaWord + 1 = 0 := by decide +kernel
  have hm := congrArg (algebraMap (ZMod p) K) h
  simpa [delta, map_add, map_sub, map_pow] using hm

theorem xi_half : xi ^ ((q - 1) / 2) = -1 := by
  have h := xi_power ((q - 1) / 2) (by decide +kernel)
  rw [show powBy mulFp2 (1, 0) 762 (1, 1) ((q - 1) / 2) = (p - 1, 0) by decide +kernel] at h
  have hm : ((p - 1 : ℕ) : K) = -1 := by
    rw [Nat.cast_sub (by decide : 1 ≤ p), Fp2Field.natCast_modulus]
    simp
  simpa [toFp2, hm] using h.symm

end LeanBlsSimd.Cyclotomic.Bls
