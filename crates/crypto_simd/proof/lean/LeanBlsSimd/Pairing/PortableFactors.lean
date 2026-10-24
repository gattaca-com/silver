import LeanBlsSimd.Pairing.ProjectiveLine
import LeanBlsSimd.Portable.G1.Coordinates

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd

namespace LeanBlsSimd.Pairing.PortableLines

set_option maxRecDepth 2000
set_option exponentiation.threshold 4096

def pointRow (p : Bls.G1) : Array portable.fp.Fp 3#usize :=
  Array.make 3#usize [(Kzg.fpEncode (p.z * p.z * p.z)).l,
    (Kzg.fpEncode (p.x * p.z)).l, (Kzg.fpEncode p.y).l] (by rfl)

def PointsRep (raw : Array portable.g1.G1 2#usize) (points : Fin 2 → Bls.G1) : Prop :=
  ∀ i : Fin 2, raw.val[i.val]'(by simp; omega) = Portable.G1.encode (points i)

theorem factors_body [RuntimeFeatures] (raw : Array portable.g1.G1 2#usize)
    (points : Fin 2 → Bls.G1) (hp : PointsRep raw points)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) (k : Usize) (hk : k.val < 2) :
    ∃ k', k'.val = k.val + 1 ∧
      portable.pairing.PairingLines.miller_loop_loop0.body raw factors k =
        ok (cont (factors.set k (pointRow (points ⟨k.val, hk⟩)), k')) := by
  have hin : k.val + 1 < 2^UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    scalar_tac
  let k' : Usize := UScalar.ofNatCore (k.val + 1) hin
  have hinc : k + 1#usize = ok k' := add_ok _ _ hin
  have htest : k < 2#usize := by simpa using hk
  have hpoint := hp ⟨k.val, hk⟩
  refine ⟨k', rfl, ?_⟩
  simp only [portable.pairing.PairingLines.miller_loop_loop0.body, htest, if_true,
    index_usize_eq raw k hk, bind_tc_ok]
  rw [hpoint]
  simp only [Portable.G1.encode, portable.fp.Fp.square, Portable.Fp.mul_encoded,
    bind_tc_ok, update_eq factors k _ hk, hinc, pointRow]

theorem factors_loop [RuntimeFeatures] (raw : Array portable.g1.G1 2#usize)
    (points : Fin 2 → Bls.G1) (hp : PointsRep raw points)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) :
    portable.pairing.PairingLines.miller_loop_loop0 raw factors 0#usize =
      ok ((factors.set 0#usize (pointRow (points 0))).set 1#usize (pointRow (points 1))) := by
  let f1 := factors.set 0#usize (pointRow (points 0))
  let f2 := f1.set 1#usize (pointRow (points 1))
  obtain ⟨k1, hk1, h1⟩ := factors_body raw points hp factors 0#usize (by decide)
  have he1 : k1 = 1#usize := by scalar_tac
  subst k1
  obtain ⟨k2, hk2, h2⟩ := factors_body raw points hp f1 1#usize (by decide)
  have he2 : k2 = 2#usize := by scalar_tac
  subst k2
  rw [portable.pairing.PairingLines.miller_loop_loop0, loop.eq_1]
  simp only [h1]
  change portable.pairing.PairingLines.miller_loop_loop0 raw f1 1#usize = ok f2
  rw [portable.pairing.PairingLines.miller_loop_loop0, loop.eq_1]
  simp only [h2]
  change portable.pairing.PairingLines.miller_loop_loop0 raw f2 2#usize = ok f2
  rw [portable.pairing.PairingLines.miller_loop_loop0, loop.eq_1]
  simp only [portable.pairing.PairingLines.miller_loop_loop0.body,
    show ¬ (2#usize < 2#usize) from by decide, if_false]

theorem factors_rep (points : Fin 2 → Bls.G1)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) :
    FactorsRep ((factors.set 0#usize (pointRow (points 0))).set 1#usize (pointRow (points 1)))
      (g1Factors points) := by
  intro pair i
  fin_cases pair <;> fin_cases i <;>
    simp [Aeneas.Std.Array.set, Aeneas.Std.Array.make, pointRow, g1Factors]

theorem factors_refines [RuntimeFeatures] (raw : Array portable.g1.G1 2#usize)
    (points : Fin 2 → Bls.G1) (hp : PointsRep raw points)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) :
    ∃ out, portable.pairing.PairingLines.miller_loop_loop0 raw factors 0#usize = ok out ∧
      FactorsRep out (g1Factors points) :=
  ⟨_, factors_loop raw points hp factors, factors_rep points factors⟩

end LeanBlsSimd.Pairing.PortableLines
