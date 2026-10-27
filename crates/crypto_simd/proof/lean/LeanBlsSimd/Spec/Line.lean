import LeanBlsSimd.Spec.Fp12

open EthLib.Cryptography

namespace LeanBlsSimd.Portable

namespace Fp6

def sparse (x y : Bls.Fp2) : Bls.Fp6 := ⟨x, y, Bls.Fp2.zero⟩

end Fp6

namespace Fp12

def line (x y z : Bls.Fp2) : Bls.Fp12 :=
  ⟨Fp6.sparse x y, Fp6.sparse Bls.Fp2.zero z⟩

end Fp12

end LeanBlsSimd.Portable
