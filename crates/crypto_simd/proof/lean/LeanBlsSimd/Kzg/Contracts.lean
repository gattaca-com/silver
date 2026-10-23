import LeanBlsSimd.Kzg.ScalarContracts
import LeanBlsSimd.Kzg.ShaContracts
import LeanBlsSimd.Kzg.PortableFp
import LeanBlsSimd.Kzg.PortableMsmContract
import LeanBlsSimd.Kzg.PairingContract
import LeanBlsSimd.Kzg.Decoder

open silver_crypto_simd

namespace LeanBlsSimd.Kzg

/-- Internal bundle for composing the explicit phase-2 headline premises. -/
structure ComponentContracts [RuntimeFeatures] : Prop where
  fr : FrCorrect
  bytes : FrBytesCorrect
  sha : ShaCorrect
  fp : PortableFpCorrect
  g1 : LeanBlsSimd.G1DecoderCorrect
  msm : PortableMsmCorrect
  pairing : PairingCorrect

end LeanBlsSimd.Kzg
