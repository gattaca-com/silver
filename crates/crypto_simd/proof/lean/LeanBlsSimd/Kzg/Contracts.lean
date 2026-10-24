import LeanBlsSimd.Kzg.PortableFp
import LeanBlsSimd.Kzg.PairingContract
import LeanBlsSimd.Kzg.Decoder

open silver_crypto_simd

namespace LeanBlsSimd.Kzg

/-- Internal wrapper for the remaining pairing premise. -/
structure ComponentContracts [RuntimeFeatures] : Prop where
  pairing : PairingCorrect

end LeanBlsSimd.Kzg
