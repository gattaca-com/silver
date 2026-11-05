import LeanBlsSimd.Sha256.GeneratedBytes

namespace LeanBlsSimd.Sha256.Spec

open EthLib.Cryptography

theorem digest_size (state : Array UInt32) : (digest state).size = 32 := by
  simp [digest, Hash.Sha256.digest, ByteArray.size]

private theorem digest_byte (x : UInt32) (b : Nat) (hb : b < 4) :
    (x >>> (24 - 8 * UInt32.ofNat b)).toUInt8 = UInt8.ofNat (x.toNat >>> (8*(3-b))) := by
  apply UInt8.toNat_inj.mp
  rcases b with _|_|_|_|b <;> first | omega | simp [UInt32.toNat_shiftRight]

theorem digest_get (state : Array UInt32) (w b : Nat) (hw : w < 8) (hb : b < 4) :
    (digest state)[4*w+b]! = UInt8.ofNat (state[w]!.toNat >>> (8*(3-b))) := by
  rw [getElem!_pos (digest state) (4*w+b) (by rw [digest_size]; omega)]
  have hword : (4*w+b)/4 = w := by omega
  have hbyte : (4*w+b)%4 = b := by omega
  simp only [digest, Hash.Sha256.digest, ByteArray.getElem_eq_getElem_data, Array.getElem_ofFn,
    hword, hbyte]
  rw [digest_byte _ b hb]
  congr 3
  rcases w with _|_|_|_|_|_|_|_|w <;> first | omega | rfl

end LeanBlsSimd.Sha256.Spec
