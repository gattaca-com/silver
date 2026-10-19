import LeanBlsSimd.Kzg.Model

open EthCryptographySpecs Bls Kzg Kzg.BitReversal

namespace LeanBlsSimd.Kzg.Extender.Model

/-- Natural-order evaluations on the other coset of the 4096-point blob domain. -/
def extension (evaluations : Array Fr) : Array Fr :=
  let coefficients := Kzg.Model.inverseFft (bitReversalPermutation evaluations)
    (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) (Fr.ofNat 4096).inverse
  let shifts := Kzg.Model.roots 13
  let shifted := Array.ofFn (n := 4096) fun i => coefficients[i.val]! * shifts[i.val]!
  fftFieldAux shifted (Kzg.Model.roots 12)

def extend (blob : ByteArray) : Except KzgError (Array Cell) := do
  let evaluations ← blobToPolynomial blob
  let extra := bitReversalPermutation (extension evaluations)
  return Array.ofFn (n := 128) fun i =>
    if i.val < 64 then
      blob.extract (i.val * 2048) ((i.val + 1) * 2048)
    else
      let start := (i.val - 64) * 64
      cosetEvalsToCell (extra.extract start (start + 64))

def compute (blob : ByteArray) (cells : Array Cell) : Bool × Array Cell :=
  match extend blob with
  | .ok result => (true, result)
  | .error _ => (false, cells)

end LeanBlsSimd.Kzg.Extender.Model
