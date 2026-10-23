import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Kzg

/-- Execute an arbitrary finite continuation of a streaming hash. -/
def shaContinue {S : Type} (update : S → Slice U8 → Result S)
    (finish : S → Result (Aeneas.Std.Array U8 32#usize))
    (s : S) : List (Slice U8) → Result (Aeneas.Std.Array U8 32#usize)
  | [] => finish s
  | chunk :: chunks => do
    let next ← update s chunk
    shaContinue update finish next chunks

/-- A state represents a prefix when every finite continuation produces its
SHA-256 digest. This observational relation fixes the meaning of state without
choosing a relation as part of the correctness premise. -/
def ShaRep {S : Type} (update : S → Slice U8 → Result S)
    (finish : S → Result (Aeneas.Std.Array U8 32#usize))
    (s : S) (pre : List U8) : Prop :=
  ∀ chunks, ∃ digest, shaContinue update finish s chunks = ok digest ∧
    arrayBytes digest = EthLib.Cryptography.Bls.sha256
      (bytes (pre ++ chunks.flatMap (·.val)))

/-- Primitive streaming laws, with no bound on the accumulated prefix length. -/
structure ShaPathCorrect {S : Type} (new : Result S)
    (update : S → Slice U8 → Result S)
    (finish : S → Result (Aeneas.Std.Array U8 32#usize)) : Prop where
  new_spec : ∃ s, new = ok s ∧ ShaRep update finish s []
  update_spec : ∀ s pre chunk, ShaRep update finish s pre →
    ∃ next, update s chunk = ok next ∧
      ShaRep update finish next (pre ++ chunk.val)
  finish_spec : ∀ s pre, ShaRep update finish s pre →
    ∃ digest, finish s = ok digest ∧
      arrayBytes digest = EthLib.Cryptography.Bls.sha256 (bytes pre)

/-- Correctness premises for the actual SHA-extension and portable functions. -/
structure ShaCorrect : Prop where
  extensions : ShaPathCorrect sha256.extensions.Sha256.new
    sha256.extensions.Sha256.update sha256.extensions.Sha256.finish
  portable : ShaPathCorrect sha256.portable.Sha256.new
    sha256.portable.Sha256.update sha256.portable.Sha256.finish

end LeanBlsSimd.Kzg
