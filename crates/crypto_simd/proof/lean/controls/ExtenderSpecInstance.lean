import LeanBlsSimd.Kzg.Extender.Statements

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

theorem specInstance :
    ∃ initial, @cell_extender.CellExtender.new specExternals = ok initial ∧
      StateInvariant initial ∧
      ∀ (v : cell_extender.CellExtender), StateInvariant v →
      ∀ (blob : Blob) (cells : Cells),
      ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
        @cell_extender.CellExtender.compute specExternals v blob cells =
          ok (verdict, next, out) ∧
        StateInvariant next ∧
        (verdict = true ↔ Canonical blob) ∧
        (verdict = true →
          (computeCells (arrayBytes blob)).run = pure (.ok (cellBytes out))) ∧
        (verdict = false → ∃ err,
          (computeCells (arrayBytes blob)).run = pure (.error err)) ∧
        (verdict = false → out = cells) :=
  @compute_eq_spec specExternals specExternals_correct.1 specExternals_fr_to_bytes_correct

end LeanBlsSimd.Kzg.Extender

#print axioms LeanBlsSimd.Kzg.Extender.specInstance
