import LeanBlsSimd.Kzg.Refines.Challenge

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg
open LeanBlsSimd.Kzg

namespace LeanBlsSimd.Controls.KzgStreamingSha

/-- A wrong digest cannot satisfy the fixed state relation, even when finish succeeds. -/
theorem corrupted_finish_rejected {S : Type}
    (update : S → Slice U8 → Result S)
    (finish : S → Result (Aeneas.Std.Array U8 32#usize))
    (s : S) (pre : List U8)
    (digest : Aeneas.Std.Array U8 32#usize)
    (hfinish : finish s = ok digest)
    (hbad : arrayBytes digest ≠ Bls.sha256 (bytes pre)) :
    ¬ ShaRep update finish s pre := by
  intro h
  obtain ⟨actual, hactual, hbytes⟩ := h []
  simp only [shaContinue] at hactual
  have heq : actual = digest := by simpa only [hfinish, ok.injEq] using hactual.symm
  subst actual
  exact hbad (by simpa using hbytes)

set_option maxRecDepth 20000 in
set_option maxHeartbeats 4000000 in
/-- A total constant-zero implementation is rejected on the empty transcript. -/
theorem constant_zero_hash_rejected :
    ¬ ShaRep (fun (_ : Unit) (_ : Slice U8) => ok ())
      (fun (_ : Unit) => ok (Array.repeat 32#usize 0#u8)) () [] := by
  apply corrupted_finish_rejected _ _ () [] (Array.repeat 32#usize 0#u8) rfl
  decide +kernel

/-- The observation depends on bytes and their order, not update boundaries. -/
theorem segmentation_preserves_digest
    (s : sha256.portable.Sha256) (pre : List U8)
    (h : ShaRep sha256.portable.Sha256.update sha256.portable.Sha256.finish s pre)
    (left right : List (Slice U8))
    (heq : left.flatMap (·.val) = right.flatMap (·.val)) :
    ∃ dl dr,
      shaContinue sha256.portable.Sha256.update sha256.portable.Sha256.finish s left = ok dl ∧
      shaContinue sha256.portable.Sha256.update sha256.portable.Sha256.finish s right = ok dr ∧
      arrayBytes dl = arrayBytes dr := by
  obtain ⟨dl, hl, hdl⟩ := h left
  obtain ⟨dr, hr, hdr⟩ := h right
  exact ⟨dl, dr, hl, hr, hdl.trans (by rw [heq]; exact hdr.symm)⟩

/-- Both generated SHA paths produce the same challenge for all well-indexed inputs. -/
theorem sha_routes_agree (hsha : ShaCorrect) (hbytes : FrBytesCorrect)
    (unique : Slice (Aeneas.Std.Array U8 48#usize))
    (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length) :
    challenge.challenge_in_parts unique ci indices cells ps =
      challenge.challenge_in_parts_portable unique ci indices cells ps := by
  rw [challenge_refinement hsha hbytes unique ci indices cells ps hlen,
    challenge_portable_refinement hsha hbytes unique ci indices cells ps hlen]

end LeanBlsSimd.Controls.KzgStreamingSha
