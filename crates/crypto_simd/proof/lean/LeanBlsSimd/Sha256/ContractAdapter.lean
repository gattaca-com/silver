import LeanBlsSimd.Kzg.ShaContracts

open Aeneas Aeneas.Std Result

namespace LeanBlsSimd.Kzg

variable {S : Type} {update : S → Slice U8 → Result S}
  {finish : S → Result (Aeneas.Std.Array U8 32#usize)}

theorem shaRep_update (s : S) (pre : List U8) (chunk : Slice U8)
    (h : ShaRep update finish s pre) :
    ∃ next, update s chunk = ok next ∧ ShaRep update finish next (pre++chunk.val) := by
  obtain ⟨digest,hdigest,_⟩ := h [chunk]
  cases hu : update s chunk with
  | fail e => simp [shaContinue,hu] at hdigest
  | div => simp [shaContinue,hu] at hdigest
  | ok next =>
    refine ⟨next,rfl,?_⟩
    intro chunks
    obtain ⟨digest,hdigest,hbytes⟩ := h (chunk::chunks)
    refine ⟨digest,?_,?_⟩
    · simpa only [shaContinue,hu,bind_tc_ok] using hdigest
    · simpa only [List.flatMap_cons,List.append_assoc] using hbytes

theorem shaRep_finish (s : S) (pre : List U8) (h : ShaRep update finish s pre) :
    ∃ digest, finish s = ok digest ∧
      arrayBytes digest = EthLib.Cryptography.Bls.sha256 (bytes pre) := by
  simpa only [shaContinue,List.flatMap_nil,List.append_nil] using h []

/-- A concrete state invariant supplies the initial observational relation.
The update and finish laws then follow for every observationally valid state. -/
theorem shaPathCorrect_of_invariant (new : Result S) (R : S → List U8 → Prop)
    (hnew : ∃ s, new = ok s ∧ R s [])
    (hupdate : ∀ s pre chunk, R s pre →
      ∃ next, update s chunk = ok next ∧ R next (pre++chunk.val))
    (hfinish : ∀ s pre, R s pre → ∃ digest, finish s = ok digest ∧
      arrayBytes digest = EthLib.Cryptography.Bls.sha256 (bytes pre)) :
    ShaPathCorrect new update finish := by
  have hrep : ∀ s pre, R s pre → ShaRep update finish s pre := by
    intro s pre hs chunks
    induction chunks generalizing s pre with
    | nil => simpa only [shaContinue,List.flatMap_nil,List.append_nil] using hfinish s pre hs
    | cons chunk chunks ih =>
      obtain ⟨next,hnext,hr⟩ := hupdate s pre chunk hs
      obtain ⟨digest,hdigest,hbytes⟩ := ih next (pre++chunk.val) hr
      refine ⟨digest,?_,?_⟩
      · simpa only [shaContinue,hnext,bind_tc_ok] using hdigest
      · simpa only [List.flatMap_cons,List.append_assoc] using hbytes
  refine ⟨?_,shaRep_update,shaRep_finish⟩
  obtain ⟨s,hs,hr⟩ := hnew
  exact ⟨s,hs,hrep s [] hr⟩

end LeanBlsSimd.Kzg
