import LeanBlsSimd.Kzg.G1Msm
import EthLib.Cryptography.Proofs.IdLoops
import Batteries.Tactic.OpenPrivate

open EthLib.Cryptography Bls Kzg
open WeierstrassCurve.Jacobian
open scoped EthLib.Cryptography.Bls.Fp
open private tailAllZero from EthLib.Cryptography.Bls.Compress

namespace LeanBlsSimd.Kzg

private theorem tail_zero (b : ByteArray) (start : Nat)
    (hz : ∀ i, start ≤ i → i < b.size → b.get! i = 0) : tailAllZero b start = true := by
  unfold tailAllZero
  simp only [Id.run, IdLoops.id_bind, IdLoops.id_pure]
  rw [Std.Legacy.Range.forIn_eq_forIn_range']
  have hbody : (fun (i : Nat) (acc : Bool) =>
      (if b.get! i ≠ 0 then ForInStep.yield false else ForInStep.yield acc : Id (ForInStep Bool))) =
      (fun i acc => ForInStep.yield (if b.get! i ≠ 0 then false else acc)) := by
    funext i acc
    split <;> rfl
  rw [hbody, IdLoops.forIn_list_yield]
  simp only [Std.Legacy.Range.size, Nat.add_sub_cancel, Nat.div_one]
  have hf (is : List Nat) (h : ∀ i ∈ is, b.get! i = 0) (acc : Bool) :
      is.foldl (fun acc i => if b.get! i ≠ 0 then false else acc) acc = acc := by
    induction is generalizing acc with
    | nil => rfl
    | cons i is ih =>
      simp only [List.foldl_cons, h i (by simp), ne_self_iff_false, ite_false]
      exact ih (fun i hi => h i (by simp [hi])) acc
  apply hf
  intro i hi
  have hi' := List.mem_range'_1.mp hi
  exact hz i hi'.1 (by omega)

theorem g1_uncompress_infinity : G1.uncompress G1.infinityBytes = .ok G1.zero := by
  have hs : G1.infinityBytes.size = 48 := by simp [G1.infinityBytes, ByteArray.size]
  have hh : G1.infinityBytes.get! 0 = 0xc0 := by
    change ((Array.replicate 48 (0 : UInt8)).set! 0 0xc0)[0]! = 0xc0
    simp [getElem!_pos]
  have ht : tailAllZero G1.infinityBytes 1 = true := by
    apply tail_zero
    intro i hi hib
    have hi48 : i < 48 := by simpa only [hs] using! hib
    change ((Array.replicate 48 (0 : UInt8)).set! 0 0xc0)[i]! = 0
    simp [getElem!_pos, hi48, show i ≠ 0 by omega]
  simp only [G1.uncompress, hs, ne_self_iff_false, ite_false, hh, ht]
  decide

theorem g1_uncompress_curve {b : ByteArray} {p : G1} (hd : G1.uncompress b = .ok p) :
    p.isInfinity = true ∨
      let a := p.toAffine
      a.2 * a.2 = a.1 * a.1 * a.1 + Fp.ofNat 4 := by
  by_cases hinf : p.isInfinity = true
  · exact Or.inl hinf
  · exact Or.inr (EthLib.Cryptography.Bls.G1.affine_sqrt_witness
      (EthLib.Cryptography.Bls.G1.uncompress_valid hd) hinf)

theorem g1_uncompress_compress {p : G1} (hp : G1Valid p) :
    ∃ q, G1.uncompress (G1.compress p) = .ok q ∧ G1Valid q ∧
      q.isInfinity = p.isInfinity ∧ q.toAffine = p.toAffine := by
  by_cases hinf : p.isInfinity = true
  · refine ⟨G1.zero, ?_, g1Valid_zero, ?_, ?_⟩
    · have hc : G1.compress p = G1.infinityBytes := by
        unfold G1.compress
        simp only [Id.run, hinf, ite_true]
        rfl
      rw [hc]
      exact g1_uncompress_infinity
    · exact hinf.symm
    · simp only [G1.toAffine, show p.z.isZero = true from hinf, ite_true]
      rfl
  · obtain ⟨q, hdecode, hpoint⟩ :=
      EthLib.Cryptography.Bls.G1.uncompress_compress (g1_groupValid_of_noninfinity hp hinf)
    have hq : G1Valid q := by
      apply g1Valid_of_groupValid (EthLib.Cryptography.Bls.G1.uncompress_valid hdecode)
      rw [hpoint]
      exact g1Valid_subgroup hp
    exact ⟨q, hdecode, hq, (g1_toPoint_eq_iff hq hp).mp hpoint⟩

theorem validateKzgG1_facts (b : ByteArray) (h : validateKzgG1 b = true) :
    ∃ p, G1.uncompress b = .ok p ∧ G1Valid p := by
  unfold validateKzgG1 at h
  split at h
  · rename_i hb
    have heq : b = Constants.G1_POINT_AT_INFINITY := by
      apply ByteArray.ext
      exact eq_of_beq hb
    subst b
    exact ⟨G1.zero, g1_uncompress_infinity, g1Valid_zero⟩
  · cases hd : G1.uncompress b with
    | error err => simp [G1.keyValidate, G1.keyValidatePoint, hd, Bind.bind, Except.bind,
        Except.isOk, Except.toBool] at h
    | ok p =>
      cases hinf : p.isInfinity <;> cases hsub : p.inSubgroup <;>
        simp [G1.keyValidate, G1.keyValidatePoint, hd, hinf, hsub, Bind.bind, Except.bind,
          Except.isOk, Except.toBool, Pure.pure, Except.pure, throw, throwThe,
          MonadExceptOf.throw] at h
      exact ⟨p, rfl, g1_uncompress_curve hd, hsub⟩

theorem specPoint_isSome (b : ByteArray) : (specPoint b).isSome = validateKzgG1 b := by
  cases hv : validateKzgG1 b with
  | false => simp [specPoint, bytesToKzgProof, hv, Except.toOption]
  | true =>
    obtain ⟨p, hd, _⟩ := validateKzgG1_facts b hv
    simp [specPoint, bytesToKzgProof, hv, hd, Except.toOption]

theorem specPoint_uncompress {b : ByteArray} {p : G1} (h : specPoint b = some p) :
    G1.uncompress b = .ok p := by
  cases hv : validateKzgG1 b with
  | false => simp [specPoint, bytesToKzgProof, hv, Except.toOption] at h
  | true =>
    obtain ⟨q, hd, _⟩ := validateKzgG1_facts b hv
    simp only [specPoint, bytesToKzgProof, hv, ite_true, Except.toOption, Option.bind_some, hd,
      Option.some.injEq] at h
    exact h ▸ hd

theorem specPoint_valid {b : ByteArray} {p : G1} (h : specPoint b = some p) : G1Valid p := by
  have hv : validateKzgG1 b = true := by rw [← specPoint_isSome, h]; rfl
  obtain ⟨q, hd, hq⟩ := validateKzgG1_facts b hv
  have : q = p := Except.ok.inj (hd.symm.trans (specPoint_uncompress h))
  exact this ▸ hq

end LeanBlsSimd.Kzg
