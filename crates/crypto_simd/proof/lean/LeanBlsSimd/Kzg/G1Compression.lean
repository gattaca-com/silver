import LeanBlsSimd.Kzg.G1Msm
import EthLib.Cryptography.Proofs.IdLoops

open EthLib.Cryptography Bls Kzg
open WeierstrassCurve.Jacobian
open scoped EthLib.Cryptography.Bls.Fp
open private tailAllZero from EthLib.Cryptography.Bls.Compress
open private compress_inf compress_noninf uncompress_of_facts ba_get!_set!_ne
  ba_get!_set!_self ba_size_set! ba_ext from EthLib.Cryptography.Proofs.Bls.Compress

namespace LeanBlsSimd.Kzg

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

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
      simp only [List.foldl_cons, h i (by simp), ne_self_iff_false, if_false]
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
    have hi48 : i < 48 := by simpa only [hs] using hib
    change ((Array.replicate 48 (0 : UInt8)).set! 0 0xc0)[i]! = 0
    simp [getElem!_pos, hi48, show i ≠ 0 by omega]
  simp only [G1.uncompress, hs, ne_self_iff_false, if_false, hh, ht]
  decide

theorem g1_uncompress_curve {b : ByteArray} {p : G1} (hd : G1.uncompress b = .ok p) :
    p.isInfinity = true ∨
      let a := p.toAffine
      a.2 * a.2 = a.1 * a.1 * a.1 + Fp.ofNat 4 := by
  unfold G1.uncompress at hd
  split at hd
  · cases hd
  · dsimp only at hd
    split at hd
    · cases hd
    · split at hd
      · split at hd
        · cases hd
        · cases hd
          exact Or.inl rfl
      · split at hd
        · cases hd
        · rename_i x hx
          split at hd
          · cases hd
          · rename_i y hy
            cases hd
            apply Or.inr
            rw [g1_toAffine_of_one]
            have hs := Fp.sqrt_ok hy
            dsimp only
            split
            · exact hs
            · simpa only [neg_mul_neg] using hs

open G1

private def flagFacts (b : UInt8) : Prop :=
  ((b ||| 0x80 ||| 0x20) &&& 0x80) ≠ 0 ∧
  ((b ||| 0x80 ||| 0x20) &&& 0x40) = 0 ∧
  ((b ||| 0x80 ||| 0x20) &&& 0x20) ≠ 0 ∧
  ((b ||| 0x80 ||| 0x20) &&& 0x1f) = b ∧
  ((b ||| 0x80) &&& 0x80) ≠ 0 ∧
  ((b ||| 0x80) &&& 0x40) = 0 ∧
  ((b ||| 0x80) &&& 0x20) = 0 ∧
  ((b ||| 0x80) &&& 0x1f) = b

private theorem flag_bits (b : UInt8) (hb : b < 0x20) : flagFacts b := by
  have hall : ∀ n : Fin 32, flagFacts (UInt8.ofNat n.val) := by
    unfold flagFacts
    decide
  have hn : b.toNat < 32 := (UInt8.lt_iff_toNat_lt).mp hb
  simpa only [UInt8.ofNat_toNat] using hall ⟨b.toNat, hn⟩

private theorem g1_group_uncompress_compress {p : G1} (h : Valid p) :
    ∃ q, uncompress (compress p) = .ok q ∧ toPoint q = toPoint p := by
  by_cases hinf : p.isInfinity = true
  · refine ⟨zero, ?_, ?_⟩
    · rw [compress_inf hinf]; exact g1_uncompress_infinity
    · rw [toPoint_zero]
      exact (Point.toAffine_of_Z_eq_zero (W := curve)
        (isZero_iff.mp hinf : rep p 2 = 0)).symm
  · rcases hpa : p.toAffine with ⟨xa, ya⟩
    set B0 := (Fp.toBytesBE xa).get! 0 with hB0
    have hb0 : B0 < 0x20 := by
      rw [hB0, UInt8.lt_iff_toNat_lt]; exact Fp.toBytesBE_head_lt xa
    obtain ⟨hsc, hsi, hss, hsm, huc, hui, hus, hum⟩ := flag_bits B0 hb0
    have hsqw : (ya : ZMod Fp.modulus) * ya = xa * xa * xa + Fp.ofNat 4 := by
      have := affine_sqrt_witness h hinf; rw [hpa] at this; exact this
    have hsqrt := Fp.sqrt_complete hsqw
    have hysq : ((Fp.powNat (xa * xa * xa + Fp.ofNat 4)
        ((Fp.modulus + 1) / 4) : Fp) : ZMod Fp.modulus)
        * Fp.powNat (xa * xa * xa + Fp.ofNat 4) ((Fp.modulus + 1) / 4)
        = (ya : ZMod Fp.modulus) * ya := by rw [Fp.sqrt_ok hsqrt, ← hsqw]
    have hsz48 : (Fp.toBytesBE xa).size = 48 := Fp.size_toBytesBE xa
    have hcp := compress_noninf hinf hpa
    have hother : ∀ i, i ≠ 0 → (compress p).get! i = (Fp.toBytesBE xa).get! i := by
      intro i hi0
      rw [hcp]; dsimp only
      by_cases hs : Fp.signBit ya
      · rw [if_pos hs, ba_get!_set!_ne _ _ hi0, ba_get!_set!_ne _ _ hi0]
      · rw [if_neg hs, ba_get!_set!_ne _ _ hi0]
    have hsize : (compress p).size = 48 := by
      rw [hcp]; dsimp only
      by_cases hs : Fp.signBit ya
      · rw [if_pos hs, ba_size_set!, ba_size_set!, hsz48]
      · rw [if_neg hs, ba_size_set!, hsz48]
    refine ⟨⟨xa, ya, Fp.one⟩, ?_, ?_⟩
    · by_cases hs : Fp.signBit ya
      · have hhead : (compress p).get! 0 = B0 ||| 0x80 ||| 0x20 := by
          rw [hcp]; dsimp only
          rw [if_pos hs, ba_get!_set!_self _ _ (by rw [ba_size_set!, hsz48]; decide),
            ba_get!_set!_self _ _ (by rw [hsz48]; decide)]
        refine uncompress_of_facts hsize (by rw [hhead]; exact hsc)
          (by rw [hhead]; exact hsi) ?_ ?_ hsqrt hysq
        · rw [hhead]
          exact ⟨fun _ => hs, fun _ => hss⟩
        · refine ba_ext (by rw [ba_size_set!, hsize, hsz48]) (fun i hi' => ?_)
          rw [ba_size_set!, hsize] at hi'
          by_cases hi0 : i = 0
          · subst hi0
            rw [ba_get!_set!_self _ _ (by rw [hsize]; decide), hhead, ← hB0]
            exact hsm
          · rw [ba_get!_set!_ne _ _ hi0, hother i hi0]
      · have hhead : (compress p).get! 0 = B0 ||| 0x80 := by
          rw [hcp]; dsimp only
          rw [if_neg hs, ba_get!_set!_self _ _ (by rw [hsz48]; decide)]
        refine uncompress_of_facts hsize (by rw [hhead]; exact huc)
          (by rw [hhead]; exact hui) ?_ ?_ hsqrt hysq
        · rw [hhead]
          exact ⟨fun hne => absurd hus hne, fun hh => absurd hh hs⟩
        · refine ba_ext (by rw [ba_size_set!, hsize, hsz48]) (fun i hi' => ?_)
          rw [ba_size_set!, hsize] at hi'
          by_cases hi0 : i = 0
          · subst hi0
            rw [ba_get!_set!_self _ _ (by rw [hsize]; decide), hhead, ← hB0]
            exact hum
          · rw [ba_get!_set!_ne _ _ hi0, hother i hi0]
    · have := toPoint_affine_normalize (p := p) hinf
      rw [hpa] at this; exact this


theorem g1_uncompress_compress {p : G1} (hp : G1Valid p) :
    ∃ q, G1.uncompress (G1.compress p) = .ok q ∧ G1Valid q ∧
      q.isInfinity = p.isInfinity ∧ q.toAffine = p.toAffine := by
  by_cases hinf : p.isInfinity = true
  · refine ⟨G1.zero, ?_, g1Valid_zero, ?_, ?_⟩
    · rw [compress_inf hinf]
      exact g1_uncompress_infinity
    · exact hinf.symm
    · simp only [G1.toAffine, show p.z.isZero = true from hinf, if_true]
      rfl
  · obtain ⟨q, hdecode, hpoint⟩ :=
      g1_group_uncompress_compress (g1_groupValid_of_noninfinity hp hinf)
    have hq : G1Valid q := by
      by_cases hqinf : q.isInfinity = true
      · exact g1Valid_of_infinity hqinf
      · apply g1Valid_of_groupValid
          (g1_valid_of_affine hqinf ((g1_uncompress_curve hdecode).resolve_left hqinf))
        rw [hpoint]
        exact g1Valid_subgroup hp
    exact ⟨q, hdecode, hq, (g1_toPoint_eq_iff hq hp).mp hpoint⟩

private theorem keyValidate_facts (b : ByteArray) (h : (G1.keyValidate b).isOk = true) :
    ∃ p, G1.uncompress b = .ok p ∧ G1Valid p := by
  cases hd : G1.uncompress b with
  | error err => simp [G1.keyValidate, hd, Bind.bind, Except.bind, Except.isOk, Except.toBool] at h
  | ok p =>
    cases hinf : p.isInfinity <;> cases hsub : p.inSubgroup <;>
      simp [G1.keyValidate, hd, hinf, hsub, Bind.bind, Except.bind, Except.isOk,
        Except.toBool, Pure.pure, Except.pure] at h
    exact ⟨p, rfl, g1_uncompress_curve hd, hsub⟩

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
  · exact keyValidate_facts b h

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
    simp only [specPoint, bytesToKzgProof, hv, if_true, Except.toOption, Option.bind_some, hd,
      Option.some.injEq] at h
    exact h ▸ hd

theorem specPoint_valid {b : ByteArray} {p : G1} (h : specPoint b = some p) : G1Valid p := by
  have hv : validateKzgG1 b = true := by rw [← specPoint_isSome, h]; rfl
  obtain ⟨q, hd, hq⟩ := validateKzgG1_facts b hv
  have : q = p := Except.ok.inj (hd.symm.trans (specPoint_uncompress h))
  exact this ▸ hq

end LeanBlsSimd.Kzg
