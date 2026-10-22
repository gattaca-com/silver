import LeanBlsSimd.Msm8.InputGroup
import LeanBlsSimd.Msm8.OutputBridge
import LeanBlsSimd.Kzg.G1Msm

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthCryptographySpecs Bls
local instance inputOutputAffineInhabited0 : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

theorem inputContribution_range_eq_zip (ps : List blst.blst_p1_affine) (words : List ScalarWords)
    (hlen : ps.length=words.length) :
    (∑ i ∈ Finset.range words.length,inputContribution (ps[i]!,words[i]!))=
      ((ps.zip words).map inputContribution).sum := by
  have he : (ps.zip words).map inputContribution=List.ofFn
      (fun i : Fin words.length => inputContribution (ps[i.val]!,words[i.val]!)) := by
    apply List.ext_getElem
    · simp [hlen]
    · intro i hi hj
      have hiw : i<words.length := by simpa only [List.length_ofFn] using hj
      simp only [List.getElem_map,List.getElem_zip,List.getElem_ofFn]
      rw [getElem!_pos ps i (by omega),getElem!_pos words i hiw]
  rw [he,List.sum_ofFn]
  exact Finset.sum_range (fun i => inputContribution (ps[i]!,words[i]!))

theorem inputContribution_sum_msm (ps : List blst.blst_p1_affine) (words : List ScalarWords)
    (hlen : ps.length=words.length) (hp : ∀p∈ps,Kzg.G1AffineValid p)
    (hs : ∀s∈words,Kzg.limbs s.val<Fr.modulus) :
    ((ps.zip words).map inputContribution).sum=
      G1.toPoint (G1.msm (ps.map Kzg.g1ReadAffine).toArray
        (words.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray) := by
  have hval : ∀j,j<(if (ps.map Kzg.g1ReadAffine).toArray.size≤
      (words.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray.size
      then (ps.map Kzg.g1ReadAffine).toArray.size
      else (words.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray.size) →
      Kzg.G1Valid (ps.map Kzg.g1ReadAffine).toArray[j]! := by
    intro j hj
    have hjp : j<ps.length := by simpa only [List.size_toArray,List.length_map,hlen,ite_self] using hj
    rw [getElem!_pos _ j (by simpa using hjp),List.getElem_toArray,List.getElem_map]
    exact (hp _ (List.getElem_mem hjp)).2
  rw [(Kzg.g1_msm_spec _ _ hval).2]
  simp only [List.size_toArray,List.length_map,hlen,ite_self]
  rw [←inputContribution_range_eq_zip ps words hlen]
  apply Finset.sum_congr rfl
  intro j hj
  have hjw := Finset.mem_range.mp hj
  have hjp : j<ps.length := by omega
  have hsj := hs words[j] (List.getElem_mem hjw)
  simp only [inputContribution]
  rw [getElem!_pos ps j hjp,getElem!_pos words j hjw,
    getElem!_pos (ps.map Kzg.g1ReadAffine).toArray j (by simpa using hjp),
    getElem!_pos (words.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray j (by simpa using hjw)]
  simp only [List.getElem_toArray,List.getElem_map,Fr.ofNat,Fin.val_ofNat,Nat.mod_eq_of_lt hsj]

theorem input_msm_valid (ps : List blst.blst_p1_affine) (words : List ScalarWords)
    (hp : ∀p∈ps,Kzg.G1AffineValid p) :
    Kzg.G1Valid (G1.msm (ps.map Kzg.g1ReadAffine).toArray
      (words.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray) := by
  apply Kzg.g1Valid_msm
  intro j hj
  have hjp : j<ps.length := by
    simp only [List.size_toArray,List.length_map] at hj
    split at hj <;> omega
  rw [getElem!_pos _ j (by simpa using hjp),List.getElem_toArray,List.getElem_map]
  exact (hp _ (List.getElem_mem hjp)).2

theorem lane_zero_in_blst_sum (p : g1x8.G1x8) (P : G1)
    (hholds : (ofG1x8 p).Holds 0 P) (hvalid : G1.Valid P)
    (ps : List blst.blst_p1_affine) (words : List ScalarWords)
    (hlen : ps.length=words.length) (hp : ∀point∈ps,Kzg.G1AffineValid point)
    (hs : ∀s∈words,Kzg.limbs s.val<Fr.modulus)
    (hsum : G1.toPoint P=((ps.zip words).map inputContribution).sum) :
    msm8.lane_zero_in_blst p=ok (Kzg.g1Jacobian P) ∧
      Kzg.G1Rep (Kzg.g1Jacobian P) (G1.msm (ps.map Kzg.g1ReadAffine).toArray
        (words.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray) := by
  have hmsm := input_msm_valid ps words hp
  have he := hsum.trans (inputContribution_sum_msm ps words hlen hp hs)
  have hP : Kzg.G1Valid P := Kzg.g1Valid_of_groupValid hvalid
    (by rw [he];exact Kzg.g1Valid_subgroup hmsm)
  have hmatch := (Kzg.g1_toPoint_eq_iff hP hmsm).mp he
  obtain ⟨hzero,hrep⟩ := lane_zero_in_blst_rep p P hholds
  exact ⟨hzero,hrep.1,hrep.2.1.trans hmatch.1,hrep.2.2.trans hmatch.2⟩

end LeanBlsSimd.Msm8
