import LeanBlsSimd.Spec.G1

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

theorem BETA_MONT_eq : val (.ofList BETA_MONT) = beta * R % Fp.modulus := by
  sorry

namespace G1x8

structure Holds (self : G1x8) (l : Fin 8) (P : G1) : Prop where
  x : self.x.Holds l P.x
  y : self.y.Holds l P.y
  z : self.z.Holds l P.z

theorem double_correct (self : G1x8) (l : Fin 8) (P : G1)
    (h : self.Holds l P) (hP : G1.Valid P)
    (hu : self.double.2.toNat.testBit l = false) :
    self.double.1.Holds l (G1.double P) := by
  sorry

theorem add_affine_correct (self : G1x8) (qx qy : Fp8) (l : Fin 8) (P : G1) (x y : Fp)
    (h : self.Holds l P) (hx : qx.Holds l x) (hy : qy.Holds l y)
    (hP : G1.Valid P) (hQ : G1.Valid ⟨x, y, Fp.one⟩)
    (hu : (self.add_affine qx qy).2.toNat.testBit l = false) :
    (self.add_affine qx qy).1.Holds l (G1.add P ⟨x, y, Fp.one⟩) := by
  sorry

theorem add_correct (self q : G1x8) (l : Fin 8) (P Q : G1)
    (h : self.Holds l P) (hq : q.Holds l Q) (hP : G1.Valid P) (hQ : G1.Valid Q)
    (hu : (self.add q).2.toNat.testBit l = false) :
    (self.add q).1.Holds l (G1.add P Q) := by
  sorry

theorem times_z_affine_correct (px py : Fp8) (l : Fin 8) (x y : Fp)
    (hx : px.Holds l x) (hy : py.Holds l y) (hP : G1.Valid ⟨x, y, Fp.one⟩)
    (hu : (times_z_affine px py).2.toNat.testBit l = false) :
    ∃ Q, (times_z_affine px py).1.Holds l Q ∧ G1.Valid Q ∧
      G1.toPoint Q = blsX • G1.toPoint ⟨x, y, Fp.one⟩ := by
  sorry

theorem times_z_correct (self : G1x8) (l : Fin 8) (P : G1)
    (h : self.Holds l P) (hP : G1.Valid P)
    (hu : self.times_z.2.toNat.testBit l = false) :
    ∃ Q, self.times_z.1.Holds l Q ∧ G1.Valid Q ∧ G1.toPoint Q = blsX • G1.toPoint P := by
  sorry

theorem scott_membership_iff (px py : Fp8) (l : Fin 8) (x y : Fp)
    (hx : px.Holds l x) (hy : py.Holds l y) (hP : G1.Valid ⟨x, y, Fp.one⟩)
    (hu : (scott_membership px py).undecided.toNat.testBit l = false) :
    (scott_membership px py).members.toNat.testBit l = true ↔
      G1.inSubgroup ⟨x, y, Fp.one⟩ = true := by
  sorry

end G1x8

namespace DecompressG1

theorem valid_sound (inputs : Vector Encoding 8) (l : Fin 8)
    (hv : (decompress inputs).valid.toNat.testBit l = true) :
    ∃ P, G1.uncompress (G1Spec.toBytes inputs[l]) = .ok P ∧ G1.inSubgroup P = true ∧
      (decompress inputs).points[l] = G1Spec.blstLimbs P ∧
      (decompress inputs).undecided.toNat.testBit l = false := by
  sorry

theorem valid_complete (inputs : Vector Encoding 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false)
    (h : (G1Spec.verdict inputs[l]).isSome = true) :
    (decompress inputs).valid.toNat.testBit l = true := by
  sorry

theorem decompress_eq_spec (inputs : Vector Encoding 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    laneVerdict (decompress inputs) l = G1Spec.verdict inputs[l] := by
  sorry

theorem infinity_undecided (inputs : Vector Encoding 8) (l : Fin 8)
    (h : inputs[l] = G1Spec.infinity) :
    (decompress inputs).undecided.toNat.testBit l = true := by
  sorry

end DecompressG1
end LeanBlsSimd
