import LeanBlsSimd.Kzg.Setup

open EthLib.Cryptography Bls Kzg

namespace LeanBlsSimd.Kzg.Controls

def changedEmbeddedSetup : TrustedSetup :=
  { embeddedSetup with g2Monomial := embeddedSetup.g2Monomial.set! 64 G2.zero }

theorem changed_setup_point : changedEmbeddedSetup.g2Monomial[64]! = G2.zero := by
  have hs : 64 < embeddedSetup.g2Monomial.size := by rw [embedded_g2_size]; decide
  simp [changedEmbeddedSetup, Array.set!, hs, getElem!_pos]

theorem changed_setup_is_rejected : ¬ SetupMatches changedEmbeddedSetup := by
  intro h
  have hd := h.2.2.2.1
  rw [changed_setup_point] at hd
  have hpoint : SetupPoints.g2Point64 = G2.zero := by
    have hg := SetupPoints.g2_64_decoded
    change G2.uncompress rustG2CellBytes = .ok SetupPoints.g2Point64 at hg
    rw [hg] at hd
    exact Except.ok.inj hd
  have hfinite := congrArg G2.isInfinity hpoint
  have hleft : SetupPoints.g2Point64.isInfinity = false := by decide +kernel
  have hright : G2.zero.isInfinity = true := by decide +kernel
  rw [hleft, hright] at hfinite
  contradiction

theorem changed_setup_differs : changedEmbeddedSetup ≠ embeddedSetup := by
  intro h
  apply changed_setup_is_rejected
  rw [h]
  exact embedded_setup_matches

end LeanBlsSimd.Kzg.Controls

#print axioms LeanBlsSimd.Kzg.Controls.changed_setup_is_rejected
#print axioms LeanBlsSimd.Kzg.Controls.changed_setup_differs
