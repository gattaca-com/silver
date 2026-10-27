import LeanBlsSimd.Portable.Fp.Correct
import LeanBlsSimd.Kzg.PortableG1
import LeanBlsSimd.Kzg.PairingContract

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

def ScalarPairRep (raw : Array portable.g1.G1 2#usize) (p q : G1) : Prop :=
  ∀ lane : Fin 2,
    let point := raw.val[lane.val]'(by simpa using lane.isLt)
    G1Rep ⟨⟨point.x⟩, ⟨point.y⟩, ⟨point.z⟩⟩ (if lane.val = 0 then p else q)


theorem pairing_points_refinement [RuntimeFeatures]
    (sums : verify.PairingSums) (ll rlc rli rlp : G1)
    (hll : G1Rep sums.ll ll) (hrlc : G1Rep sums.rlc rlc)
    (hrli : G1Rep sums.rli rli) (hrlp : G1Rep sums.rlp rlp)
    (hvlc : G1Valid rlc) (hvli : G1Valid rli) (hvlp : G1Valid rlp) :
    ∃ out, sums.points = ok out ∧
      ScalarPairRep out ll (G1.add (G1.add rlc (G1.neg rli)) rlp) := by
  obtain ⟨lc,hlc,hlcr⟩ := PortableG1.from_blst_refines sums.rlc rlc hrlc
  obtain ⟨li,hli,hlir⟩ := PortableG1.from_blst_refines sums.rli rli hrli
  obtain ⟨nli,hnli,hnlir⟩ := PortableG1.neg_refines li rli hlir hvli
  obtain ⟨difference,hd, hdr⟩ := PortableG1.add_complete_refines lc nli rlc
    (G1.neg rli) hlcr hnlir hvlc (g1Valid_neg hvli)
  obtain ⟨left,hl,hlr⟩ := PortableG1.from_blst_refines sums.ll ll hll
  obtain ⟨lp,hlp,hlpr⟩ := PortableG1.from_blst_refines sums.rlp rlp hrlp
  obtain ⟨right,hr,hrr⟩ := PortableG1.add_complete_refines difference lp
    (G1.add rlc (G1.neg rli)) rlp hdr hlpr (g1Valid_add hvlc (g1Valid_neg hvli)) hvlp
  refine ⟨Array.make 2#usize [left,right] (by rfl), ?_, ?_⟩
  · simp only [verify.PairingSums.points, hlc,hli,hnli,hd,hl,hlp,hr,bind_tc_ok]
  · intro lane
    fin_cases lane
    · exact hlr
    · exact hrr

end LeanBlsSimd.Kzg
