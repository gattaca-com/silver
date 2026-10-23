import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Lazy
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Reduced

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg.Extender.Kernel

theorem add_lazy_refinement {m m' : Nat} (a b : fr8.Fr8)
    (values other : Fin 8 → Fr) (ha : LazyRep 2 m a values) (hb : LazyRep 2 m' b other)
    (hm : m ≤ 256) (hm' : m' ≤ 256) :
    ∃ out, fr8.Fr8.add a b = ok out ∧
      Represents out (fun lane => values lane + other lane) ∧
      ∀ lane, (laneNat out lane : ℤ) =
        (laneInt a lane + laneInt b lane) % (2 * Fr.modulus) := by
  obtain ⟨raw, hr, hraw, he⟩ :=
    add_raw_lazy_refinement a b values other ha hb (by omega)
  obtain ⟨norm, hn, hnorm, hne⟩ :=
    normalise_lazy_refinement raw _ hraw (by norm_num) (by omega)
  obtain ⟨out, hout, hbnd, hval⟩ := reduced_refinement norm hnorm (fun lane => by
    have hv := (hraw.1 lane).2.1
    rw [← (hne lane).1] at hv
    exact_mod_cast hv)
  refine ⟨out, ?_, ⟨hbnd, fun lane => ?_⟩, fun lane => ?_⟩
  · simp only [fr8.Fr8.add, hr, hn, hout, bind_tc_ok]
  · rw [(hval lane).2, (hne lane).2]
  · rw [(hval lane).1]
    push_cast
    rw [(hne lane).1, he]

theorem add_lazy_representation {m m' : Nat} (a b : fr8.Fr8)
    (values other : Fin 8 → Fr) (ha : LazyRep 2 m a values) (hb : LazyRep 2 m' b other)
    (hm : m ≤ 256) (hm' : m' ≤ 256) :
    ∃ out, fr8.Fr8.add a b = ok out ∧
      Represents out (fun lane => values lane + other lane) := by
  obtain ⟨out, he, hr, _⟩ := add_lazy_refinement a b values other ha hb hm hm'
  exact ⟨out, he, hr⟩

theorem sub_lazy_refinement {m m' : Nat} (a b : fr8.Fr8)
    (values other : Fin 8 → Fr) (ha : LazyRep 2 m a values) (hb : LazyRep 2 m' b other)
    (hm : m ≤ 256) (hm' : m' ≤ 256) :
    ∃ out, fr8.Fr8.sub a b = ok out ∧
      Represents out (fun lane => values lane - other lane) ∧
      ∀ lane, (laneNat out lane : ℤ) =
        (laneInt a lane + 2 * Fr.modulus - laneInt b lane) % (2 * Fr.modulus) := by
  obtain ⟨offset, ho, hon, hov⟩ := multiple_of_r_refinement 2#u64 (by decide)
  obtain ⟨raw, hr, hraw, he⟩ :=
    sub_raw_lazy_refinement a b offset values other ha hb hon hov (by decide) (by omega)
  obtain ⟨norm, hn, hnorm, hne⟩ :=
    normalise_lazy_refinement raw _ hraw (by norm_num) (by omega)
  obtain ⟨out, hout, hbnd, hval⟩ := reduced_refinement norm hnorm (fun lane => by
    have hv := (hraw.1 lane).2.1
    rw [← (hne lane).1] at hv
    exact_mod_cast hv)
  refine ⟨out, ?_, ⟨hbnd, fun lane => ?_⟩, fun lane => ?_⟩
  · simp only [fr8.Fr8.sub, ho, hr, hn, hout, bind_tc_ok]
  · rw [(hval lane).2, (hne lane).2]
  · rw [(hval lane).1]
    push_cast
    rw [(hne lane).1, he]
    rfl

theorem sub_lazy_representation {m m' : Nat} (a b : fr8.Fr8)
    (values other : Fin 8 → Fr) (ha : LazyRep 2 m a values) (hb : LazyRep 2 m' b other)
    (hm : m ≤ 256) (hm' : m' ≤ 256) :
    ∃ out, fr8.Fr8.sub a b = ok out ∧
      Represents out (fun lane => values lane - other lane) := by
  obtain ⟨out, he, hr, _⟩ := sub_lazy_refinement a b values other ha hb hm hm'
  exact ⟨out, he, hr⟩

theorem add_refinement (a b : fr8.Fr8) (ha : Bounded a) (hb : Bounded b) :
    ∃ out, fr8.Fr8.add a b = ok out ∧ Bounded out ∧
      ∀ lane, laneNat out lane = (laneNat a lane + laneNat b lane) % (2 * Fr.modulus) ∧
        laneValue out lane = laneValue a lane + laneValue b lane := by
  have ha' : Represents a (laneValue a) := ⟨ha, fun _ => rfl⟩
  have hb' : Represents b (laneValue b) := ⟨hb, fun _ => rfl⟩
  obtain ⟨out, ho, hr, he⟩ := add_lazy_refinement a b _ _ ha'.lazy hb'.lazy
    (by decide) (by decide)
  refine ⟨out, ho, hr.1, fun lane => ⟨?_, hr.2 lane⟩⟩
  have h := he lane
  rw [laneInt_eq_laneNat ha.1, laneInt_eq_laneNat hb.1] at h
  exact_mod_cast h

theorem sub_refinement (a b : fr8.Fr8) (ha : Bounded a) (hb : Bounded b) :
    ∃ out, fr8.Fr8.sub a b = ok out ∧ Bounded out ∧
      ∀ lane, laneNat out lane =
          (laneNat a lane + 2 * Fr.modulus - laneNat b lane) % (2 * Fr.modulus) ∧
        laneValue out lane = laneValue a lane - laneValue b lane := by
  have ha' : Represents a (laneValue a) := ⟨ha, fun _ => rfl⟩
  have hb' : Represents b (laneValue b) := ⟨hb, fun _ => rfl⟩
  obtain ⟨out, ho, hr, he⟩ := sub_lazy_refinement a b _ _ ha'.lazy hb'.lazy
    (by decide) (by decide)
  refine ⟨out, ho, hr.1, fun lane => ⟨?_, hr.2 lane⟩⟩
  have h := he lane
  rw [laneInt_eq_laneNat ha.1, laneInt_eq_laneNat hb.1] at h
  have hle : laneNat b lane ≤ laneNat a lane + 2 * Fr.modulus := by
    have := hb.2 lane
    omega
  exact_mod_cast (show (laneNat out lane : ℤ) =
    ((laneNat a lane + 2 * Fr.modulus - laneNat b lane : Nat) : ℤ) % (2 * Fr.modulus) by
      rw [Nat.cast_sub hle]; push_cast; exact h)

end LeanBlsSimd.Kzg.Extender.Kernel
