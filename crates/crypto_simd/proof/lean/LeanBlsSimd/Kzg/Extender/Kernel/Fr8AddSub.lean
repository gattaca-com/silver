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
  · simp only [fr8.Fr8.add, hr, hn, hout, bind_ok]
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
  · simp only [fr8.Fr8.sub, ho, hr, hn, hout, bind_ok]
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

end LeanBlsSimd.Kzg.Extender.Kernel
