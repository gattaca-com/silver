import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode
import LeanBlsSimd.Kzg.Extender.Acceptance

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

private def rawField (blob : Blob) (v : Nat) (lane : Fin 8) : Nat :=
  Fr.bytesBEToNat ((arrayBytes blob).extract (32 * (8 * v + lane.val))
    (32 * (8 * v + lane.val + 1)))

private def RawPrefix (data : alloc.vec.Vec fr8.Fr8) (blob : Blob) (count : Nat) : Prop :=
  data.val.length = 512 ∧ ∀ v : Fin 512, v.val < count →
    Normalized data.val[v.val]! ∧ ∀ lane, laneNat data.val[v.val]! lane = rawField blob v.val lane

private def CanonicalPrefix (blob : Blob) (count : Nat) : Prop :=
  ∀ v, v < count → ∀ lane, rawField blob v lane < Fr.modulus

private theorem canonical_prefix_full (blob : Blob) :
    CanonicalPrefix blob 512 ↔ Canonical blob := by
  constructor
  · intro h i
    have hi : i.val / 8 < 512 := by omega
    have hdecomp : 8 * (i.val / 8) + i.val % 8 = i.val := by omega
    simpa only [rawField, hdecomp, Nat.mul_comm 32] using
      h (i.val / 8) hi ⟨i.val % 8, Nat.mod_lt _ (by decide)⟩
  · intro h v hv lane
    have hi : 8 * v + lane.val < 4096 := by omega
    simpa only [rawField, Nat.mul_comm 32] using h ⟨8 * v + lane.val, hi⟩

private theorem decode_loop (blob : Blob) (data : alloc.vec.Vec fr8.Fr8)
    (valid : Bool) (i : Usize) (hi : i.val ≤ 512)
    (hd : RawPrefix data blob i.val)
    (hc : valid = true ↔ CanonicalPrefix blob i.val) :
    ∃ out verdict, extension_kernel.ExtensionKernel.decode_loop data blob valid i = ok (out, verdict) ∧
      RawPrefix out blob 512 ∧ (verdict = true ↔ Canonical blob) := by
  induction hrem : 512 - i.val generalizing i data valid with
  | zero =>
    have he : i.val = 512 := by omega
    refine ⟨data, valid, ?_, by simpa only [he] using hd, ?_⟩
    · rw [extension_kernel.ExtensionKernel.decode_loop, loop.eq_1]
      simp [extension_kernel.ExtensionKernel.decode_loop.body, alloc.vec.Vec.len,
        UScalar.lt_equiv, hd.1, he]
    · simpa only [he, canonical_prefix_full] using hc
  | succ rem ih =>
    have hit : i.val < 512 := by omega
    have hil : i.val < data.val.length := by rw [hd.1]; exact hit
    let block : Usize := UScalar.ofNatCore (i.val * 8) (by scalar_tac)
    let atByte : Usize := UScalar.ofNatCore (i.val * 8 * 32) (by scalar_tac)
    have hblock : i * fr8.LANES = ok block := by
      simpa only [fr8.LANES] using scalar_mul_ok i 8#usize (by scalar_tac)
    have hat : block * BYTES_PER_FIELD_ELEMENT = ok atByte := by
      simpa only [BYTES_PER_FIELD_ELEMENT, block, atByte, UScalar.ofNatCore_val_eq] using
        scalar_mul_ok block 32#usize (by scalar_tac)
    have hbytes : atByte.val + 256 ≤ (Array.to_slice blob).val.length := by
      simp only [atByte, UScalar.ofNatCore_val_eq, Array.to_slice, blob.property]
      omega
    obtain ⟨vector, mask, hfrom, hnormal, hraw, hmask⟩ :=
      from_bytes_refinement (Array.to_slice blob) atByte hbytes
    have hraw' (lane : Fin 8) : laneNat vector lane = rawField blob i.val lane := by
      simpa only [rawField, atByte, UScalar.ofNatCore_val_eq, Array.to_slice, arrayBytes,
        Nat.mul_add, Nat.add_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc,
        Nat.add_assoc] using (hraw lane).1
    have hmask' : mask = 255#u8 ↔ ∀ lane, rawField blob i.val lane < Fr.modulus := by
      simpa only [hraw'] using hmask
    let next := alloc.vec.Vec.set data i vector
    let nextValid : Bool := if mask != 255#u8 then false else valid
    have hprefix : RawPrefix next blob (i.val + 1) := by
      refine ⟨by simpa [next, alloc.vec.Vec.set] using hd.1, ?_⟩
      intro v hv
      by_cases he : v.val = i.val
      · have hve : v = ⟨i.val, hit⟩ := Fin.ext he
        subst v
        simpa [next, alloc.vec.Vec.set, List.getElem!_set, hil] using ⟨hnormal, hraw'⟩
      · simpa only [next, alloc.vec.Vec.set,
          List.getElem!_set_ne data.val i.val v.val vector (by omega)]
          using hd.2 v (by omega)
    have hcanonical : nextValid = true ↔ CanonicalPrefix blob (i.val + 1) := by
      have hp : CanonicalPrefix blob (i.val + 1) ↔
          CanonicalPrefix blob i.val ∧ ∀ lane, rawField blob i.val lane < Fr.modulus := by
        constructor
        · intro h
          exact ⟨fun v hv => h v (by omega), h i.val (by omega)⟩
        · rintro ⟨hprev, hcurrent⟩ v hv
          by_cases he : v = i.val
          · subst v; exact hcurrent
          · exact hprev v (by omega)
      rw [hp, ← hc, ← hmask']
      by_cases hm : mask = 255#u8 <;> simp [nextValid, hm]
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by scalar_tac)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : i + 1#usize = ok i' := scalar_add_ok i 1#usize (by scalar_tac)
    have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        data i = ok (data.val[i.val]!, alloc.vec.Vec.set data i) := by
      simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize,
        List.getElem?_eq_getElem hil]
    obtain ⟨out, verdict, hout, ho, hv⟩ := ih next nextValid i' (by omega)
      (by simpa only [hi'] using hprefix) (by simpa only [hi'] using hcanonical) (by omega)
    refine ⟨out, verdict, ?_, ho, hv⟩
    have hlt : i < alloc.vec.Vec.len data := by
      simpa only [UScalar.lt_equiv, alloc.vec.Vec.len, UScalar.ofNatCore_val_eq] using hil
    have hbody : extension_kernel.ExtensionKernel.decode_loop.body blob data valid i =
        ok (cont (next, nextValid, i')) := by
      simp only [extension_kernel.ExtensionKernel.decode_loop.body, hlt, if_true,
        lift, bind_tc_ok, hblock, hat, hfrom, hmut, hadd]
      by_cases hm : mask = 255#u8
      · simp [hm, nextValid, next]
      · have hmv : mask.val ≠ 255 := by
          intro he
          apply hm
          exact UScalar.eq_of_val_eq he
        simp [hm, hmv, nextValid, next]
    rw [extension_kernel.ExtensionKernel.decode_loop, loop.eq_1]
    simpa only [hbody] using hout

theorem decode_refinement (kernel : extension_kernel.ExtensionKernel)
    (hk : StateInvariant kernel) (blob : Blob) :
    ∃ verdict next, extension_kernel.ExtensionKernel.decode kernel blob = ok (verdict, next) ∧
      StateInvariant next ∧ SameTables kernel next ∧
      (verdict = true ↔ Canonical blob) ∧
      (∀ v : Fin 512, Normalized next.data.val[v.val]!) ∧
      (∀ (v : Fin 512) (lane : Fin 8),
        laneNat next.data.val[v.val]! lane = Fr.bytesBEToNat
          ((arrayBytes blob).extract (32 * (8 * v.val + lane.val))
            (32 * (8 * v.val + lane.val + 1)))) ∧
      (verdict = true → ∃ values, blobToPolynomial (arrayBytes blob) = .ok values ∧
        DataRep (alloc.vec.Vec.deref next.data) values) := by
  obtain ⟨data, verdict, hloop, hd, hc⟩ := decode_loop blob kernel.data true 0#usize
    (by decide) ⟨hk.2.2.2.1, by simp⟩ (by simp [CanonicalPrefix])
  let next := { kernel with data := data }
  have hnext : StateInvariant next := ⟨hk.1, hk.2.1, hk.2.2.1, hd.1, hk.2.2.2.2⟩
  refine ⟨verdict, next, ?_, hnext, ⟨rfl, rfl, rfl⟩, hc,
    (fun v => (hd.2 v v.isLt).1), (fun v => (hd.2 v v.isLt).2), ?_⟩
  · have hlen : alloc.vec.Vec.len kernel.data = 512#usize := by
      apply UScalar.eq_of_val_eq
      simpa only [alloc.vec.Vec.len, UScalar.ofNatCore_val_eq] using hk.2.2.2.1
    have hmul1 : 512#usize * 8#usize = ok 4096#usize := by
      rw [scalar_mul_ok 512#usize 8#usize (by scalar_tac)]
      rfl
    have hmul2 : 4096#usize * 32#usize = ok 131072#usize := by
      rw [scalar_mul_ok 4096#usize 32#usize (by scalar_tac)]
      rfl
    simp only [extension_kernel.ExtensionKernel.decode, hlen, fr8.LANES,
      BYTES_PER_FIELD_ELEMENT, BYTES_PER_BLOB, FIELD_ELEMENTS_PER_BLOB, hmul1, hmul2,
      bind_tc_ok, massert, _root_.ite_true, hloop, next]
    rfl
  · intro hv
    have hcanonical := hc.mp hv
    obtain ⟨values, hvalues⟩ := (blob_decode_exists_iff blob).mpr hcanonical
    have hsize : values.size = 4096 := size_blobToPolynomial _ _ hvalues
    refine ⟨values, hvalues, ?_⟩
    change DataRep (alloc.vec.Vec.deref data) values
    refine ⟨by simp only [hsize, alloc.vec.Vec.deref, hd.1], ?_⟩
    intro v
    change Represents data.val[v.val] (fun lane => values[8 * v.val + lane.val]!)
    have hvt : v.val < 512 := by simpa only [alloc.vec.Vec.deref, hd.1] using v.isLt
    have hraw := hd.2 ⟨v.val, hvt⟩ hvt
    have hrawEq (lane : Fin 8) : laneNat data.val[v.val] lane = rawField blob v.val lane := by
      simpa only [getElem!_pos data.val v.val v.isLt] using hraw.2 lane
    refine ⟨⟨?_, ?_⟩, ?_⟩
    · simpa only [getElem!_pos data.val v.val v.isLt] using hraw.1
    · intro lane
      have hi : 8 * v.val + lane.val < 4096 := by omega
      have hlt := hcanonical ⟨8 * v.val + lane.val, hi⟩
      rw [hrawEq]
      have : rawField blob v.val lane < Fr.modulus := by
        simpa only [rawField, Nat.mul_comm 32] using hlt
      omega
    · intro lane
      have hi : 8 * v.val + lane.val < values.size := by omega
      have hfield := getElem_blobToPolynomial _ _ hvalues (8 * v.val + lane.val) hi
      have hfr : Fr.fromBytesBE ((arrayBytes blob).extract
          ((8 * v.val + lane.val) * 32) ((8 * v.val + lane.val + 1) * 32)) =
          .ok values[8 * v.val + lane.val] := by
        simp only [bytesToBlsField, Constants.BYTES_PER_FIELD_ELEMENT] at hfield
        split at hfield
        · cases hfield
        · cases hh : Fr.fromBytesBE ((arrayBytes blob).extract
              ((8 * v.val + lane.val) * 32) ((8 * v.val + lane.val + 1) * 32)) with
          | error err => simp only [hh] at hfield; cases hfield
          | ok f =>
            simp only [hh, Except.ok.injEq] at hfield
            simp only [hfield]
      have hval := (Fr.fromBytesBE_ok hfr).2.1
      change laneValue data.val[v.val] lane = values[8 * v.val + lane.val]!
      simp only [laneValue, hrawEq, getElem!_pos values (8 * v.val + lane.val) hi]
      apply Fin.ext
      change rawField blob v.val lane % Fr.modulus = (values[8 * v.val + lane.val]).val
      simp only [rawField, Fr.bytesBEToNat, Nat.mul_comm 32, ← hval,
        Nat.mod_eq_of_lt (values[8 * v.val + lane.val]).isLt]

end LeanBlsSimd.Kzg.Extender.Kernel
