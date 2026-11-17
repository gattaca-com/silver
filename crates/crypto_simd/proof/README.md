# Formal proof of BLS decoding and KZG cell operations

One Lean project checks the Charon/Aeneas translation of `silver_crypto_simd`'s x86_64 build.
It covers the G1 and G2 batch decoders, `bls::PairingProduct`, `kzg::CellBatchVerifier` and `kzg::CellExtender`.
The target is the executable specification in [ethereum/EthLib](https://github.com/ethereum/EthLib).

The pins live in `lean/lakefile.toml` and `lean/lake-manifest.json`:

| Dependency | Pin |
|---|---|
| Lean, Mathlib | v4.35.0 |
| EthLib | `98395150e9eb6a11fd85022bee7ea9da9a8e3760` |
| Aeneas | `nightly-2026.10.30-de16f3c` (`backends/lean`) |

The Lake package is `lean_bls_simd`; its library is `LeanBlsSimd`.
[`lean/README.md`](lean/README.md) explains how to change the Rust or the proofs.

## What is proved

Every headline states that the generated function returns `ok`.
In Aeneas's semantics, that rules out both a panic and divergence.
Each result is then equal to the specification's verdict, under the premises listed below.

| Rust API | Lean theorems | Lean module | Premises beyond the trust list |
|---|---|---|---|
| `bls::uncompress_in_g1` | `uncompress_in_g1_eq_spec`, `uncompress_in_g1_eq_spec_list` | `LeanBlsSimd.Refines.UncompressG1` | `UncompressG1.FallbackCorrect`, which applies only when `simdAvailable = false` |
| same, IFMA route | `uncompress_in_g1_eq_spec_list_ifma` | same | none |
| `bls::uncompress_in_g2` | `uncompress_in_g2_eq_spec_or_blst` | `LeanBlsSimd.Refines.UncompressG2` | none; fallback lanes return the opaque blst verdict |
| same, exact equality | `uncompress_in_g2_eq_spec_list` | same | `UncompressG2.BlstMatchesSpec` |
| G2 kernel `decompress_g2::decompress` | `decompress_extracted_eq_spec_complete` | `LeanBlsSimd.Refines.Complete` | none; covers decided lanes only |
| `bls::PairingProduct` | `build_is_one_correct`, `built_owner_correct`, `two_pairs_are_one_correct`, `is_one_correct` | `LeanBlsSimd.PairingProduct.Headline` | `PairingProduct.BlstMatchesSpec` and valid input points |
| `kzg::CellBatchVerifier` | `Kzg.verify_eq_spec`, `Kzg.verify_eq_upstream` | `LeanBlsSimd.Kzg.Statements` | `UncompressG1.FallbackCorrect` and `Kzg.BlstPairing.CorrectFor` per state |
| same, IFMA route | `Kzg.verify_eq_spec_ifma`, `Kzg.verify_eq_upstream_ifma` | same | `simdAvailable = true` and a lane workspace |
| `kzg::CellExtender` | `Kzg.Extender.compute_eq_spec` | `LeanBlsSimd.Kzg.Extender.Statements` | none |
| `G1Point::from_blst`, `G2Point::from_blst` | `g1_from_blst_some_iff`, `g2_from_blst_some_iff` | `LeanBlsSimd.Refines.CheckedPoints` | `ConstructorsMatchSpec` |
| `hash_to_curve`, `weighted_sum`, `negative_generator` | contracts only | `LeanBlsSimd.Refines.PointOperations` | `OperationsMatchSpec` |

The theorem statements in those modules are the authoritative claims.
The notes below explain the parts a reader may misread.

- **Decoders.** Each output slot equals the specification verdict for its input.
  The exception is a G2 fallback lane without `UncompressG2.BlstMatchesSpec`.
  Accepted points have canonical coordinates and lie in the prime-order subgroup.
  Unequal input and output lengths return `fail .assertionFailure`.
  The proofs do not retain Rust's panic text.
- **G1 routes.** IFMA lanes, IFMA tails and undecided lanes are proved.
  Tails and undecided lanes go through the generated portable decoder, proved by `Portable.Decode.g1_decoder_correct`.
  Without IFMA, each input calls the opaque blst decoder.
- **G2 routes.** `usesKernelAt_iff` characterizes when a lane uses the kernel.
  Smaller chunks, undecided lanes and calls without SIMD use the opaque blst decoder.
  The proof does not show that subgroup members always take the kernel route.
- **Pairing products.** The IFMA lane route is proved without a blst law.
  The blst route and the whole-product fallback use `PairingProduct.BlstMatchesSpec`.
  Infinity pairs are filtered before blst, as the specification skips them.
- **KZG verifier.** Construction establishes `StateInvariant`; every call preserves it, including rejected calls.
  Specification errors become `false`: length mismatches, invalid encodings and out-of-range indices.
  `verify_eq_upstream` additionally assumes `TrustedSetup.get! = pure embeddedSetup`.
- **KZG extender.** `compute` returns `true` exactly for canonical blobs.
  On success it writes the specification's exact cell bytes.
  On rejection it leaves the output unchanged.
- **Inputs.** `Input.Representable` only bounds each slice by `isize::MAX` bytes.
  There is no batch-size limit.

Out of scope:

- full BLS signature verification, public-key admission and random-weight batching;
- correctness of hash-to-G2 and weighted sums, which remain blst contracts;
- the non-x86_64 build;
- route choice, fallback frequency and performance;
- heap exhaustion and allocator capacity panics, which Aeneas does not model.

## What a reader must trust

1. **Lean and dependencies.** Lean v4.35.0's kernel and the three standard axioms: `propext`, `Classical.choice` and `Quot.sound`.
   `LeanBlsSimd/Axioms.lean` rejects any other reported dependency of a checked theorem.
   `acceptedAxioms` is empty, so `sorryAx`, `native_decide` and `bv_decide` fail.
   `lake exe cache get` downloads Mathlib `.olean` files, which Lean imports without rechecking.
   Building Mathlib from source removes that reliance.
2. **Specification.** Mathlib and [EthLib at `98395150`](https://github.com/ethereum/EthLib/tree/98395150e9eb6a11fd85022bee7ea9da9a8e3760) define the target.
   This includes field and group laws, decoders, subgroup checks, KZG validation, cell verification and `computeCells`.
   Their fidelity to Ethereum's requirements is trusted.
   Manual review connects `G2Spec.verdict` to the decoding stage of `coreVerify`.
3. **Input and output interpretation.** `ofArray`, `ofU8`, `ofBatch` and the affine conversions preserve bytes, lanes and fields.
   G1 and G2 coordinates are six little-endian 64-bit Montgomery limbs with R = 2^384.
   G2 orders c0 before c1 and x before y; infinity is all-zero.
   KZG scalars are four 64-bit Montgomery limbs with R = 2^256.
   This is blst's 64-bit platform layout.
4. **Extraction.** Trust includes Charon's MIR semantics, Aeneas's translation and the [preparation step](#reproducing-the-extraction).
   Charon's revision comes from the pinned Aeneas checkout's `charon-pin`.
   `extract.sh` verifies both checkout pins and the commits both binaries report.
   `--check` detects drift; it does not prove the translators correct.
5. **External semantics.** `Extracted/TypesExternal.lean` and `FunsExternal.lean` are handwritten.
   They bind AVX-512 and SHA/SSE intrinsics, carry arithmetic, lane extraction, feature detection and standard-library calls.
   Their agreement with hardware, ABI and the standard library is trusted.
   Controls check concrete cases and selected mutations.
6. **CPU observations and blst decoders.** `RuntimeFeatures` supplies independent SIMD, SHA and BMI2 Booleans.
   Real execution needs hardware support for every instruction on the selected route.
   `BlsExternals` holds only the G2 signature decoder.
   `KzgExternals` holds G1 decoding and the scalar KZG pairing.
   These opaque calls are assumed to return `ok`.
7. **Signature pairing through blst.** `PairingProduct.BlstMatchesSpec` trusts the whole `PairingInputs::blst_is_one` wrapper on finite subgroup pairs.
   Raw `blst_miller_loop_n` does not skip G2 infinity, so the law applies only after the proved infinity filter.
   KZG and decoder headlines do not use it.
8. **Runtime setup.** `verify_eq_upstream`, `verify_eq_upstream_ifma` and `Kzg.model_eq_spec` assume `TrustedSetup.get! = pure embeddedSetup`.
   `verify_eq_spec` instead uses the embedded value and its kernel-checked certificates.

### Axioms

The production import environment declares exactly 15 axioms.
`LeanBlsSimd/AxiomInventory.lean` pins their names; `controls/AxiomInventory.lean` fails on any added or missing name.
It compares names only, not statements.
Lean core contributes the three standard axioms, `sorryAx` and eight unsafe compiler primitives.
Aeneas contributes three:

| Aeneas axiom | Role |
|---|---|
| `Aeneas.Data.ListN.Test.E2` | Recovery stub from a rejected positivity test |
| `Aeneas.Data.ListN.Test.E3` | Recovery stub from a rejected positivity test |
| `Aeneas.Std.core.slice.Slice.get_unchecked_SliceIndexUsizeSlice_spec` | Unchecked slice indexing contract |

The per-theorem allow-list still admits only the three standard axioms.
The guard walks Silver-defined constants directly and uses Lean's exported axiom lists at foreign constants.
Lean 4.35's exported lists can miss dependencies reached through type/constructor cycles inside a dependency.
An existing pinned Aeneas axiom reached only that way would go undetected.

### Opaque Rust functions

`extract.sh` keeps these functions opaque. Extraction does not refine their source.

| Rust function | Lean interpretation |
|---|---|
| `bls::fp8::lanes` | Bitwise extraction of the eight vector lanes |
| `ifma_available`, `sha_available`, `bmi2_available` | The fixed Booleans in `RuntimeFeatures` |
| `bls::uncompress_in_g1_blst` | The non-IFMA G1 observation in `KzgExternals` |
| `kzg::blst_pairing::pairing_check` | The scalar two-pair observation in `KzgExternals` |
| `bls::uncompress_in_g2_blst` | The G2 observation in `BlsExternals`; unused by KZG |
| `bls::pairing_product::PairingInputs::blst_is_one` | `PairingExternals.check`, constrained by `PairingProduct.BlstMatchesSpec` |
| `G1Point::from_blst`, `G2Point::from_blst` | `PointExternals`, constrained by `ConstructorsMatchSpec` |
| `G1Point::negative_generator`, `G2Point::hash_to_curve`, both `weighted_sum` methods | `PointOperationExternals`, constrained by `OperationsMatchSpec` |
| `sha256::extensions::load_bytes`, `load_words`, `store_words` | Raw-pointer loads and stores replaced by 32-bit lane packing |

## How the Rust is tied to the model

The Lean proofs are about generated code, so the tie to Rust is the extraction plus finite evidence.

- **Extraction drift.** `extract.sh --check` reruns Charon and Aeneas on the crate.
  It compares the result with `LeanBlsSimd/Extracted/Types.lean`, `Literals.lean` and `Funs.lean`.
  Only the line numbers in Aeneas's `Source:` comments are masked.
  CI runs this check on every change to the crate.
- **BLS vectors.** `decompress_g1_vectors.txt` and `decompress_g2_vectors.txt` record kernel and wrapper outputs plus blst verdicts.
  `proof/vectors.rs` (`cargo test --test proof_vectors`) replays them against the Rust.
  `lake exe differential` replays them against the Lean model and the generated code.
  These are finite checks; they do not prove `BlstMatchesSpec` or `FallbackCorrect`.
- **KZG vectors.** `src/kzg/spec_vectors.rs` runs EthLib's KZG vectors fetched by `make -C crates/crypto_simd`.
  The Makefile pins an older EthLib revision than `lean/lakefile.toml`.
  `src/kzg/tests.rs` compares with c-kzg.

`replay_vectors` skips without AVX-512 IFMA unless `SILVER_REQUIRE_IFMA` is set.
CI sets it only on IFMA hosts.
To regenerate the BLS vectors on an IFMA host, from the repository root:

```sh
cargo test -p silver_crypto_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
```

## Reproducing the proof and checks

CI runs `.github/workflows/crypto_simd_proof.yaml` when the crate, the workflow or its locked dependencies change:

| Job | Runs |
|---|---|
| `extraction` | `extract.sh --check`, then `controls/extraction-check.py` |
| `lean` | `lake exe cache get` and `lake build`, including the axiom guard and inventory |
| `lean-controls` | Every `controls/*.lean` file |
| `lean-downstream` | The independent `controls/downstream` package |
| `lean-differential` | The differential vector test and `Test/check_g1_controls.py` |
| `rust` | `make -C crates/crypto_simd` and `cargo test --locked -p silver_crypto_simd --all-features` |

You need [elan](https://github.com/leanprover/elan). From `lean/`:

```sh
lake exe cache get
lake build
```

`lake build` reports `axiom inventory: exactly 15 declarations` and `axioms used: [propext, Quot.sound, Classical.choice]`.
`lake build --wfail` also rejects warnings.

Controls check that selected mutations are rejected and concrete cases hold. Every file must exit 0:

```sh
(
  for f in controls/*.lean; do
    lake env lean -DautoImplicit=false -DrelaxedAutoImplicit=false "$f" || exit 1
  done
)
python3 -I controls/extraction-check.py
```

The source mutation checks are development tools; CI does not run them. Run them after `lake build`:

```sh
for f in controls/*-mutation-check.py; do python3 -I "$f"; done
```

The downstream package applies the public results across a package boundary:

```sh
(cd controls/downstream && lake update && lake build --wfail)
```

If `controls/downstream/.lake/packages` does not exist yet, symlink it to `../../../.lake/packages` to reuse the parent's checkouts.

The differential vector test, from `lean/`:

```sh
lake build differential
lake exe differential ../decompress_g2_vectors.txt --g1 ../decompress_g1_vectors.txt
python3 -I Test/check_g1_controls.py
```

The executable exits 0 when every value matches, 1 on a mismatch and 2 on a malformed file.
`check_g1_controls.py` also runs `check_g2_controls.py`.

The Rust checks, from the repository root:

```sh
make -C crates/crypto_simd
SILVER_REQUIRE_IFMA=1 cargo test --locked -p silver_crypto_simd --all-features
```

Serialize top-level Lean commands; each can use several Lean processes and much memory.

### Reproducing the extraction

`AENEAS_DIR` must name an [Aeneas](https://github.com/AeneasVerif/aeneas) checkout at the revision `lean/lake-manifest.json` pins.
In that checkout, `make setup-charon` builds Charon at `charon-pin`, and `make` builds Aeneas.
Charon also needs rustup to install its nightly. From `lean/`:

```sh
AENEAS_DIR=/path/to/aeneas ./extract.sh --check
```

Without `--check`, the script replaces `Types.lean`, `Literals.lean`, `Funs.lean` and `controls/ExtractedLiterals.lean`.
`prepare-extraction.py` adapts the raw Aeneas output before comparison:

- it binds `RuntimeFeatures`, `KzgExternals`, `BlsExternals` and `PairingExternals` where generated definitions use them;
- it quotes the eight generated `full` identifiers;
- it supplies structural `Array.make` length witnesses;
- it hoists large literal tables into `Extracted/Literals.lean`, preserving type, order and contents.

`controls/ExtractedLiterals.lean` checks the hoisted values against the raw extraction.
