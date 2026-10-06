# Releasing silver

The workspace `version` in `Cargo.toml` is the only input.

1. Bump `version`, e.g. to `0.1.0-alpha.2`.
2. Merge to main.

`.github/workflows/release.yaml` then sees that `v<version>` has no release yet.
It builds `silver-linux-x86_64` and `silver_surfer-linux-x86_64`, and publishes
them with their `.sha256` files and generated notes. This creates the tag at the
merge commit. The release is marked latest, so the `releases/latest/download/`
links in `README.md` always serve it.

- Merges that don't change the version publish nothing.
- A failed build publishes nothing and creates no tag. To retry, merge a fix or
  re-run the workflow from the Actions tab.
