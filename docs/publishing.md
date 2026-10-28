# Publishing packages

Silver publishes two packages through GitHub Actions:

| Package | Registry reference | Version source |
| --- | --- | --- |
| Linux amd64 image | `ghcr.io/gattaca-com/silver` | Silver release tag, such as `v0.1.0-alpha.6` |
| Helm chart | `oci://ghcr.io/gattaca-com/charts/silver` | Silver release tag without the `v`, such as `0.1.0-alpha.6` |

## Maintainer setup

Enable GitHub Actions and allow the actions referenced by the publishing workflows.
The publishing jobs request `packages: write` for the repository's `GITHUB_TOKEN`.
No personal access token or registry secret is required.
The repository's default token permissions can remain read-only.
Organization or enterprise policies must permit package creation and the requested job permissions.

After the first successful publication, open each package's settings under the `gattaca-com` organization.
Set both packages to **Public** so Docker and Helm can pull anonymously.
GitHub creates container packages as private by default, even for public repositories.

Confirm both packages are connected to `gattaca-com/silver`.
Under **Manage Actions access**, give that repository **Write** access if it is not inherited.
For an existing package, configure repository access before running publication.
The image source label and chart source annotation identify the upstream repository.

See GitHub's [container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
and [package access settings](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

## Silver releases

The existing release workflow runs on pushes to `main` when the workspace version has no tag.
It builds and checksums `silver` and `silver_surfer`, then packages both binaries into the image.
It tests Silver's `--version` and `--help`, Surfer's executable permission, and byte equality with both release binaries before publishing.
Surfer is an interactive TUI without `--version` or `--help` flags.
The GitHub release keeps its binaries, checksums, and attestations, plus the image tag, digest, and package link.
The image's provenance attestation is pushed to GHCR beside it. Verify it with:

```bash
gh attestation verify oci://ghcr.io/gattaca-com/silver:v0.1.0-alpha.6 --repo gattaca-com/silver
```

If publication fails before the release exists, rerun the workflow from `main`.
It creates the release tag only after the image and chart are published.

The image and chart publish from the `[self-hosted, silver]` runners, which need Docker with Buildx.

To bootstrap an image and chart for an existing release:

This optional path also requires `gh` and `python3` on those runners.

```bash
gh workflow run release.yaml --ref main -f existing_tag=v0.1.0-alpha.6
```

This path downloads the release's binaries and verifies their checksums and attestations.
It publishes the image and chart, and adds the image link to the existing release notes.
It does not replace the binary assets or their attestations.
Rerunning it replaces the marked image section in the notes.

Images use exact release tags. No floating `latest` tag is published.

## Helm chart releases

Each Silver release also publishes the chart from `main`.
The release tag sets the chart `version` and `appVersion`, overriding `charts/silver/Chart.yaml`.
A chart-only change ships with the next Silver release.

Check anonymous access after making both packages public:

```bash
docker pull ghcr.io/gattaca-com/silver:v0.1.0-alpha.6
helm show chart oci://ghcr.io/gattaca-com/charts/silver --version 0.1.0-alpha.6
```

Use a client without cached GHCR credentials for that check.
