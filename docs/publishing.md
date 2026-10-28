# Publishing packages

Silver publishes two packages through GitHub Actions:

| Package | Registry reference | Version source |
| --- | --- | --- |
| Linux amd64 image | `ghcr.io/gattaca-com/silver` | Silver release tag, such as `v0.1.0-alpha.6` |
| Helm chart | `oci://ghcr.io/gattaca-com/charts/silver` | `version` in `charts/silver/Chart.yaml`, such as `0.1.0` |

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
It creates the release tag only after the image is published.

To bootstrap an image for an existing release:

This optional path requires `gh` and `python3` on the existing `[self-hosted, silver]` publishing runner.

```bash
gh workflow run release.yaml --ref main -f existing_tag=v0.1.0-alpha.6
```

This path downloads the release's binaries and verifies their checksums and attestations.
It publishes the image and adds its link to the existing release notes.
It does not replace the binary assets or their attestations.
Rerunning it replaces the marked image section in the notes.

Images use exact release tags. No floating `latest` tag is published.

## Helm chart releases

Publish the chart after its default Silver image is available.
Bump `version` in `charts/silver/Chart.yaml` for chart changes and merge them into `main`.
Change `appVersion` only when changing the default Silver image.

Create a separate chart tag at the reviewed commit:

```bash
git switch main
git pull --ff-only
git tag helm-silver-0.1.0
git push origin helm-silver-0.1.0
```

The `helm-release` workflow verifies the tag matches the chart version, then pushes the chart package to GHCR.
It does not create a GitHub release or rebuild Silver binaries or images.
Never move a published chart tag; bump the chart version for changes.
Retry a failed chart publication from its tag:

```bash
gh workflow run helm-release.yaml --ref helm-silver-0.1.0
```

Check anonymous access after making both packages public:

```bash
docker pull ghcr.io/gattaca-com/silver:v0.1.0-alpha.6
helm show chart oci://ghcr.io/gattaca-com/charts/silver --version 0.1.0
```

Use a client without cached GHCR credentials for that check.
