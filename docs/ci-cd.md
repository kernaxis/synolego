# CI and releases

The default branch is `main`. Ordinary CI never cross-compiles or packages a release.

| Workflow | Events | Checks |
| --- | --- | --- |
| CI | PR to `main`, push to `main`, manual, reusable call | Formatting, vet, minimal lint, tests with coverage, race detection on Linux amd64 |
| Security | PR, push to `main`, daily, manual, reusable call | govulncheck on Linux amd64; workflow validation and Dependency Review where applicable |
| CodeQL | PR, push to `main`, weekly, manual | Go analysis with one native build |
| Release | Version tag push or manual dispatch with a version | Version validation, CI and security gates, four Linux archives, checksums, tag and draft release |

Go comes from `go.mod`. The current module/toolchain and dependencies are not
upgraded by these workflows. Lint tools are pinned: golangci-lint v2.15.0,
govulncheck v1.9.0 (compatible with the current Go toolchain), actionlint v1.7.7,
and zizmor v1.6.0. Revisit tool versions when upgrading Go. Dependabot opens
weekly PRs for Go dependencies and Actions; it does not merge them automatically.

Local checks, with the corresponding tools available in `PATH`:

```sh
make fmt-check vet lint test race
make vulncheck
actionlint
zizmor --offline .github/workflows
```

`make test` writes `coverage.out`, which is ignored by Git. Formatting is checked
without rewriting files. No arbitrary coverage threshold is enforced. Tests use
temporary files and synthetic certificates, not live ACME/DNS/DSM credentials.
govulncheck fails for reachable vulnerabilities or scanner/database errors; no
security check is silently allowed to fail.

CodeQL uses the same Go toolchain and a manual `go build -mod=readonly ./...`
between initialization and analysis. This native build supplies its Go database;
cross-compilation and packaging remain exclusive to releases.

## Preparing a release

From GitHub, open **Actions → Release → Run workflow**, select **main** and
enter a version in the `tag` field, such as `v1.0.0` or `v1.1.0-rc.1`. No existing
tag or release is needed. A new version uses the `main` commit selected when the
run starts; later pushes to `main` do not change the commit being built. Manual
runs from other branches or tags are rejected.

The accepted formats are `vMAJOR.MINOR.PATCH` and `vMAJOR.MINOR.PATCH-rc.N`.
Pushing a version tag still triggers the same pipeline. Its commit must be an
ancestor of `main`. Manual runs can also reuse an existing tag, for example to
retry a failed release, and then build that tag's commit instead of the current
`main` commit. Tags are never moved or overwritten.

The release reruns CI and govulncheck against the resolved commit. Only for
release does govulncheck cover all four Linux architectures. CodeQL runs
independently on the branch/PR and weekly; it is not redundantly rerun on tags.

After the gates pass, the build matrix produces:

```text
synolego_1.0.0_linux_amd64.tar.gz
synolego_1.0.0_linux_386.tar.gz
synolego_1.0.0_linux_armv7.tar.gz
synolego_1.0.0_linux_arm64.tar.gz
SHA256SUMS
```

Each archive contains `synolego`, the project license, third-party notices and
generated license texts, plus the MPL-2.0 module sources. No dependency catalogue
or dependency sources are vendored in the repository. Builds disable CGO, use `-trimpath`, and embed
the tag as the CLI version. ARM explicitly uses `GOARM=7`, matching the previous
implicit build default. This does not establish support for ARMv5 NAS models.
The amd64 binary receives a `--version` smoke test. Other binaries are
cross-compiled, not executed on a NAS by Actions.

The publishing job verifies that all four archives exist and creates SHA-256
checksums. After these checks, it creates a missing tag for a new manually
requested version, pointing at the exact validated commit, then creates the
draft release. Existing tags are checked again before release creation; a moved
or deleted tag blocks publication. Only this job has `contents: write`; it
executes no repository build code. The tag uses `GITHUB_TOKEN`, so its creation
does not trigger a second workflow run.

Release build caches are disabled. All artifacts are scoped to the current run
attempt. An existing release, including a draft, is never overwritten. After a
failed run, use **Re-run all jobs** to rebuild a complete set of artifacts. If a
tag was created before release creation failed, it remains available for the
retry. If a draft already exists, review it manually instead of bypassing the
overwrite check. Do not create a release yourself before running the workflow.

The result is a **draft**, with generated notes and the prerelease flag for RC
tags. Publish it manually after NAS validation. The initial release does not
require an older tag for changelog generation. No NAS deployment, attestations,
SBOM, registry publication or automatic commit creation is included in V1.

Local packaging can be checked without publishing anything:

```sh
go install github.com/google/go-licenses/v2@v2.0.1
make package VERSION=v1.0.0 GOARCH=amd64
make releases VERSION=v1.0.0
```

Packaging requires Python 3. The release workflow installs the license tool for
the runner's architecture before cross-compiling; it is a packaging tool, not an
application dependency. The legal materials are generated inside the ignored
build directory and bundled with each binary. See
[third-party notices](../THIRD_PARTY_NOTICES.md) for the distribution details.

The `linux-amd64`, `linux-386`, `linux-arm` and `linux-arm64` convenience build
targets remain available. `make ci` now runs local quality checks; the obsolete
`sslcap`/`gox`/`release.sh` target has been removed.

## Repository settings

After the first push, enable the dependency graph and code scanning as needed,
then configure branch protection against the actual successful check names:
`quality`, `tests`, `race`, `govulncheck (amd64)`, `workflow-security`,
`dependency-review`, and `codeql`. Workflow files do not change these settings.
If using CodeQL's checked-in workflow, avoid enabling a duplicate default setup.
No personal access token or DNS secret is required; publication uses the job's
scoped `GITHUB_TOKEN`. PR jobs do not publish artifacts to GitHub Releases.
