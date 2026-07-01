# Release Guide

## Automated Release Process

This project is configured with automated CI/CD workflow that builds and publishes releases when new version tags are pushed.

## Release Steps

### 1. Update Version Information

First, update `CHANGELOG.md` to record the changes for this release:

```markdown
## [1.0.1] - 2025-01-15

### Added

- New feature description

### Changed

- Changes description

### Fixed

- Bug fixes description
```

### 2. Commit Changes

```bash
git add .
git commit -m "chore: prepare for release v1.0.1"
git push origin main
```

### 3. Create and Push Tag

```bash
# Create tag
git tag -a v1.0.1 -m "Release v1.0.1"

# Push tag to remote repository
git push origin v1.0.1
```

### 4. Automated Build

After pushing the tag, GitHub Actions will automatically:

1. ✅ Build binaries for the following platforms:

   - Linux x86_64
   - Linux ARM64
   - macOS x86_64 (Intel)
   - macOS ARM64 (Apple Silicon)
   - Windows x86_64

2. ✅ Create compressed archives for each binary:

   - Linux/macOS: `.tar.gz` format
   - Windows: `.zip` format

3. ✅ Generate SHA256 checksums file (`checksums.txt`)

4. ✅ Automatically create GitHub Release

5. ✅ Upload all binaries to the Release

6. ✅ Publish/update the Homebrew tap formula (if `HOMEBREW_TAP_TOKEN` is configured; see below)

### 5. Verify Release

Visit the GitHub Releases page to verify:

```
https://github.com/talkincode/sshx/releases
```

Check:

- ✅ Release has been created
- ✅ All 5 platform binaries have been uploaded
- ✅ checksums.txt file exists
- ✅ Release notes are complete

## Version Numbering

Follow [Semantic Versioning](https://semver.org/) specification:

- **MAJOR version**: incompatible API changes
- **MINOR version**: backwards-compatible functionality additions
- **PATCH version**: backwards-compatible bug fixes

Examples:

Examples:

- `v1.0.0` - Initial stable release
- `v1.1.0` - Add new features
- `v1.1.1` - Bug fixes
- `v2.0.0` - Breaking changes, not backwards compatible

## Pre-release Versions

To publish a test version:

```bash
# Beta version
git tag -a v1.1.0-beta.1 -m "Release v1.1.0-beta.1"
git push origin v1.1.0-beta.1

# Release Candidate version
git tag -a v1.1.0-rc.1 -m "Release v1.1.0-rc.1"
git push origin v1.1.0-rc.1
```

Pre-release versions will be marked as "Pre-release" in GitHub Release.

## Delete Incorrect Tags

If you pushed an incorrect tag:

```bash
# Delete local tag
git tag -d v1.0.1

# Delete remote tag
git push origin :refs/tags/v1.0.1
```

## Manual Build (Development Testing)

To test the build locally:

```bash
# Build all platforms
make build-all

# View build results
ls -lh bin/
```

## Troubleshooting

### Build Failure

1. Check GitHub Actions logs
2. Verify `go.mod` dependencies are correct
3. Ensure all tests pass: `make test`

### Release Not Created

1. Check if tag format matches `v*.*.*`
2. Verify GitHub Actions permissions
3. Check if `GITHUB_TOKEN` is valid

### File Upload Failure

1. Check file size limits
2. Verify network connection
3. Review detailed error messages in Actions logs

## Homebrew Tap Publishing

On every tag push, the `homebrew` job in `.github/workflows/release.yml` renders and
pushes a `Formula/sshx.rb` file to the `talkincode/homebrew-tap` repository, so
users can run:

```bash
brew install talkincode/tap/sshx
```

The formula is built from the `checksums.txt` produced by the `build` job, and
covers `darwin`/`linux` on both `amd64` and `arm64`. Windows has no Homebrew
equivalent, so it is intentionally excluded from the formula.

### One-time setup

1. Create (or reuse) a `talkincode/homebrew-tap` repository with a `Formula/`
   directory.
2. Generate a fine-grained GitHub Personal Access Token scoped to `Contents:
   write` on that repository only.
3. Add it as a repository secret named `HOMEBREW_TAP_TOKEN` in `talkincode/sshx`
   (Settings → Secrets and variables → Actions).

If `HOMEBREW_TAP_TOKEN` is not set, the `homebrew` job no-ops (its steps are
skipped) and the rest of the release is unaffected — this mirrors how the
project treats other optional publish integrations.

### Verifying a published formula

```bash
brew tap talkincode/tap
brew install sshx
sshx --version
```

Or inspect the rendered formula directly:

```
https://github.com/talkincode/homebrew-tap/blob/main/Formula/sshx.rb
```

## CI/CD Workflows

### Release Workflow (.github/workflows/release.yml)

Trigger: Push tags matching `v*.*.*` format

Tasks:

1. Checkout code

### CI Workflow (.github/workflows/ci.yml)

Trigger: Push to main/develop branches or Pull Requests

Tasks:

1. Run tests on multiple operating systems
2. Generate code coverage reports
3. Run code checks (golangci-lint)
4. Run security scans (gosec)

## Reference Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Go Release Workflow Examples](https://github.com/marketplace/actions/go-release-binaries)
- [Semantic Versioning Specification](https://semver.org/)
