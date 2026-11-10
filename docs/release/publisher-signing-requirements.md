# Publisher signing and provenance requirements

Status: **requirements defined; not satisfied.** The candidate bundle
`dist/release-0.5.0rc1/` is unsigned. The development Ed25519 key used for
0.4.0 candidates is a local tamper-evidence key and not a publisher identity;
it was not used for 0.5.0rc1.

## What exists

- `tools/build_provenance.py` writes `provenance.intoto.json` (in-toto Statement,
  SLSA provenance predicate) binding the source-tree digest, wheel digest,
  hash-locked dependency files, Dockerfile digest and base image, the container
  image ID and every acceptance evidence file, plus `manifest-unsigned.json` in the
  payload format verified by `enkstein_guard.release.verify_artifacts`.
- `reproducibility.json`: an independent rebuild from the same source produced
  identical wheel members (zip timestamps differ, so the archive hash differs;
  set `SOURCE_DATE_EPOCH` in the release builder for byte-identical archives).
- Dependency locks for Linux ARM64 glibc and musl regenerate with identical
  dependency hashes from the pinned inputs.

## Required before a release is published

1. **Build on an attested builder**, not a workstation: hosted CI with an OIDC
   identity (for example GitHub Actions on `ubuntu-24.04-arm`) running
   `.github/workflows/security-validation.yml`, so provenance names the
   repository, commit, workflow and runner instead of "local-operator-workstation".
2. **Publisher key custody**: either keyless Sigstore signing bound to the CI
   OIDC identity, or an Ed25519 key held in an HSM/KMS with at least two named
   custodians, no export, audited use, and a documented rotation and revocation
   procedure. The private key never resides on a developer machine.
3. **Independent trust anchor distribution**: publish the verification key or
   Sigstore identity policy through a channel separate from the artifacts.
4. **Sign**: the manifest payload (`payload` object in `manifest-unsigned.json`),
   the provenance statement and the container image digest (for example
   `cosign sign` on the pushed digest).
5. **Verify before deployment**: `verify_artifacts(envelope, public_key, bundle_dir)`
   for the wheel bundle and signature verification of the image digest; deploy by
   digest, never by mutable tag.
6. **Record** the signature, certificate/key fingerprint, transparency-log entry
   (if Sigstore) and verifier output in the readiness register.

## Not claimed

No signature, attested build, transparency-log entry or third-party
certification exists for 0.5.0rc1.
