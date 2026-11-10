# Alpine ARM64 runtime candidate

This is an isolated candidate for reducing the Debian OS vulnerability findings
in the default image. It does not replace the default image or waive any scanner
finding. The candidate tag is always `enkstein-guard:alpine-candidate`.

## Pinned inputs

- Base: `python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4`
  (`linux/arm64`, pulled from the official Python image repository).
- Application tested here: `enkstein-guard 0.4.0rc4` from
  `dist/deployment/enkstein_guard-0.4.0rc4-py3-none-any.whl`.
- Dependencies: `cffi 2.1.1`, `cryptography 50.0.2`, `pycparser 3.11`, and
  `pip 26.2.1`, downloaded as `musllinux_1_2_aarch64` CPython 3.12/abi3
  wheels. `dist/vendor-linux-musl-arm64/requirements.txt` SHA-locks every
  dependency wheel and the application wheel.

Prepare and build from the project root:

```sh
python tools/build_alpine_release.py --build
```

The builder sends Docker a minimal context because the default `.dockerignore`
admits only the Debian wheelhouse. The minimal context contains the candidate
Dockerfile, selected application wheel, lock file, and four dependency wheels.

For a later reviewed wheel, regenerate the lock and pass the same wheel path to
the Docker build. A changed wheel without a regenerated matching hash fails the
offline install:

```sh
python tools/build_alpine_release.py \
  --guard-wheel dist/deployment/enkstein_guard-0.4.0rc5-py3-none-any.whl \
  --build
```

The runtime has no pip, `ensurepip`, or compiler. It uses numeric UID/GID
`10001:10001`. Operators must retain the runtime restrictions used for
acceptance: read-only root filesystem, no network, all capabilities dropped,
`no-new-privileges`, and a bounded `/tmp` tmpfs. Writable state must be supplied
as an explicitly scoped mount when the daemon configuration requires it.

## Acceptance evidence

The exact candidate is scanned through `tools/scan_image.py`, which exports the
image and gives Trivy no Docker socket and no scan-time network. No findings are
suppressed. Runtime inspection and installed-wheel tests use the same candidate
tag with a read-only root filesystem, no network, no capabilities, and a bounded
`/tmp` tmpfs. Test sources are bind-mounted read-only.

Results are recorded after the experiment in `verification/alpine-*` artifacts.
Alpine/musl compatibility is a separate support surface from the default glibc
image. A clean vulnerability scan reports no known findings in that scanner DB;
it does not establish zero security risk, reachability safety, or production
readiness.
