# Development validation — 0.5.0rc3.dev5

Unreleased development candidate; no production acceptance or full OWASP/ATLAS
protection is declared. This retains the reviewed offline secret/approval key
rotation and synthetic AI characterization harness from rc3.dev4.

The rc3.dev4 image build failed because the current Alpine v3.24 repository
no longer supplied its pinned zlib 1.3.2-r1. This version explicitly pins
zlib 1.4-r0, as observed in the authenticated APK repository index. Existing
musl 1.2.6-r3 pins and the immutable Python base image are retained.

Primary release documentation: [zlib 1.4](https://www.zlib.net/), released
November 4, 2026; [Alpine package index](https://pkgs.alpinelinux.org/packages?name=zlib).
The observed target-architecture repository policy is preserved under the
failed dev4 evidence as apk-availability-probe.log. No pin was silently relaxed.

All dev4 artifacts and its exact 177-file source snapshot remain preserved.
Dev3's full local validation remains historical. Fresh installed-wheel tests,
production boundary/disk-full/synthetic AI wiring, actual AI-path full-history
characterization, exact-image scan, full capacity, fresh three-hour soak and
final snapshot are pending for this changed version.

Seven attack gaps, live-model robustness, wider platforms/integrations and
external release/review gates remain open. Rotation retains old decrypt keys;
no retirement, rollback resistance or secure erasure is claimed. The AI harness
uses only a local synthetic model and includes durable-counter fixture overhead.

## Candidate prepared

Wheel SHA256: e82d8d83a0252377d06a87f50bb0d72143aee5048dfeaa36eabdbc8ee7c304d2.
Image ID: sha256:cf6ad6f822bd795a6cefe111c51626fc01dc675e4738cf3b6031b7f7ef4fdb8e.
The networkless, read-only image probe matches the wheel package digest and
confirms zlib1.4-r0 and musl/musl-utils1.2.6-r3. Exact177input snapshot and both
locks are preserved. Bootstrap native source515passed/7skipped out522; attack
bootstrap42prevented/7benign/7confirmed gaps out56. Installed and production
checks remain pending; candidate inputs are frozen for fresh validation.

## Installed candidate checks

macOS519passed/3Linux-only skips and nativeLinux515passed/7macOS-only skips out
522 each; optionalSDK4passed (Cisco mocked). Attack scenarios:42prevented,7benign
and7confirmed gaps out56, zero unexpected failures/skips. Root's explicit
installed-wheel check passed all four report identities and outcomes, including
exact native dependency lock. Packaged mapping matches these actual reports.
Production boundary, disk-full and synthetic AI wiring are now running
sequentially under the detached, exclusively locked structural driver. No
production, AI-capacity or endurance result is inferred from launch.

## Structural pass and preserved characterization failure

Boundary38/38,disk-full20/20 and syntheticAI40/40 passed, and root verified
wheel/image/package/revision and preserved configuration hashes for all three.
The first characterization failed before requests because its builder returned
normalized internal config instead of valid user-facing JSON; serializing
nullable/default-only fields made CLI validation fail. Report and log remain
preserved. Capacity, soak and scan were not run; this candidate is superseded
by rc3.dev6 for the harness correction. No enforcement policy is relaxed.
