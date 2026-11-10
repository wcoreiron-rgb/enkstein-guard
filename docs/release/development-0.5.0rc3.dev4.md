# Development validation — 0.5.0rc3.dev4

Unreleased development candidate. No production acceptance, independent human
review or full OWASP/ATLAS protection is declared. The validated rc3.dev3 wheel,
image, locks, exact input snapshot and completed evidence remain preserved.
Their results do not validate this changed candidate.

This iteration extends the existing offline `keys rotate` command to connector
secrets and approval storage, with explicit `--resume`, retained decrypt keys,
paired backup/restore compatibility, stale writer rejection and fixed partial
failure reporting. The service must be stopped. Rotation preserves secret
scopes and approval bindings/consumption; it does not retire keys, prevent
rollback to old backups or provide secure erasure. Old releases cannot read a
rotated JSON keyring; rollback needs the matching pre-rotation backup.

A new plan-first, explicitly executed synthetic AI-path characterization harness
fills every configured actor history through ordinary protected requests before
measurement. It records offered/actual/success/error counts, queue-inclusive
latency, inspector/business counter deltas and candidate identity. It never
claims production acceptance or real-model robustness. Counters are persisted
before each synthetic response, so that fixture overhead is included.

## Evidence so far

Root reviewed the two store implementations, offline CLI path and bounded
characterization topology. A mismatched approval-rotation busy error was fixed
in integration and covered by a real held-lock CLI test. Combined staged source
checks ran 522 tests: 518 passed, four skipped. One skip was a missing copied
examples directory; after copying the unchanged examples, the complete product
configuration module passed separately. The other three are Linux-only checks.
These are bootstrap source results, not installed-wheel or deployment acceptance.

Installed candidate checks, Linux checks, optional adapters, attacks, production
boundary/disk-full/AI wiring, actual AI-path characterization, exact-image scan,
full capacity, fresh three-hour soak and final snapshot remain pending. No old
result is substituted for this candidate. Seven known attack gaps and all
broader external/platform requirements remain open.

## Preserved build failure

The installed macOS wheel passed 519 tests with three Linux-only skips out of
522. Native Linux bootstrap source checks passed 515 with seven macOS-only
skips. The image build failed before a candidate image was created because
Alpine no longer supplies pinned zlib 1.3.2-r1 in its current v3.24 index.
The wheel, both locks, failed build log and 177-file exact input snapshot are
preserved. This candidate has no deployment acceptance. Dependency correction
continues as a new development version, rc3.dev5.
