# Reuse inventory and source boundary

This package is standalone. Upstream application checkouts and their private
runtime configuration are not dependencies and are not included here.

| Component | Action | Reason / remaining review |
|---|---|---|
| Public Guard scanner | Copied with SHA-256 provenance | Dependency-free; retains upstream behavior and known limits |
| Root license | Copied verbatim | MIT attribution preserved; no inference from plugin manifest license |
| Hook/backend wiring | Read only, not copied | Coupled to application and host contracts; adapt later |
| Policy engine / ring enforcement | Read only, not copied | Preserve originals; new contract must compose applicable controls explicitly |
| Connector secrets manager | Read only, not copied | Has local modifications; vault extraction needs key lifecycle and tenant review |
| Credential requests/approvals | Read only, not copied | Existing foundation; exact-action binding not yet proven |
| Swarm/memory | Read only, not copied | Framework-specific; future adapters rather than vendoring application |
| Private policy packs / keys / databases | Not read or copied | Operator-provided runtime assets, excluded from distribution |
| AGT/NeMo/Cisco | Not bundled | Pin API/license/maintenance and select a capability before adding dependencies |

`docs/source-provenance.json` records the exact imported bytes. Its revision is
the source checkout HEAD at copy time, not a statement that all working-tree
files were clean. Imported scanner and license hashes are the content identity.
New `contracts.py`, config and CLI code are independent additions, not upstream
policy behavior. No full policy-catalog count can be inferred from these copies.

## Risks carried forward

The scanner uses heuristics and placeholder exemptions, imports operator packs,
and truncates private-pack scanning. Unknown pack actions degrade to monitor and
invalid expressions may be skipped. These compatibility behaviors must be
reported now and replaced with validated admission in protected mode later.
The pure aggregation contract does not close host-hook, transport, replay,
isolation or workflow-lineage gaps.

Initial validated environment: local macOS / Python 3.14. Other Python versions,
Windows, Linux and cloud deployments are targets, not tested compatibility claims.
