# Protected orchestration — 0.3.0.dev0

Scope: one trusted coordinator, local encrypted artifacts/memory, registered
tools, optional macOS workers and a tested LangGraph reference. This is the
steps 7–10 application profile, not universal cloud/framework enforcement.

## Security model

Trusted bootstrap creates workflows with fixed tenant/user identity, routes and
shared Budget. Agents receive random credentials in Lease objects; credentials
are hashed in the coordinator and omitted from repr/audit. Do not expose start(),
the vault, raw callbacks or approver credentials as agent tools. AgentSession
exposes the scoped execution path. Same-process malicious Python can introspect
objects; use an independent host/gateway to isolate truly untrusted agents.

Delegation requires its own grant. Every child inherits tenant, principal and
workflow, receives a new agent ID, and may request only a subset of its parent's
grants. Agent count, delegation depth, call count, work units, concurrency and
deadline belong to the shared workflow. Admission reserves counters before await;
failed attempts that reached controls retain their call/unit charge. Units are
host-configured reservations, not measured provider tokens or currency. Configure
worst-case route units and provider output limits before claiming cost limits.
There is no cross-process/distributed budget ledger in this version.

## Data and memory

Tools return encrypted artifact handles. Reads, writes, handoffs and mailbox
receives are separately granted and policy checked. Artifacts carry server-side
origin and labels; caller-supplied labels are never trusted. Memory values remain
encrypted at rest, old artifacts remain addressable to authorized workflow agents,
and every agent memory write adds an untrusted classification. Memory content
cannot change capability grants. Indexes and workflow state are process-local;
they are not durable cross-session memory or tamper-resistant distributed state.

Workflow-wide labels are sticky: source labels and locally detected sensitive
arguments/results propagate across every descendant and arbitrary summary.
This intentionally over-restricts some unrelated branches rather than pretending
to track exact semantic lineage. Tools must explicitly accept the accumulated
labels; approvals do not clear them. Authorization and component integrity are
rechecked immediately before dispatch. A label added while another operation
waits for inspection can therefore block that pending operation.

Inspectors receive locally tokenized payloads. Fixed route metadata identifies
the resource and destination. Trusted transport callbacks receive approved actual
arguments and must enforce their configured endpoint/resource semantics; arbitrary
dynamic recipient/business-logic validation is not inferred from a route name.
Use PrivateAI/BrokeredChatProvider for model/API privacy; do not send read() results
to a direct unprotected SDK. Untracked traffic outside registered boundaries is
not covered. Known opaque vault markers are treated as sensitive, not as authority.

Handoffs authenticate the sender's lease, require a live recipient in the same
workflow, carry server-resolved artifacts, and reject duplicate sender/recipient/
artifact deliveries. This is in-coordinator messaging, not network A2A encryption,
remote identity federation or a persistent replay ledger.

## Approvals

An agent may request a ticket; only a separately configured tenant-authorized
human/host credential can review and approve. Review returns trusted resource,
destination, a redacted payload and action digest. Tickets bind workflow, agent,
tenant/principal, exact arguments, route, resource, destination, component hash
and policy contract version. They expire and are consumed at dispatch. Child
substitution, modified arguments and replay fail. A human approval cannot override
an explicit policy denial or information-flow restriction. The API is intended
for an existing host approval UI; no new dashboard is introduced.

## Component admission and containment

Every registered Tool requires a trusted manifest file/hash. Byte integrity is
checked at registration and again at dispatch. A changed component is denied.
This proves admission against a host-approved pin, not that a component is benign.
General malware/dependency/skill/MCP scanning and signed supply-chain attestation
are not supplied by a hash. DefenseClaw scanner integration remains a separate
production admission option, not an enabled feature here.

SandboxedPythonWorker executes a verified byte snapshot, preventing source-file
replacement between validation and execution. The worker has a fresh working
directory, JSON stdin, scrubbed environment, bounded output/time, and no shell.
On macOS the deny-by-default sandbox profile permits Python/system runtime reads,
filesystem metadata and listing the filesystem root; only the working directory
is writable. Network and unrelated private-file reads are denied in actual tests.
Runtime/virtual-environment directories must not contain secrets. This profile is
platform-specific and depends on Apple's sandbox-exec; there is no unsandboxed
fallback or Linux/Windows/cloud profile. A sandbox escape is not ruled out by
these tests. Operators must validate their Python/runtime paths before deployment.

Cancellation revokes an agent subtree before signaling tasks. Registered workers
are killed by process group and reaped; late results are denied. In-process
callbacks use cooperative cancellation and cannot be forcibly stopped by Python.
Independent gateway/network/credential revocation is still needed for rogue
processes outside the worker profile. No cancellation result implies rollback
of side effects that already occurred.

## Run

```sh
python -m pip install .
python examples/protected_orchestration.py
# Optional actual LangGraph profile:
python -m pip install -r requirements-orchestration.txt
python examples/protected_orchestration.py --langgraph
```

The reference delegates to a child, reads a protected source, summarizes it, and
proves no external messaging transport executes. Graph state contains handles
and a blocked flag, never raw customer content or agent credentials. Keep those
values out of custom graph checkpoints/traces as well. AgentSession.tool_node is
a LangGraph-compatible async node factory, not automatic interception of every
LangGraph tool or arbitrary coding-agent hook.

Verification logs and artifact hashes are under verification/. No OWASP category
is declared fully validated by this increment. See the versioned acceptance
matrix for remaining category/ATLAS evidence requirements.
