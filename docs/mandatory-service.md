# Persistent local enforcement service

> The CLI product runs `GuardService` through `enkstein-guard service start`
> (`host.ProductService`), adding diagnostics IDs, approvals, sensitivity release
> checks and an admin socket. See the [operator guide](cli-operator-guide.md).

GuardService hosts an existing configured GuardRuntime behind a bounded Unix
socket. Agents send only credential, route and JSON payload. The trusted service
owns identity registration, policy callbacks and connectors; caller-provided
identity context, destinations and control verdicts are not accepted.

Python 3.11 or newer is required. Create an operator-owned directory with mode
0700, configure a GuardRuntime in trusted bootstrap, then run:

```python
service = await GuardService(runtime, "/private/operator/run/guard.sock").start()
# Keep the host event loop running; drain/shutdown with await service.close().
```

Clients use `guarded_request(socket_path, credential, route, payload)`. Responses
have explicit status codes. Never automatically retry unknown outcomes. Configure
PrivateAI/ProtectedOrchestrator paths separately: this IPC implementation exposes
GuardRuntime routes, not every orchestration method or automatic output inspection.

Each request is authenticated and inspected. Tenant comes from trusted credential
registration. The default service admits 32 active connections, limits input and
output frames to 1 MiB, and imposes a 60-second request timeout. Overload returns
busy; this is not a durable queue. Shutdown cancels active tasks; external side
effects may already have happened. Audit, tokenization and inspection are those
explicitly configured on the underlying routes, not automatic side effects of
starting the service. Raw data must not be returned to unauthorized agents.

## Required deployment boundary

Place the service in a separate trusted process. Workers must not possess connector
credentials, service source write access, unrestricted egress or access to other
tenants' stores. Socket permissions constrain local access but are not tenant
isolation between arbitrary same-user processes. Bearer credentials must remain
scoped and confidential; compromised same-user processes are not isolated by this
socket. Use separate OS identities/containers and controlled socket mounts in a
real deployment. The service does not install firewall rules or establish these
boundaries. Windows and authenticated remote transport are not implemented.

Normal policy-approved requests proceed. Failed required checks deny the request;
there is no unchecked fallback. Business availability needs redundant deployment,
durable queues and explicitly governed fallback paths; these remain open work.
This service does not establish complete OWASP or MITRE ATLAS coverage.
