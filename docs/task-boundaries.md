# Task boundaries

CLI configuration: a route's `task_boundaries` list maps directly onto
`TaskBoundary` objects (one per principal and workflow; the agent's `task` is
its workflow ID); see [configuration reference](configuration-reference.md).

`intent_control` lets a trusted host restrict an already admitted tool route to
one operator-defined task. It compares the operation's tenant, principal,
workflow, route, resource, destination, and operation name exactly. It also
requires the payload to match an exact dictionary schema: required fields must
be present, nested containers must be dictionaries, scalar values must have the
configured `str`, `int`, or `bool` type, and unknown fields are denied.

Configure the boundary during trusted bootstrap and add the returned async
control to the route just like any other required control:

```python
from enkstein_guard.intent import FieldRule, TaskBoundary, intent_control
from enkstein_guard.runtime import Route

boundary = TaskBoundary(
    tenant_id="tenant-a",
    principal_id="support-operator",
    workflow_id=workflow_id,
    route="ticket.write",
    resource="support-ticket",
    destination="internal-ticket-service",
    operations=frozenset({"ticket.update"}),
    fields=(
        FieldRule(("ticket", "id"), "str", choices=frozenset({"INC-42"})),
        FieldRule(("action",), "str", choices=frozenset({"comment"})),
        FieldRule(("comment",), "str", max_length=2000),
    ),
)
controls = {"task_boundary": intent_control(boundary)}
route = Route(
    "ticket.write", "ticket.update", "support-ticket",
    "internal-ticket-service", "tenant-a", ("task_boundary",), transport,
)
```

For `GuardRuntime`, the trusted `context_factory` must place the same workflow ID
in `SecurityContext`.

`ProtectedOrchestrator` can install exact boundaries after it generates a
workflow ID and before it publishes the workflow. Supply a trusted synchronous
factory at bootstrap:

```python
from enkstein_guard.orchestration import ProtectedOrchestrator

def task_boundaries(tenant, principal, workflow_id, routes):
    if len(routes) != 1 or routes[0].name != "ticket.write":
        raise ValueError("unexpected workflow tools")
    route = routes[0]
    return (TaskBoundary(
        tenant_id=tenant,
        principal_id=principal,
        workflow_id=workflow_id,
        route=route.name,
        resource=route.resource,
        destination=route.destination,
        operations=frozenset({route.operation}),
        fields=(
            FieldRule(("ticket", "id"), "str", choices=("INC-42",)),
            FieldRule(("action",), "str", choices=("comment",)),
            FieldRule(("comment",), "str", max_length=2000),
        ),
    ),)

orchestrator = ProtectedOrchestrator(
    tools=(ticket_tool,),
    controls={"policy": policy_control},
    vault=vault,
    audit=audit,
    task_boundary_factory=task_boundaries,
)
```

The factory receives the exact granted tool routes and must return exactly one
matching `TaskBoundary` for each route. The orchestrator rejects asynchronous,
missing, extra, duplicate, mismatched, or reused workflow boundaries before it
publishes the workflow. It stores the resulting controls with workflow state,
so delegated children cannot replace or bypass them. The task control evaluates
the raw local tool payload and trusted `SecurityContext`; privacy-tokenized
copies remain limited to external inspection controls.

During trusted construction, the orchestrator also preallocates vault
reservations for the sorted unique tenants represented by its tools. `start()`
rechecks the selected tenant with the vault before publishing workflow state.
Reservation errors therefore fail closed, including for a multi-tenant tool
registry.

Never accept a workflow ID from an agent request or copy one from the payload.
The factory and its configuration belong in trusted host bootstrap code.
Caller-supplied labels are not identity or authorization.

The control captures immutable snapshots of operations, field rules, and exact
choices when it is constructed. Changing a source set or list later cannot
expand the task. There are no callbacks or arbitrary predicates in a field rule.

This boundary validates declared request facts. It does not determine semantic
intent or business truth. The ticket service still needs server-side checks for
facts such as whether `INC-42` exists, whether it belongs to the tenant, whether
the principal may comment on it, and whether its current state permits the
operation. Keep direct service credentials and alternate network paths outside
the untrusted caller's reach.
