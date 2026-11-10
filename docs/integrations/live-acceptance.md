# Live integration acceptance procedures (Hatz, Cisco AI Defense)

Status: **prepared, not executed.** No live credentials were available to this
work. All existing provider tests use captured or mocked responses and are
labelled as such; they are not live acceptance.

## Preconditions (operator)

- Written authorization to send synthetic traffic to the named nonproduction
  tenant/account, including any usage cost.
- Nonproduction credentials delivered through approved secret handling as a
  file with mode `0600` (or via stdin). Never in arguments, configuration,
  environment variables, shell history or tickets.
- The exact endpoint host(s) added to `egress.allow` and the connector configured
  in `guard.json`.
- A stopped-or-running Guard you can observe with `service status` and audit.

## A. Hatz (chat completions, `x-api-key`)

1. Direct connectivity and response shape (no Guard topology):

   ```sh
   python tools/live_integration_check.py hatz \
       --endpoint https://<hatz-host>/v1/chat/completions --model <nonprod-model> \
       --credential-file /secure/hatz-nonprod.key --i-have-authorization \
       --output verification/cli-v1/live-hatz.json
   ```

   Expected: `status: ok`, `response_shape.has_choices: true`. The report holds
   no key, prompt or reply text.
2. End to end through the production stack:

   ```sh
   # guard.json: connector {"type":"chat_completions","endpoint":"https://<hatz-host>/v1/chat/completions",
   #   "model":"<nonprod-model>","credential":"hatz-key","authentication":"x-api-key"}
   # route {"name":"model.chat","connector":"hatz",...,"privacy":"tokenize","clearance":"internal"}
   # egress.allow += {"host":"<hatz-host>","port":443}
   docker compose -f deployment/compose.production.yaml run --rm --no-deps -T guard \
       --config /bootstrap/guard.json connector secret-set --name hatz-key --tenant <tenant> \
       --destination <hatz-host> --route model.chat --value-file - < /secure/hatz-nonprod.key
   docker compose -f deployment/compose.production.yaml up -d egress guard
   # from an agent container: request route model.chat with a synthetic prompt containing a synthetic email
   ```

   Expected: agent receives `ok`; egress log shows one `allowed` decision for the
   host; `diagnose --id` shows `transport_completed`; the provider receives a
   vault reference instead of the synthetic email (check with the vendor's
   request log if available); `audit export` and container logs contain no key.
3. Negative checks: wrong key → `execution_or_audit_failed_outcome_unknown`
   with no retry; host removed from `egress.allow` → service refuses to start
   (`destination_not_on_egress_allowlist`); model override in the payload →
   denied before any call.
4. Clean up: `connector secret-remove --name hatz-key`; revoke the
   nonproduction key with the vendor; delete local key files.

## B. Cisco AI Defense (inspection SDK)

1. Prepare a Python 3.11 environment with `requirements-engines.txt` (pins
   `cisco-aidefense-sdk==2.2.0`).
2. Run:

   ```sh
   python tools/live_integration_check.py cisco --api-key-file /secure/aidefense-nonprod.key \
       --i-have-authorization --output verification/cli-v1/live-cisco.json
   ```

   Expected: a verdict for a benign prompt and for a synthetic injection; record
   both. The vendor's policy decides the verdicts — the acceptance criterion is
   that verdicts are returned, parsed strictly, and that an explicit Block maps
   to deny. Errors/timeouts must surface as denial when the control is required.
3. Wire `cisco_control` as a required PrivateAI/SDK control (CLI routes do not
   yet expose external inspection engines; that integration is SDK-only in
   this release).
4. Clean up: revoke the key with the vendor; delete local files.

## Recording results

Add the generated JSON to `verification/cli-v1/`, reference it from the
readiness register (R-INT-01/R-INT-02) and note the date, tenant/account
(non-secret identifier), endpoint host and the operator who authorized it.
