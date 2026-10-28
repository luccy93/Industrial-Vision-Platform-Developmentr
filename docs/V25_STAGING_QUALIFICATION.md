# V25 Controlled Staging Qualification and Evidence Collection

V25 adds a controlled staging qualification path on top of the V24 release
qualification gate. It answers one narrow question: may this exact release be
exercised on one named staging target, and what evidence proves it? It does not
promote a release to production. Staging evidence never sets
`production_qualified`.

## Status

| Item | State | Detail |
| --- | --- | --- |
| V25 staging control plane | Complete | Explicit target contract, fail-closed validation, preflight-only default, exact-name mutation authorization |
| Staging qualification tests | Complete | 12 offline tests for target validation, production exclusion, authorization gating, honest states, and evidence tamper detection |
| Live GitHub/GHCR/attestation evidence | `UNAVAILABLE` | `gh` is not installed and `GH_TOKEN` / `GITHUB_TOKEN` are unset in this environment |
| Live staging deployment and smoke | `NOT_RUN` | No authorized staging target, deployment host, or smoke credentials exist in this environment |
| Rollback rehearsal on staging | `NOT_RUN` | Requires an authorized staging target and a previous release manifest |
| GPU runtime and inference on staging | `NOT_RUN` | No NVIDIA host or GPU runtime is available here |
| Production qualification | Not claimed | Staging reports always set `production_qualified` to `false` |

`NOT_RUN`, `UNAVAILABLE`, and `SIMULATED` never satisfy a required staging
check. A report with any required non-`PASS` check has `staging_qualified:
false`.

## Target contract

A staging run consumes one explicit JSON target validated against
`release/staging-target.schema.json`. The target must:

* set `environment` to exactly `staging`;
* use a lowercase staging `name` that does not contain production markers;
* bind `release.tag`, `release.commit`, and `release.source_repository` to the
  immutable manifest;
* use `https://` for API and web URLs and `wss://` for the WebSocket URL;
* contain no embedded credentials, query strings, or fragments;
* name a password environment variable instead of containing a password;
* reference Compose files and an optional previous manifest by relative paths
  that stay inside the repository.

Production environments, production-like names, production-like hostnames, and
credentials embedded in URLs are rejected before any command runs.

Example shape (values are illustrative, not a real deployment):

```json
{
  "schema_version": 1,
  "name": "staging-east-1",
  "environment": "staging",
  "release": {
    "tag": "v1.2.3",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "source_repository": "owner/repository"
  },
  "api_url": "https://api.staging.example.test",
  "web_url": "https://web.staging.example.test",
  "ws_url": "wss://ws.staging.example.test",
  "smoke_username": "smoke@example.test",
  "smoke_password_env": "IVP_SMOKE_PASSWORD",
  "compose_project": "ivp-staging",
  "compose_files": ["compose.release.yaml"],
  "gpu": false
}
```

## Modes

| Invocation | Mode | Behaviour |
| --- | --- | --- |
| `staging-qualify` | `preflight` | Validates the target and manifest and runs deployment preflight only. No live probe and no mutation. |
| `staging-qualify --execute` | `live-read` | Adds read-only Docker and GitHub CLI probes. No mutation. |
| `staging-qualify --execute --authorize <target-name>` | `authorized-mutation` | Required before any deployment mutation. The authorization value must exactly equal the target `name`. |

`--authorize` without `--execute` is rejected. An authorization value that does
not exactly match the target name is rejected before any command runs. The
resolved target name, environment, URLs, release subject, and image digests are
printed before any execution.

## Qualification gate

`check-staging` verifies a report produced by `staging-qualify`:

* the report is bound to the supplied manifest bytes;
* the report subject matches the manifest release;
* the target is staging and not production-like;
* the mode is `authorized-mutation` and `authorized` is true;
* the overall state is `PASS` and every required check is `PASS`;
* every evidence file still matches its recorded SHA-256;
* `production_qualified` is `false`.

A preflight-only or live-read report never passes this gate.

## Current limitations

This commit establishes the control plane and honest reporting. It does not yet
execute a deployment, run post-deployment smoke checks, collect GitHub/GHCR or
attestation evidence, rehearse a rollback, or run GPU inference. Those checks
remain required `NOT_RUN` placeholders until the evidence-collection phase is
implemented and separately authorized.

No live deployment, image publication, tag creation, GitHub Release, registry
mutation, rollback rehearsal, or destructive database operation was performed
while implementing this phase.
