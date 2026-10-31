# V28 Live Infrastructure Verification

V28 extends the V26/V27 staging readiness report with an explicitly authorized,
read-only inspection of the external release infrastructure:

- the GitHub tag, release, release assets, and release workflow run;
- the published GHCR image digests and platform metadata;
- GitHub attestations and the local SBOM/scan evidence;
- bounded DNS, TCP, TLS, HTTPS, and WSS reachability of an explicit staging
  target;
- the readiness of an existing Docker context;
- rollback prerequisites: distinct previous digests, a previous production
  verification report, executed rollback evidence, migration compatibility,
  and backup/restore documentation.

V28 never deploys, publishes, tags, retags, dispatches a workflow, runs a
migration, restores a backup, deletes a volume, changes DNS, IAM, firewall, or
network configuration, or executes a rollback. It is an inspection layer. A
`PASS` is preparation evidence only; it is not production qualification and
does not authorize a deployment.

## Opting in

V28 is an explicit profile of the existing readiness report. The CLI always
requests it; direct Python callers keep the V26/V27 behavior unless they pass
`inspection_profile="v28"`.

```bash
python -m tools.release.cli staging-readiness \
  --manifest release-artifacts/release-manifest.json \
  --target staging-target.json \
  --previous-manifest previous-manifest.json \
  --previous-verification-report previous-release-verification.json \
  --rollback-evidence rollback-rehearsal.json \
  --artifacts-dir release-artifacts \
  --migration-report migration-compatibility.json \
  --backup-documentation docs/BACKUP_RESTORE.md \
  --docker-host staging-east \
  --connectivity-timeout 10 \
  --execute-live \
  --output release-artifacts/staging-readiness.json

python -m tools.release.cli check-readiness \
  --report release-artifacts/staging-readiness.json \
  --manifest release-artifacts/release-manifest.json \
  --report-sha256 <sha256>
```

Without `--execute-live`, the report is a local preflight. Every V28 check is
present as `NOT_RUN`, `required: false`, and `mode: local`. No GitHub, GHCR,
Docker, or staging host is contacted.

## Explicit staging target policy

The staging target must be supplied with `--target`. It is never inferred from
documentation, environment variables, DNS, Compose files, a previous report, or
a hostname convention.

V28 live mode additionally requires:

| Field | Requirement |
| --- | --- |
| `staging_statement` | Exactly `This target is an explicitly authorized staging environment and is not production.` |
| `allowed_hostnames` | Every API, web, and WebSocket hostname must appear in this list. Wildcards, URLs, and private hosts are rejected. |
| `allow_private_network` | Must be `true` before a private or loopback address is accepted. |
| `production_hostnames` | Declared production hostnames. A target hostname that overlaps this list is rejected. |

`--production-host` can add production hostnames supplied out of band. The
target and the external declaration are combined; any overlap fails the
`staging-target-live-policy` check. When that check fails, no network probe is
attempted. The live inspection also refuses a target whose environment is not
exactly `staging`, whose URLs are not HTTPS/WSS, or whose release binding does
not match the manifest.

## Check groups

| Group | Checks |
| --- | --- |
| GitHub | `github-tag-exists`, `github-tag-commit`, `github-release-exists`, `github-release-identity`, `github-release-assets`, `github-workflow-run` |
| Registry | `ghcr-api`, `ghcr-web`, `ghcr-api-gpu`, `ghcr-platform-metadata` |
| Attestation | `attestation-cli`, `attestation-api`, `attestation-web`, `attestation-api-gpu`, `attestation-sbom` |
| Artifacts | `sbom-evidence`, `scan-evidence` |
| Connectivity | `dns-resolution`, `tcp-connectivity`, `tls-certificate`, `https-live`, `https-ready`, `https-health`, `https-security-headers`, `wss-connectivity`, `service-identity` |
| Docker host | `docker-host-inspection`, `docker-host-compose`, `docker-host-containers`, `docker-host-gpu-runtime` |
| Rollback | `rollback-previous-digests`, `rollback-migration-evidence`, `rollback-backup-documentation` |
| Target | `staging-target-live-policy` |

`service-identity` and `docker-host-gpu-runtime` are optional in the general
live profile. `docker-host-gpu-runtime` becomes required when the target or the
operator requests GPU readiness.

Every check keeps the existing evidence states:

| State | Meaning |
| --- | --- |
| `PASS` | The check was performed and the prerequisite is verified. |
| `FAIL` | The check was performed and found a wrong or unsafe condition. |
| `NOT_RUN` | The check was not evaluated. |
| `UNAVAILABLE` | A tool, credential, service, or authorized target was absent. |
| `SIMULATED` | The result came from simulated data and never satisfies a required gate. |

## GitHub and GHCR

GitHub inspection uses read-only `GET` requests to the public API:

- `GET /repos/{repo}/git/ref/tags/{tag}` and the peeled tag object;
- `GET /repos/{repo}/releases/tags/{tag}`;
- `GET /repos/{repo}/actions/runs/{run_id}`.

A tag must resolve to the manifest commit. A release must be published, not a
draft or prerelease, must be tagged exactly like the manifest, must point at the
expected repository URL, and must include every manifest asset with a non-zero
size. The workflow run must match the manifest run id, commit, workflow path,
event, status, conclusion, and attempt.

Authentication uses only credentials already present in the authorized
environment. `GH_TOKEN` is preferred over `GITHUB_TOKEN`. The token is sent as
an `Authorization` header but is never written to checks, observations,
evidence, or logs. An anonymous or unauthorized response is `UNAVAILABLE`, not
`PASS`; a missing package cannot be distinguished from missing authorization,
so V28 does not guess.

GHCR inspection uses the existing Docker CLI and `docker buildx imagetools
inspect` to read each manifest digest. Every required image digest must match
the release manifest. Platform metadata is read with `--raw`; a missing
registry credential or an unreachable registry is reported honestly.

Attestations are verified with `gh attestation verify` against the OCI digest,
repository, signer workflow, source commit, source tag, and predicate type.
The SBOM attestation is additionally compared with the retained local SBOM.
A local bundle or SBOM alone is not proof of a GitHub attestation.

## Bounded connectivity

Connectivity probes use only the host/port pairs named by the explicit target
URLs. There is no port scan, no CIDR sweep, and no host discovery.

- The timeout is validated up front and must be between 1 and 60 seconds.
- DNS resolution is bounded and returns only the addresses needed for the
  target hostnames.
- TCP, TLS, HTTPS, and WSS probes use the same explicit timeout.
- TLS certificate validation and hostname verification are enabled. The
  certificate must not be expired or near expiry.
- `/live`, `/ready`, and `/health` must return the expected success shape.
- HTTPS security headers are checked against the existing baseline.
- The WebSocket probe accepts a reachable unauthorized close (for example
  `4401`) as reachability evidence; it does not use staging credentials.
- `service-identity` is optional and never substitutes for the required
  endpoint checks.

A policy failure stops all network probes before the first connection. A DNS,
TCP, TLS, HTTP, or WSS failure is reported as `FAIL` or `UNAVAILABLE` with a
bounded, sanitized detail.

## Docker host inspection

`--docker-host` names an **existing Docker context**. It is not a URL, an SSH
target, or an arbitrary hostname. The context name is validated before any
command runs. Names or endpoints that look like production (`prod`,
`production`, `prd`) are rejected.

Inspection runs only read-only commands through the named context:

```text
docker --context <name> version --format {{json .}}
docker --context <name> context inspect <name> --format {{json .}}
docker --context <name> compose version
docker --context <name> ps -a --filter label=com.docker.compose.project=<project> --format {{json .}}
docker --context <name> info --format {{json .}}
```

It does not build, pull, start, stop, restart, remove, tag, or exec anything.
Existing project containers that are restarting, dead, paused, or unhealthy
fail the container check. The GPU runtime check requires the `nvidia` runtime
only when GPU readiness is required.

## Rollback prerequisites

V28 validates rollback evidence but never executes a rollback:

- the previous manifest must have a distinct digest for every required image;
- the previous release must have a production verification report bound to its
  bytes;
- the rollback evidence must be an executed, verified rehearsal bound to the
  current and previous manifests;
- the migration compatibility report must be valid and bound to the exact
  manifest bytes;
- the backup documentation must be a UTF-8 text or Markdown document that
  covers PostgreSQL, Redis, and named volumes, and includes headings or command
  examples.

The migration report contract is the existing V25 contract; V28 does not invent
a second schema. The backup document is validated for content and never
executed. Secret-bearing files are not copied into the evidence directory.

## Report contract

The report keeps `schema_version: 1` and `profile: staging_readiness`. V28
reports add the optional marker:

```json
{
  "inspection_profile": "v28"
}
```

Legacy V26/V27 reports omit the marker and remain valid. V28 reports may add
three bindings, which are `null` in preflight and retained in live mode:

- `live_inspection` (`live-inspection.json`);
- `migration_report` (`migration-report`);
- `backup_documentation` (`backup-documentation`).

The live-inspection evidence contains the GitHub, GHCR, attestation, artifact,
connectivity, Docker, and rollback observations, the manifest hash, the target
summary, and an explicit no-mutation statement. It never contains credentials,
tokens, cookies, passwords, private keys, or secret environment values.

`check-readiness` revalidates the full V28 report:

- all V28 check names are present and their required flags match the profile;
- preflight V28 checks are local, optional, and `NOT_RUN`/`UNAVAILABLE`;
- live V28 checks are required (except the documented optional checks) and
  `PASS`;
- the live-inspection evidence is bound to the manifest and the target;
- the mutation statement says no mutation was performed;
- the connectivity, Docker, and rollback observation sections are present;
- the migration report and backup documentation are valid and retained;
- the report bytes match `--report-sha256` when supplied;
- `production_qualified` remains `false` and deployment remains unauthorized
  and unperformed.

A report cannot be reused for different manifest bytes, a different target, a
different release subject, or a different previous release.

## Opt-in live tests

The live tests are marked `live` and are deselected by default. They require
real, explicitly authorized infrastructure and skip with the exact missing
prerequisite:

```bash
pytest -m live backend/tests/live/test_v28_live_infrastructure.py -q
```

Required environment variables include `IVP_LIVE_MANIFEST`,
`IVP_LIVE_STAGING_TARGET`, `IVP_LIVE_ARTIFACTS_DIR`,
`IVP_LIVE_DOCKER_CONTEXT`, `IVP_LIVE_MIGRATION_REPORT`,
`IVP_LIVE_BACKUP_DOCUMENTATION`, `IVP_LIVE_PREVIOUS_MANIFEST`,
`IVP_LIVE_PREVIOUS_VERIFICATION`, and `IVP_LIVE_ROLLBACK_EVIDENCE`. The tests
also require the `docker` CLI, the `gh` CLI with attestation support, and
GitHub authentication already configured in the environment. The connectivity
timeout is bounded by `IVP_LIVE_CONNECTIVITY_TIMEOUT` (1 to 60 seconds).

A skipped live test is not evidence. A live test that runs fails unless the
required live checks are actually `PASS`. The tests assert that every Docker
command is read-only and that no deployment, release, registry, container,
database, volume, network, or migration mutation is claimed.

## Current live-evidence status

The V28 implementation environment has no authorized live evidence:

- no explicit staging target was supplied;
- `gh` is not installed and `GH_TOKEN`, `GITHUB_TOKEN`, `CR_PAT`, and
  `GHCR_TOKEN` are unset;
- the Docker daemon is unreachable locally and no authorized remote Docker
  context is configured;
- anonymous GHCR tag inspection returns HTTP 401, so a missing package cannot
  be distinguished from missing authorization;
- the repository currently has no release tag and no GitHub Release, so no
  release assets, attestations, SBOMs, or scans can be inspected;
- no previous release manifest, previous verification report, rollback
  evidence, migration report, backup documentation, or staging smoke
  credentials are available;
- no NVIDIA GPU or `nvidia-smi` is available.

The honest result is a non-`PASS` readiness report with explicit `UNAVAILABLE`
or `NOT_RUN` checks and blockers. No live GitHub, GHCR, Docker, staging, GPU,
release, publication, workflow, deployment, migration, rollback, or
infrastructure mutation was performed for V28.

## Relationship to V22-V27

- V22/V23 release verification and attestation contracts are unchanged.
- V24 qualification profiles, deployment preflight, rollback rehearsal, and GPU
  runtime evidence are unchanged.
- V25 staging target validation, staging qualification, mutation authorization,
  and the migration report contract are unchanged.
- V26/V27 readiness check names, evidence retention, schema compatibility, and
  deployment prohibition are unchanged.
- V28 adds an opt-in live profile and three optional bindings. It does not relax
  any existing gate, and a V28 readiness `PASS` does not satisfy V24 production
  qualification or authorize a deployment.
