# SentinelCore Operator Workflow

This guide walks an operator through the end-to-end workflow of onboarding a
scan target, configuring credentials, uploading source code, and launching
scans through the SentinelCore UI.

## Prerequisites

You have:

- A SentinelCore account in the `platform_admin`, `security_admin`, or
  `appsec_analyst` role (auditors have read-only access and cannot launch
  scans).
- Access to the SentinelCore web UI.
- A project already created in your organization. Projects are created from
  the Settings page or via the `POST /api/v1/projects` API.

## Target onboarding (required for DAST)

Dynamic scans run against a **target** — a web app, REST API, or GraphQL
endpoint you own and are authorized to test.

1. Navigate to **Targets** in the sidebar.
2. Pick the project from the dropdown at the top of the page.
3. Click **New Target**.
4. Fill in:
   - **Target Type** — `Web Application`, `REST API`, or `GraphQL API`.
   - **Base URL** — the full URL including scheme (`https://...`). Must be an
     absolute URL; http(s) only.
   - **Label** (optional) — a human-friendly name for the UI. Defaults to the
     host.
   - **Environment** (optional) — free text, e.g. `staging`.
   - **Allowed Domains** (optional, comma-separated) — defaults to the host of
     Base URL. Scan traffic is blocked from reaching any domain not listed
     here.
   - **Max requests/sec** (default 10) — hard rate cap that scans will honor.
   - **Notes** (optional).
   - **Auth Profile** (optional) — attach a DAST auth profile. See the next
     section.
5. Click **Create Target**.

Targets can be edited or deleted from the row actions. Targets referenced by
existing scans cannot be deleted (409 Conflict).

## Auth profile management (DAST credentials)

Authenticated DAST scans need credentials. SentinelCore stores credentials
AES-256-GCM-encrypted at rest and never returns them from the API once they
are saved — the UI shows `•••••••• (stored)` and offers an explicit **Rotate**
action if you want to replace a secret.

Supported types:

- **Bearer Token** — the scanner sends `Authorization: <prefix> <token>`.
  Prefix defaults to `Bearer`.
- **API Key** — the scanner sends the key in a configurable header (default
  `X-API-Key`) or a query parameter.
- **Basic Auth** — username + password.

To create one:

1. Navigate to **Auth Profiles** in the sidebar.
2. Pick the project.
3. Click **New Profile**.
4. Fill in the name, auth type, and the type-specific secret fields.
5. Optionally supply a **Login / Token Endpoint URL**. This URL is
   SSRF-checked — requests to RFC1918, loopback, or cloud-metadata IPs
   (`169.254.169.254`) are rejected at create time.
6. Click **Create Profile**.

To use the profile on a scan: open the target you want to attach it to, set
the **Auth Profile** field to the profile, and save. Future DAST scans against
that target will dispatch with the profile reference, and the scan audit log
will record an `authprofile.use` event when the scan is launched.

## Source artifact intake (required for SAST)

SAST scans run against a source bundle — a ZIP archive of your codebase.

To upload one:

1. Navigate to **Source Artifacts** in the sidebar.
2. Pick the project.
3. Click **Upload**.
4. Select a `.zip` file (256 MiB cap, 1 GiB uncompressed, 200k entries max).
5. Optionally edit the display name and description.
6. Click **Upload**.

The archive is validated before it's committed to storage:

- Magic byte check (rejects files that aren't actually ZIPs).
- Every entry is inspected for absolute paths, parent traversal (`../`),
  symlinks, and oversized entries.
- Zip bombs are rejected by a total-uncompressed-size cap.

Artifacts that fail validation are rejected with a `400 BAD_REQUEST` and
never touch disk beyond the temp file (which is cleaned up).

## Launching a DAST scan

1. Navigate to **Scans**.
2. Click **New Scan**.
3. Select **Project**.
4. Set **Scan Type** to `DAST` (or `SAST + DAST (full)` to run both).
5. Select **Target**. Only targets in the current project are listed.
6. The **Auth Profile** panel shows the profile currently attached to the
   target, if any. If it says "No auth profile attached…", the scan will run
   unauthenticated. Attach one from the Targets page if needed.
7. Select **Scan Mode** — passive / standard / aggressive.
8. Optional label / environment.
9. Click **Create Scan**.

The scan appears in the list immediately in `pending` status. A worker
consumes it from the `scan.dast.dispatch` NATS subject, and the UI polls for
status updates every 5 seconds while the scan is running.

## Launching a SAST scan

1. Navigate to **Scans**.
2. Click **New Scan**.
3. Select **Project**.
4. Set **Scan Type** to `SAST`.
5. Select **Source Artifact** — the ZIP you uploaded in the previous section.
   The selector is empty if no artifacts are uploaded for the project.
6. (Advanced) You can alternatively leave Source Artifact as None and pick a
   **Target** with a `git` URL, which triggers the legacy git-clone SAST path.
7. Click **Create Scan**.

The scan appears in the list immediately in `pending` status. The SAST worker
consumes it from the `scan.sast.dispatch` NATS subject; if no worker is
running, the scan detail page shows a **Waiting for scan worker** banner
after about 30 seconds so operators are never misled about state.

## Scan detail page

Every scan has a detail page reachable from the Scans list. It shows:

- **Status** badge and scan type.
- **Context** — project, target (label + base URL), source artifact (if any),
  and auth profile (metadata only — name and type; credentials never appear).
- **Progress** bar with phase label.
- **Timing** — created, started, finished, duration.
- **Error** block if the scan failed.
- **Findings** link that filters the Findings page by `scan_id`.

## Current limitations

- **SAST worker not deployed in the current compose stack.** SAST scans are
  correctly dispatched to NATS and the intake pipeline is fully verified, but
  until a `sentinelcore_sast_worker` service is added to the compose file the
  scans will remain in `pending`. The UI shows an honest "Waiting for scan
  worker" banner rather than faking progress.
- **OAuth2 and form-login auth types** are schema-only. The Auth Profiles UI
  only offers Bearer, API Key, and Basic Auth.
- **GitHub/GitLab native integrations, CI/CD webhooks, and scheduled scans**
  are out of scope for the current pilot. All scan creation is either via
  the UI (`manual` trigger) or direct API (`api` trigger).

## Common operator errors

| Error | Fix |
|---|---|
| `target_id is required for dast scans` | Select a target before submitting. |
| `sast scans require either target_id or source_artifact_id` | Upload an artifact or pick a target. |
| `target does not belong to this project` | You're trying to reuse a target from a different project. Create one in the current project. |
| `endpoint_url resolves to a blocked IP range` | The auth profile's login URL resolves to a private or metadata IP. Use a public hostname. |
| `archive: unsafe zip: path traversal…` | The ZIP contains entries like `../../file`. Re-pack your source without traversal paths. |
| `scans are blocked by an active emergency stop` | An admin activated an emergency stop on the project or org. Lift it from the Governance API or wait for it to be lifted. |
