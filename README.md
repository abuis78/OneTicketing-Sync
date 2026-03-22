# OneTicketing Sync — Splunk SOAR App

**Version:** 1.6.0 | **Author:** Andreas Buis | **Min SOAR:** 6.0.0 | **Python:** 3

---

## Overview

OneTicketing Sync is a Splunk SOAR app for **federated Parent-Child case management** across multiple Splunk SOAR 8.4 instances.

**Core idea:** The same app is installed on every SOAR instance. Each instance is configured as either a **Parent** (coordinator) or a **Child** (national/regional CERT). All sync actions are analyst-initiated via widgets — nothing runs automatically.

**Typical use cases:**
- Parent distributes an investigation task to one or more Child CERTs
- Child analyst sends findings, observables, and a reply note back to the Parent
- Parent sends updates (notes, new observables, severity changes) to an active Child case
- Child is unreachable (OT network) — requests queue locally and flush when connectivity is restored

---

## Architecture

```
PARENT SOAR (e.g. CERT-CTI)
  ├── App: OneTicketing Sync (role = parent)
  ├── Asset config: children_registry JSON  ← all child connections in one place
  ├── Playbook: oneticketing_parent_manager
  └── Widget: create_child_task.html        ← "+ Child Task" and "↑ Update" buttons

CHILD SOAR (e.g. DE, NO, ...)
  ├── App: OneTicketing Sync (role = child)
  ├── Asset config: server + ph_auth_token  ← points to Parent
  ├── Playbook: oneticketing_child_manager
  └── Widget: reply_to_parent.html          ← "↩ Reply to Parent" button + history panel
```

**Artifact flow:**

| Label | Direction | Created by | Triggers |
|-------|-----------|-----------|---------|
| `child_task_request` | Parent → Child | Parent widget | `oneticketing_child_manager` playbook on Child |
| `parent_case_reference` | (local) | `create_child_case` action | Widget detects child context |
| `parent_update` | Parent → Child | `update_child_case` action | `oneticketing_child_manager` playbook on Child |
| `child_reply` | Child → Parent | Child widget (reply_to_parent.html) | `oneticketing_child_manager` playbook on Child |
| `child_reply_received` | (local on Parent) | `reply_to_parent` action | Parent playbook (optional) |

---

## Prerequisites

**Python packages** (auto-installed by SOAR on import):

| Package | Purpose |
|---------|---------|
| `requests` | HTTP client for SOAR 8.4 REST API |
| `urllib3` | TLS/retry support |

No system binaries required.

---

## Installation

1. Build the TAR: `tar -czf one_ticketing_v1.6.0.tgz one_ticketing/` (run from parent directory)
2. In SOAR: **Apps → Install App → Upload TAR file**
3. After import: **Apps → OneTicketing Sync → Configure New Asset**
4. Repeat on **every** SOAR instance (Parent + all Children)

---

## Asset Configuration

### Parent instance

Create **one asset** with `instance_role = parent`:

| Field | Value | Notes |
|-------|-------|-------|
| `instance_role` | `parent` | Required |
| `server` | *(leave empty)* | Not needed when using `children_registry` |
| `ph_auth_token` | *(leave empty)* | Not needed when using `children_registry` |
| `children_registry` | JSON map ↓ | All child connections in one password field |
| `children_registry_ids` | `DE, NO, SE` | Plain-text — must match registry keys exactly |
| `phantom_token` | SOAR automation user token | Needed to read `targetChildId` from artifact CEF via local REST |
| `container_label` | `events` | Default label for child cases. Must exist in Admin → Event Settings → Labels |
| `default_workbook` | `IT Security Investigation` | Workbook template name. Leave empty for system default |
| `enable_offline_queue` | `true` | Queue requests when a child is unreachable |

**`children_registry` format** (enter as JSON in the password field):
```json
{
  "DE_OT": { "url": "https://de.soar.example.com", "token": "xxxx" },
  "NO_OT": { "url": "https://no.soar.example.com", "token": "yyyy" },
  "SE_OT": { "url": "https://se.soar.example.com", "token": "zzzz" }
}
```

> ⚠ `children_registry` is encrypted (password field). `children_registry_ids` is **not** encrypted — the widget reads it to populate the target child selector.

### Child instance

Create **one asset** per Child, pointing to the Parent:

| Field | Value | Notes |
|-------|-------|-------|
| `instance_role` | `child` | Required |
| `child_id` | `DE` | Must match the key in parent's `children_registry` |
| `server` | `https://parent.soar.example.com` | Parent SOAR URL |
| `ph_auth_token` | *(Parent automation user token)* | REST API token from Parent SOAR |
| `phantom_token` | *(local automation user token)* | Get from: Admin → User Management → Automation user → Copy auth token |
| `enable_offline_queue` | `true` | Recommended for OT environments |
| `verify_ssl` | `false` | Lab/POC only. Set `true` in production |

**Where to get `phantom_token`:**
1. In SOAR: **Admin → User Management**
2. Open the **Automation** user (or create one)
3. Copy the **Auth Token** value
4. Paste into the `phantom_token` field

**Recommended auth method by environment:**
- OT networks → `mtls` (no inbound connections required)
- IT networks → `api_token` (service account token from Splunk)

---

## Widget Activation

Two custom widgets appear in the Investigation page. Activate them on **both** Parent and Child instances:

1. Open any case Investigation page
2. Click **Manage Widgets** (gear icon, top-right)
3. Find **OneTicketing Sync** → toggle **On** for both widgets
4. Click **Save Layout**

| Widget | Visible on | Shows |
|--------|-----------|-------|
| **Create Child Task** (`create_child_task.html`) | Parent | "+ Child Task" button, dispatched children list, reply inbox |
| **Reply to Parent** (`reply_to_parent.html`) | Child | Communication history (initial task, parent updates, sent replies), "↩ Reply to Parent" button |

> The Reply to Parent widget auto-detects whether a case is a child case by looking for a `parent_case_reference` artifact. It only shows the button and history when that artifact is present.

---

## Playbook Setup

### `oneticketing_parent_manager` (on Parent)

**Purpose:** Handles child task creation, update dispatch, and reply processing on the Parent SOAR.

Typical flow:
1. Analyst clicks **+ Child Task** in widget → creates `child_task_request` artifact with `run_automation=true`
2. Playbook triggers → calls `create_child_case` action → case created on Child
3. When a reply arrives (`child_reply_received` artifact) → playbook notifies parent analyst

### `oneticketing_child_manager` (on Child)

**Purpose:** Handles incoming tasks from Parent, starts monitoring, triggers playbooks on new updates, and relays replies.

Typical flow:
1. `child_task_request` artifact arrives with `run_automation=true` → playbook starts
2. Playbook calls `start_case_monitor` → registers parent-child mapping, creates `parent_case_reference` artifact
3. When `parent_update` arrives → playbook runs again → notifies child analyst
4. Analyst uses **↩ Reply to Parent** widget → creates `child_reply` artifact with `run_automation=true`
5. Playbook triggers → calls `reply_to_parent` action → sends reply to Parent

**Required playbook filter (`filter_reply_to_parent`):**

The filter that selects `child_reply` artifacts must include **both** conditions:
```
artifact:*.label == "child_reply"
artifact:*.tags does not contain "synced-to-parent"   ← REQUIRED
```

Without the second condition, the playbook will re-process already-sent replies.

**Required `reply_to_parent` action parameter mapping:**

| Action parameter | Map from |
|-----------------|---------|
| `parent_case_id` | `artifact:*.cef.parentCaseId` |
| `container_id` | `artifact:*.container_id` |
| `note_content` | `artifact:*.cef.noteContent` |
| `note_title` | `artifact:*.cef.noteTitle` |
| `selected_artifact_ids` | `artifact:*.cef.selectedArtifactIds` |

> ⚠ `selectedArtifactIds` (camelCase in CEF) must be mapped to `selected_artifact_ids` (snake_case in action). This is a required manual step in the playbook editor.

---

## Test Connectivity

After saving an asset, click **Test Connectivity**. Expected success output:
```
Test Connectivity Passed.
Latency: 42 ms | Role: CHILD | Auth: ph-auth-token | Server: https://parent.soar.example.com
```

Common failures:

| Error | Fix |
|-------|-----|
| `Cannot reach https://...` | Check `server`, firewall rules, proxy config |
| `401 Unauthorized` | Wrong `ph_auth_token` — verify it's the **remote** SOAR token |
| `Certificate file not found` | Verify `cert_path` / `key_path` on the SOAR appliance filesystem |
| `mtls requires cert_path and key_path` | Set both fields in asset config |
| `children_registry is not valid JSON` | Validate JSON at jsonlint.com, check for trailing commas |
| `No entry for 'X' in children_registry` | Add child to registry and update `children_registry_ids` |

---

## Actions Reference

### `test connectivity`
Validates connectivity, auth, and instance role. No parameters.

---

### `create child case`
Creates a Child case on a remote Child instance and links it to a Parent case.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `parent_case_id` | Yes | Parent SOAR container ID |
| `case_name` | Yes | Title for the new child case |
| `description` | Yes | Investigation scope |
| `severity` | Yes | `low` / `medium` / `high` / `critical` |
| `target_child_id` | No | Registry key (e.g. `DE`). Read from artifact CEF if empty |
| `tlp` | No | TLP classification. Default: `TLP.AMBER` |
| `assigned_to` | No | Splunk username on child instance |
| `tags` | No | Comma-separated tags |
| `observables` | No | JSON array of observable objects |

---

### `update child case`
Pushes an update (note, severity, new observables) from Parent to an existing Child case. Creates a `parent_update` artifact on the child — stored in CEF as `cef.note` (not `cef.noteContent`).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `parent_case_id` | Yes | Parent container ID (used to locate the child case) |
| `target_child_id` | Yes* | Registry key. *Required when using `children_registry` |
| `comment` | No | Update text (stored as `cef.note` on child) |
| `severity` | No | New severity |
| `artifact_ids` | No | Comma-separated parent artifact IDs to copy to child |
| `new_observables` | No | JSON array of new observable objects |

---

### `reply to parent`
Sends a Child reply (note + selected observables) to the Parent case. Called by the child playbook when a `child_reply` artifact is detected.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `parent_case_id` | Yes | Map from `artifact:*.cef.parentCaseId` |
| `container_id` | Yes | Local child container ID |
| `note_content` | Yes | Map from `artifact:*.cef.noteContent` |
| `note_title` | No | Map from `artifact:*.cef.noteTitle` |
| `selected_artifact_ids` | No | Map from `artifact:*.cef.selectedArtifactIds` |

---

### `start case monitor`
Activates per-case monitoring for a child container. Creates a `monitor_heartbeat` artifact and a `parent_case_reference` artifact (which is how the Reply widget detects child context).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `container_id` | Yes | Local child container ID |
| `parent_case_id` | Yes | Parent container ID to monitor |

---

### `stop case monitor`
Deactivates monitoring for a child container.

---

### `update case status`
Updates status and/or severity on a remote case (bidirectional).

---

### `close child case`
Closes a Child case locally. Optionally posts a closure note to the Parent.

---

### `get children status`
Returns live status of all Child cases linked to a Parent case. Rendered as a custom widget.

---

### `queue sync request` / `flush sync queue`
IT-OT Red Button resilience. Queues requests locally when Parent is unreachable; flushes on reconnect.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Widget shows "No task history" | No `child_task_request` artifact in container | Check if `create_child_case` ran successfully; verify playbook mapped parameters correctly |
| "REPLIES: 0 received" on parent | Child playbook re-processes old `child_reply` artifact | Add `tags does not contain "synced-to-parent"` filter to `filter_reply_to_parent` in child playbook |
| Update from Parent shows "(no content)" | Update text is in `cef.note`, not `cef.noteContent` | Known difference — widget reads `cef.note` (✓ fixed in v1.5.22+) |
| `selectedArtifactIds` not arriving on Parent | CEF key not mapped to action parameter | Map `artifact:*.cef.selectedArtifactIds` → `selected_artifact_ids` in playbook |
| `400 artifact already exists` | Same observable submitted twice | SDI includes timestamp — if still occurring, check for duplicate playbook runs |
| `requests library not installed` | pip install failed | SSH to SOAR: `phenv pip3 install requests urllib3` |
| Widget not visible | Not activated | Manage Widgets → toggle OneTicketing On → Save Layout |
| Multiple app directories detected | Wrong TAR structure | Re-package: `tar -czf one_ticketing_v1.6.0.tgz one_ticketing/` from the parent directory |

---

## SSH Testing

```bash
# Create test input
cat > /tmp/test_connectivity.json << 'EOF'
{
  "identifier": "test_connectivity",
  "asset_id": "1",
  "parameters": [{}],
  "config": {
    "server": "https://parent.soar.example.com",
    "instance_role": "child",
    "child_id": "DE",
    "ph_auth_token": "your-token-here",
    "verify_ssl": false,
    "enable_offline_queue": true
  }
}
EOF

# Run connector directly
cd /opt/phantom/apps/one_ticketing_*/
phenv python3 one_ticketing_connector.py /tmp/test_connectivity.json
```

Expected: JSON with `"status": "success"` and latency info.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.6.0 | 2026-03-20 | Production release. All inline comments cleaned up and translated to English. Version labels removed from CSS/JS comments. |
| 1.5.22 | 2026-03-20 | Fix: `parent_update` text read from `cef.note` (not `cef.noteContent`) in View modal and table preview. |
| 1.5.21 | 2026-03-20 | Add: Communication history panel in `reply_to_parent.html` widget — shows initial task, parent updates, and sent replies with View modals. |
| 1.5.20 | 2026-03-19 | Fix: Widget artifact list fetched fresh on every modal open — stale list after new artifact creation no longer occurs. |
| 1.5.19 | 2026-03-19 | Add: Diagnostic warning row in reply table when all replies are filtered as "Start" protocol artifacts. |
| 1.5.18 | 2026-03-18 | Fix: Duplicate artifact error on re-submission — timestamp + index added to SDI. |
| 1.5.17 | 2026-03-17 | Add: Full Splunk CIM field set in "Add observable" dropdown (both widgets). |
| 1.5.10 | 2026-03-14 | Add: Toolbar "↑ Send Update" button on Parent widget. Artifact name back-fill for display. |
| 1.5.8 | 2026-03-13 | Add: 2-step "Send Update to Child" overlay on Parent widget. Full CIM field set. |
| 1.5.4 | 2026-03-12 | Fix: 1:1 parent:child guard per case. Child list scoped to current case only. |
| 1.5.3 | 2026-03-12 | Add: Persistent status sidebar on Parent widget. |
| 1.5.2 | 2026-03-11 | Fix: Double-observable bug — newObservables removed from `child_reply` CEF. |
| 1.4.8 | 2026-03-10 | Add: TLP read from artifact CEF. `targetChildId` always read from artifact. |
| 1.4.4 | 2026-03-09 | Add: TLP selector on Parent widget. `children_registry` multi-child routing. |
| 1.0.0 | 2026-03-01 | Initial release. 14 actions, mTLS + api_token + basic auth, offline queue. |
