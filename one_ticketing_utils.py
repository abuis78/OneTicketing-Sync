# -*- coding: utf-8 -*-
# Copyright 2026 Andreas Buis
#
# one_ticketing_utils.py
# Helper functions: HTTP client, sync logic, queue management, observable tagging.

import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote as _url_unquote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Constants ────────────────────────────────────────────────────────────────

# Note state prefixes — three-state model: pending → in-flight → done
NOTE_SYNC_PREFIX    = "[SYNC]"       # analyst marks note for sync
NOTE_SYNCING_PREFIX = "[SYNCING]"    # app claimed it — no second run will touch it
NOTE_SYNCED_PREFIX  = "[SYNCED ✓]"  # successfully sent to parent

# Backwards-compat alias (used in earlier code)
SYNC_PREFIX         = NOTE_SYNC_PREFIX
SYNCED_PREFIX       = NOTE_SYNCED_PREFIX

# Observable / artifact tag states
TAG_SYNC            = "sync-to-parent"
TAG_SYNCING         = "syncing-to-parent"
TAG_SYNCED          = "synced-to-parent"

# Task note pattern written by request_child_investigation
TASK_NOTE_PREFIX    = "[TASK:"        # e.g. "[TASK:CERT_NO_OT]"
TASK_ACCEPTED_PREFIX = "[TASK_ACCEPTED:"  # e.g. "[TASK_ACCEPTED:CERT_NO_OT]"
CASE_CLOSED_PREFIX  = "[CASE_CLOSED]"

QUEUE_FILE_NAME    = "one_ticketing_queue.json"

# SOAR internal REST base (local loopback)
SOAR_LOCAL_BASE    = "https://127.0.0.1"

# ─── Splunk SOAR REST API Paths ───────────────────────────────────────────────
# All inter-instance communication (Parent ↔ Child) uses the native SOAR
# REST API.  These are the verified endpoint paths for Splunk SOAR on-premises.
# Reference: Splunk SOAR REST API Reference (on-premises) — /rest/ endpoints
#
# Containers  (/rest/container)
#   GET  /rest/container              → list containers (with _filter_* params)
#   POST /rest/container              → create container
#   GET  /rest/container/{id}         → get single container
#   POST /rest/container/{id}         → update container (SOAR uses POST, not PATCH)
#   DELETE /rest/container/{id}       → delete container
#
# Notes  (/rest/note)
#   GET  /rest/note                   → list notes (_filter_container_id=N)
#   POST /rest/note                   → create note  (body: container_id, title, content)
#   POST /rest/note/{id}              → update note  (body: content)
#
# Artifacts / Observables  (/rest/artifact)
#   GET  /rest/artifact               → list artifacts (_filter_container_id=N)
#   POST /rest/artifact               → create artifact (body: container_id, cef, …)
#   POST /rest/artifact/{id}          → update artifact (SOAR uses POST, not PATCH)
#
# Reference: https://help.splunk.com/en/splunk-soar/soar-on-premises/rest-api-reference/8.4.0/notes-endpoints/rest-note

SOAR_CONTAINERS_PATH  = "/rest/container"
SOAR_CONTAINER_PATH   = "/rest/container/{container_id}"

SOAR_NOTES_PATH       = "/rest/note"
SOAR_NOTE_PATH        = "/rest/note/{note_id}"

SOAR_ARTIFACTS_PATH   = "/rest/artifact"
SOAR_ARTIFACT_PATH    = "/rest/artifact/{artifact_id}"

# Health-check endpoint — accessible to any authenticated Automation-role user.
# /rest/system_info requires admin privileges and returns 401 for Automation users.
ES_HEALTH_PATH        = "/rest/container?page_size=1"


# ─── HTTP Client ──────────────────────────────────────────────────────────────

class OneTicketingClient:
    """
    HTTP client for Splunk SOAR REST API communication between federated
    SOAR instances (Parent ↔ Child).

    Authentication uses the standard Splunk SOAR automation-user token
    passed as the 'ph-auth-token' HTTP header — the same mechanism used
    by all native SOAR REST API calls.

    Configuration keys (from asset config):
        server         – Base URL of the REMOTE SOAR instance
                         (e.g. https://parent.soar.example.com)
        ph_auth_token  – REST API authorization token of the automation
                         user on that remote SOAR instance.
    """

    def __init__(self, config: dict):
        if not HAS_REQUESTS:
            raise ImportError(
                "requests library is not installed. "
                "Run: phenv pip3 install requests"
            )

        # Accept both 'server' (new) and 'base_url' (legacy) so that
        # distribute_to_children / get_children_status child-client builds
        # still work during transition.
        self.base_url = (
            config.get("server") or config.get("base_url", "")
        ).rstrip("/")

        # SOAR password config fields may be URL-encoded by the UI form
        # submission (e.g. '+' → '%2B', '/' → '%2F', '=' → '%3D').
        # _url_unquote decodes %XX sequences without touching raw '+' chars
        # (unlike unquote_plus which would incorrectly convert '+' → space).
        raw_token          = config.get("ph_auth_token", "")
        self.ph_auth_token = _url_unquote(raw_token).strip()

        self.instance_role = config.get("instance_role", "child").lower()
        self.child_id      = config.get("child_id", "UNKNOWN")

        # Expose sanitised token length for debug output in test_connectivity
        self.ph_auth_token_len = len(self.ph_auth_token)

        if not self.base_url:
            raise ValueError(
                "Asset configuration is missing the 'server' field. "
                "Set it to the base URL of the remote SOAR instance "
                "(e.g. https://parent.soar.example.com)."
            )
        if not self.ph_auth_token:
            raise ValueError(
                "Asset configuration is missing the 'ph_auth_token' field. "
                "Find the token at Administration → Users → Automation Users "
                "→ <user> → REST API Authorization Token."
            )

        self._session = self._build_session()

    def _build_session(self) -> "requests.Session":
        session = requests.Session()

        # ── Authentication: ph-auth-token (SOAR automation user) ─────────────
        # This is the only auth mechanism supported by the SOAR REST API.
        # See: Splunk SOAR docs › Manage Automation Users
        session.headers.update({
            "ph-auth-token": self.ph_auth_token,
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        })

        # ── Retry Strategy ────────────────────────────────────────────────────
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PATCH", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://",  adapter)

        return session

    def get(self, path: str, params: dict = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = self._session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, data: dict) -> dict:
        url = f"{self.base_url}{path}"
        resp = self._session.post(url, json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def patch(self, path: str, data: dict) -> dict:
        url = f"{self.base_url}{path}"
        resp = self._session.patch(url, json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def delete(self, path: str) -> bool:
        url = f"{self.base_url}{path}"
        resp = self._session.delete(url, timeout=30)
        resp.raise_for_status()
        return True

    def health_check(self) -> tuple:
        """
        Returns (reachable: bool, latency_ms: float, detail: str).

        Uses /rest/container?page_size=1 — accessible to any authenticated
        Automation-role user.  Distinguishes auth failures (401/403) from
        network errors and returns the raw SOAR error body for diagnostics.

        Implementation notes:
        - Uses a fresh requests.get() (NOT the session) to avoid any
          session-level adapter interference.
        - SSL certificate verification is disabled (verify=False) because
          SOAR-to-SOAR calls between internal instances frequently use
          self-signed or internally-signed certificates.  The token itself
          provides the authentication security guarantee.
        - The raw response body is included in auth-failure messages so that
          the exact SOAR error reason is visible in the action output.
        """
        import requests as _requests  # local import — already guaranteed available

        try:
            start   = time.monotonic()
            url     = f"{self.base_url}{ES_HEALTH_PATH}"
            headers = {
                "ph-auth-token": self.ph_auth_token,
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            }
            resp    = _requests.get(
                url,
                headers=headers,
                timeout=30,
                verify=False,          # trust the token, not the cert chain
                allow_redirects=True,
            )
            latency = round((time.monotonic() - start) * 1000, 1)

            # Capture response body for diagnostics (truncated to 500 chars)
            try:
                body_text = resp.text[:500]
            except Exception:
                body_text = "(unreadable)"

            if resp.status_code == 401:
                return False, latency, (
                    f"Authentication failed (401 Unauthorized). "
                    f"Server response: {body_text!r} | "
                    f"Token sent: length={self.ph_auth_token_len}, "
                    f"hint={self.ph_auth_token[:4]}...{self.ph_auth_token[-4:]} | "
                    f"URL: {url}"
                )

            if resp.status_code == 403:
                return False, latency, (
                    f"Access denied (403 Forbidden). "
                    f"Server response: {body_text!r} | "
                    "The token is valid but the user lacks 'Automation' role."
                )

            resp.raise_for_status()

            # Parse response for container count confirmation
            try:
                body = resp.json()
                container_count = body.get("count", "?")
                detail = f"OK — remote SOAR reports {container_count} container(s)."
            except Exception:
                detail = "OK"

            return True, latency, detail

        except Exception as exc:
            err = str(exc)
            if "timed out" in err.lower() or "timeout" in err.lower():
                return False, -1, (
                    f"Connection timed out reaching {self.base_url}. "
                    "Check network/firewall rules between the two SOAR instances."
                )
            if "connection" in err.lower() or "refused" in err.lower():
                return False, -1, (
                    f"Cannot connect to {self.base_url}. "
                    "Verify the 'server' URL and that the remote SOAR is reachable."
                )
            return False, -1, err


# ─── Case / Container API Helpers ────────────────────────────────────────────
# All helpers below use the verified Splunk SOAR REST API paths.
# SOAR uses POST for both create AND update operations — there is no PATCH/PUT.
# Collection responses have the shape: {"count": N, "data": [...], "num_pages": N}
# Single-create responses have the shape: {"id": N, "success": true}

def get_case(client: OneTicketingClient, container_id: str) -> dict:
    """GET /rest/container/{id} — fetch a single SOAR container (case)."""
    path = SOAR_CONTAINER_PATH.format(container_id=container_id)
    return client.get(path)


def create_case(client: OneTicketingClient, payload: dict) -> dict:
    """POST /rest/container — create a new SOAR container (case).
    Returns {"id": <new_id>, "success": true, "message": "..."}
    """
    return client.post(SOAR_CONTAINERS_PATH, payload)


def update_case(client: OneTicketingClient, container_id: str,
                payload: dict) -> dict:
    """POST /rest/container/{id} — update an existing SOAR container.
    SOAR REST API uses POST (not PATCH/PUT) for updates.
    """
    path = SOAR_CONTAINER_PATH.format(container_id=container_id)
    return client.post(path, payload)


def get_notes(client: OneTicketingClient, container_id: str,
              since_ts: str = None) -> list:
    """GET /rest/note — list notes for a container.
    Filters by container_id using SOAR's _filter_* query param syntax.
    Optional since_ts filters to notes created after that ISO timestamp.
    Returns the 'data' list from the response.
    """
    params = {
        "_filter_container_id": int(container_id),
        "page_size":            200,
        "sort":                 "create_time",
        "order":                "asc",
    }
    if since_ts:
        params["_filter_create_time__gt"] = f"'{since_ts}'"
    result = client.get(SOAR_NOTES_PATH, params=params)
    return result.get("data", [])


def post_note(client: OneTicketingClient, container_id: str,
              content: str, title: str = "") -> dict:
    """POST /rest/note — create a note on a SOAR container.
    Required body fields: container_id (int), content (str).
    Returns {"id": <note_id>, "success": true}
    """
    payload: dict = {
        "container_id": int(container_id),
        "content":      content,
        "note_type":    "general",
    }
    if title:
        payload["title"] = title
    return client.post(SOAR_NOTES_PATH, payload)


def get_observables(client: OneTicketingClient, container_id: str,
                    since_ts: str = None) -> list:
    """GET /rest/artifact — list artifacts (observables/indicators) for a container.
    In SOAR, observables are represented as artifacts with CEF fields.
    Returns the 'data' list from the response.
    """
    params = {
        "_filter_container_id": int(container_id),   # consistent with get_notes
        "page_size":            200,
    }
    if since_ts:
        params["_filter_create_time__gt"] = f"'{since_ts}'"
    result = client.get(SOAR_ARTIFACTS_PATH, params=params)
    return result.get("data", [])


def update_observable_tags(client: OneTicketingClient, container_id: str,
                            artifact_id: str, tags: list) -> dict:
    """POST /rest/artifact/{id} — update tags on a SOAR artifact.
    SOAR REST API uses POST (not PATCH/PUT) for updates.
    Note: container_id is accepted for API symmetry but not sent (artifact
    already knows its container).
    """
    path = SOAR_ARTIFACT_PATH.format(artifact_id=artifact_id)
    return client.post(path, {"tags": tags})


# ─── Sync Helpers ─────────────────────────────────────────────────────────────

def now_iso() -> str:
    """Current time as UTC ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def make_sync_note(child_id: str, content: str) -> str:
    """
    Wraps content in the standard sync note format.
    Example: '[CERT_NO_OT @ 2026-03-13T12:00:00+00:00] Finding: ...'
    """
    ts = now_iso()
    return f"[{child_id} @ {ts}]\n{content}"


def is_sync_note(note_content: str) -> bool:
    """Returns True if note starts with [SYNC] prefix."""
    return note_content.strip().upper().startswith(SYNC_PREFIX.upper())


def is_already_synced(note_content: str) -> bool:
    """Returns True if note has already been synced ([SYNCED] prefix)."""
    return note_content.strip().upper().startswith(SYNCED_PREFIX.upper())


def strip_sync_prefix(content: str) -> str:
    """Removes [SYNC] or [SYNCED] prefix from note content."""
    stripped = content.strip()
    for prefix in (SYNC_PREFIX, SYNCED_PREFIX):
        pattern = re.compile(re.escape(prefix), re.IGNORECASE)
        stripped = pattern.sub("", stripped, count=1).strip()
    return stripped


def mark_as_synced(content: str) -> str:
    """Replaces [SYNC] prefix with [SYNCED] in note content."""
    stripped = strip_sync_prefix(content)
    return f"{SYNCED_PREFIX} {stripped}"


def build_child_case_payload(parent_case_id: str, case_name: str,
                              description: str, severity: str,
                              child_id: str, assigned_to: str = None,
                              tags: list = None, due_date: str = None,
                              label: str = "events",
                              artifact_id: str = None) -> dict:
    """Constructs the POST /rest/container payload for creating a Child container.

    SOAR REST API required fields: name, label.
    Parent tracking metadata is encoded in description and tags because
    SOAR custom_fields require pre-configuration in each target instance.

    SOAR container severity values: "low", "medium", "high"
    SOAR container status values:   "new", "open", "closed"
    SOAR container sensitivity:     "white", "green", "amber", "red" (TLP)
    """
    ts = now_iso()
    # Encode lineage in description — survives without custom field setup
    desc = (
        f"[ParentCase:{parent_case_id}] [Origin:{child_id}] [At:{ts[:10]}]\n\n"
        f"{description}"
    )
    # Tags carry structured metadata queryable via SOAR filter API
    combined_tags = list(tags or []) + [
        f"parent_case:{parent_case_id}",
        f"origin:{child_id}",
        "one_ticketing",
    ]
    # Derive SOAR sensitivity from TLP tag (v1.4.8: was hardcoded "amber")
    _tlp_sens_map = {
        "TLP.WHITE": "white", "TLP.GREEN": "green",
        "TLP.AMBER": "amber", "TLP.RED":   "red",
    }
    sensitivity = "amber"   # default if no TLP tag found
    for _t in combined_tags:
        _t_norm = str(_t).upper().strip()
        if _t_norm in _tlp_sens_map:
            sensitivity = _tlp_sens_map[_t_norm]
            break

    payload = {
        "name":                   case_name,
        "label":                  label or "events",   # must exist in target SOAR
        "description":            desc,
        "severity":               severity.lower(),
        "sensitivity":            sensitivity,
        "status":                 "new",
        "tags":                   combined_tags,
        # SDI enforces max 1 child case per parent per location.
        # Remove date and artifact_id — uniqueness is child_id + parent_case_id.
        "source_data_identifier": f"ot_{parent_case_id}_{child_id}",
    }
    if assigned_to:
        payload["owner"] = assigned_to
    # Note: SOAR containers do not have a native due_date field.
    # If due_date is provided, encode it in description.
    if due_date:
        payload["description"] += f"\n\nDue: {due_date}"
    return payload


def build_status_payload(new_status: str, new_severity: str = None) -> dict:
    """Builds the POST /rest/container/{id} body for status/severity updates.

    SOAR container status values: "new", "open", "closed"
    SOAR container severity values: "low", "medium", "high"
    """
    payload = {"status": new_status.lower()}
    if new_severity:
        payload["severity"] = new_severity.lower()
    return payload


# ─── Queue Management ─────────────────────────────────────────────────────────

class SyncQueue:
    """
    File-based persistent queue for IT-OT Red Button resilience.
    Queue is stored as a JSON array in the SOAR app state directory.
    Thread-safety: single-writer (SOAR playbooks are sequential per asset).
    """

    def __init__(self, state_dir: str):
        """
        Args:
            state_dir: Path to the SOAR app state directory (from connector.get_state_file()).
        """
        self._path = os.path.join(state_dir, QUEUE_FILE_NAME)
        self._queue = self._load()

    def _load(self) -> list:
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save(self):
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._queue, f, indent=2)
        except OSError as exc:
            raise RuntimeError(f"Failed to persist sync queue: {exc}") from exc

    def enqueue(self, operation_type: str, parent_case_id: str,
                container_id: int, payload: dict,
                priority: str = "normal") -> str:
        """
        Adds a new item to the queue. Returns the generated queue_id.
        """
        queue_id = str(uuid.uuid4())
        item = {
            "queue_id":       queue_id,
            "operation_type": operation_type,
            "parent_case_id": parent_case_id,
            "container_id":   container_id,
            "payload":        payload,
            "priority":       priority,
            "queued_at":      now_iso(),
        }
        if priority == "high":
            # High-priority items go before normal items
            insert_pos = 0
            for i, existing in enumerate(self._queue):
                if existing.get("priority") == "high":
                    insert_pos = i + 1
            self._queue.insert(insert_pos, item)
        else:
            self._queue.append(item)
        self._save()
        return queue_id

    def dequeue_batch(self, max_items: int = 50) -> list:
        """
        Removes and returns up to max_items items from the front of the queue.
        """
        batch = self._queue[:max_items]
        self._queue = self._queue[max_items:]
        self._save()
        return batch

    def requeue_failed(self, items: list):
        """Re-inserts failed items at the front for next flush attempt."""
        self._queue = items + self._queue
        self._save()

    @property
    def depth(self) -> int:
        return len(self._queue)

    def is_empty(self) -> bool:
        return len(self._queue) == 0


# ─── Observable Tag Logic ─────────────────────────────────────────────────────

def compute_new_tags(current_tags: list, tag_action: str) -> tuple:
    """
    Returns (new_tags: list, previous_tag: str, applied_tag: str).

    tag_action options:
      'mark_for_sync'  → replaces any existing sync tags with TAG_SYNC
      'mark_synced'    → replaces TAG_SYNC with TAG_SYNCED
      'reset'          → removes all sync tags
    """
    sync_tags      = {TAG_SYNC, TAG_SYNCED}
    non_sync_tags  = [t for t in current_tags if t not in sync_tags]
    previous_tag   = next((t for t in current_tags if t in sync_tags), "")

    if tag_action == "mark_for_sync":
        new_tags    = non_sync_tags + [TAG_SYNC]
        applied_tag = TAG_SYNC
    elif tag_action == "mark_synced":
        new_tags    = non_sync_tags + [TAG_SYNCED]
        applied_tag = TAG_SYNCED
    elif tag_action == "reset":
        new_tags    = non_sync_tags
        applied_tag = ""
    else:
        raise ValueError(
            f"Unknown tag_action '{tag_action}'. "
            "Use: mark_for_sync, mark_synced, or reset"
        )

    return new_tags, previous_tag, applied_tag


# ─── Children Registry ────────────────────────────────────────────────────────

def parse_children_registry(state: dict) -> dict:
    """
    Returns the children registry from app state.
    Structure: { child_id: { base_url, last_sync, last_known_status, ... } }
    """
    return state.get("children_registry", {})


def register_child_sync(state: dict, child_id: str, child_case_id: str,
                         parent_case_id: str) -> dict:
    """
    Records a successful Child-to-Parent sync in the app state registry.
    """
    registry = parse_children_registry(state)
    if child_id not in registry:
        registry[child_id] = {}
    registry[child_id]["last_sync"]         = now_iso()
    registry[child_id]["last_child_case_id"] = child_case_id
    registry[child_id]["last_parent_case_id"]= parent_case_id
    state["children_registry"] = registry
    return state


def update_child_status_in_registry(state: dict, child_id: str,
                                     status: str, severity: str = None) -> dict:
    registry = parse_children_registry(state)
    if child_id not in registry:
        registry[child_id] = {}
    registry[child_id]["last_known_status"]   = status
    registry[child_id]["last_known_severity"] = severity
    registry[child_id]["status_updated_at"]   = now_iso()
    state["children_registry"] = registry
    return state


# ─── Sync Trigger Container Builder ──────────────────────────────────────────

SYNC_TRIGGER_LABEL = "sync_trigger"


def build_sync_trigger_container(child_id: str, parent_case_id: str,
                                  local_container_id: int,
                                  sync_direction: str = "both",
                                  label: str = None) -> dict:
    """
    Builds a SOAR container dict for a Sync Trigger event.
    Saved via BaseConnector.save_container() in on_poll and trigger_sync.

    Fields:
        child_id:           Identifier of the originating Child instance.
        parent_case_id:     Parent ES case ID to sync with.
        local_container_id: Local SOAR container linked to this sync cycle.
        sync_direction:     'both', 'pull_only', or 'push_only'.
        label:              Container label (default: SYNC_TRIGGER_LABEL).
    """
    ts = now_iso()
    # Unique source_data_identifier prevents duplicate containers on re-poll
    sdi = f"sync_trigger_{child_id}_{parent_case_id}_{ts[:16]}"  # minute-granular
    effective_label = label if label else SYNC_TRIGGER_LABEL

    return {
        "name":                  f"Sync Trigger | {child_id} ↔ {parent_case_id}",
        "description":           (
            f"Automated sync trigger created by OneTicketing on_poll.\n"
            f"Child: {child_id} | Parent Case: {parent_case_id} | "
            f"Direction: {sync_direction}"
        ),
        "label":                 effective_label,
        "source_data_identifier": sdi,
        "status":                "new",
        "severity":              "low",
        "tags":                  ["one_ticketing", "auto_sync"],
        "custom_fields": {
            "child_id":           child_id,
            "parent_case_id":     parent_case_id,
            "local_container_id": local_container_id,
            "sync_direction":     sync_direction,
            "triggered_at":       ts,
        },
    }


def build_sync_trigger_artifact(container_id: int, child_id: str,
                                 parent_case_id: str,
                                 local_container_id: int,
                                 sync_direction: str = "both",
                                 label: str = None) -> dict:
    """
    Builds the CEF artifact attached to a Sync Trigger container.
    The playbook reads these CEF fields to know what to sync.
    """
    effective_label = label if label else SYNC_TRIGGER_LABEL
    return {
        "container_id":          container_id,
        "name":                  "Sync Parameters",
        "label":                 effective_label,
        "source_data_identifier": f"sync_artifact_{child_id}_{parent_case_id}",
        "cef": {
            "child_id":           child_id,
            "parent_case_id":     parent_case_id,
            "local_container_id": local_container_id,
            "sync_direction":     sync_direction,
        },
        "cef_types": {
            "parent_case_id": ["splunk case id"],
            "child_id":       ["splunk cert id"],
        },
        "run_automation": True,   # triggers attached playbooks immediately
    }


# ─── Note State Helpers ───────────────────────────────────────────────────────

def get_note_sync_state(content: str) -> str:
    """
    Returns 'pending', 'syncing', 'synced', or 'none' based on note prefix.
    """
    c = content.strip()
    if c.upper().startswith(NOTE_SYNCING_PREFIX.upper()):
        return "syncing"
    if c.upper().startswith(NOTE_SYNCED_PREFIX.upper()):
        return "synced"
    if c.upper().startswith(NOTE_SYNC_PREFIX.upper()):
        return "pending"
    return "none"


def transition_note_to_syncing(content: str) -> str:
    """[SYNC] text → [SYNCING] text"""
    bare = strip_sync_prefix(content)
    return f"{NOTE_SYNCING_PREFIX} {bare}"


def transition_note_to_synced(content: str) -> str:
    """[SYNCING] text  (or any state) → [SYNCED ✓] text"""
    bare = strip_sync_prefix(content)
    return f"{NOTE_SYNCED_PREFIX} {bare}"


def transition_note_to_pending(content: str) -> str:
    """Roll back to [SYNC] on failure."""
    bare = strip_sync_prefix(content)
    return f"{NOTE_SYNC_PREFIX} {bare}"


# ─── Idempotency Key ──────────────────────────────────────────────────────────

def get_idempotency_key(child_id: str, item_id: str,
                         container_id: int) -> str:
    """
    Stable unique key per syncable item.
    Used as source_data_identifier on the parent note to prevent true duplicates.
    Format: 'ot_{child_id}_{container_id}_{item_id}'
    """
    return f"ot_{child_id}_{container_id}_{item_id}"


# ─── Sync Registry ────────────────────────────────────────────────────────────
#
# Stored in App State under key "sync_registry":
# {
#   "notes":      { "<note_id>":      { "status", "synced_at", "parent_case_id" } },
#   "observables":{ "<artifact_id>":  { "status", "synced_at" } },
#   "evidence":   { "<evidence_id>":  { "status", "synced_at", "container_id" } }
# }
#
# status values: "pending" | "syncing" | "synced"

REGISTRY_TYPES = ("notes", "observables", "evidence")


def get_sync_registry(state: dict) -> dict:
    return state.setdefault("sync_registry", {
        "notes": {}, "observables": {}, "evidence": {}
    })


def is_item_registered(state: dict, item_type: str, item_id: str) -> bool:
    """True if item exists in registry with status 'syncing' or 'synced'."""
    reg = get_sync_registry(state)
    entry = reg.get(item_type, {}).get(str(item_id))
    if not entry:
        return False
    return entry.get("status") in ("syncing", "synced")


def register_sync_item(state: dict, item_type: str, item_id: str,
                        status: str, parent_case_id: str,
                        container_id: int = 0) -> dict:
    """
    Adds or updates a registry entry.
    Call with status='syncing' BEFORE making the remote call.
    Call with status='synced'  AFTER successful remote call.
    """
    reg = get_sync_registry(state)
    bucket = reg.setdefault(item_type, {})
    bucket[str(item_id)] = {
        "status":         status,
        "parent_case_id": parent_case_id,
        "container_id":   container_id,
        "updated_at":     now_iso(),
    }
    state["sync_registry"] = reg
    return state


def update_sync_item_status(state: dict, item_type: str,
                             item_id: str, status: str) -> dict:
    reg = get_sync_registry(state)
    entry = reg.get(item_type, {}).get(str(item_id))
    if entry:
        entry["status"]     = status
        entry["updated_at"] = now_iso()
    state["sync_registry"] = reg
    return state


def cleanup_sync_registry(state: dict, parent_case_id: str) -> dict:
    """
    Removes all registry entries associated with a parent_case_id.
    Called when the parent case is closed — keeps App State lean.
    Also removes the case_mapping entry for this parent_case_id.
    """
    reg = get_sync_registry(state)
    for item_type in REGISTRY_TYPES:
        bucket = reg.get(item_type, {})
        to_delete = [
            k for k, v in bucket.items()
            if v.get("parent_case_id") == parent_case_id
        ]
        for k in to_delete:
            del bucket[k]
    state["sync_registry"] = reg

    # Also remove the case_mapping
    case_mappings = state.get("case_mappings", {})
    case_mappings.pop(parent_case_id, None)
    state["case_mappings"] = case_mappings

    state[f"cleanup_{parent_case_id}_at"] = now_iso()
    return state


# ─── Task Registry ────────────────────────────────────────────────────────────
#
# Stored under state["pending_tasks"][child_id][parent_case_id]:
# { "task_title", "status", "created_at", "task_note_id", "accepted_at" }
#
# status: "pending" | "accepted" | "closed"

def register_pending_task(state: dict, child_id: str, parent_case_id: str,
                           task_title: str, task_note_id: str = "") -> dict:
    tasks = state.setdefault("pending_tasks", {})
    child_tasks = tasks.setdefault(child_id, {})
    child_tasks[parent_case_id] = {
        "task_title":   task_title,
        "status":       "pending",
        "created_at":   now_iso(),
        "task_note_id": task_note_id,
    }
    state["pending_tasks"] = tasks
    return state


def update_task_status(state: dict, child_id: str, parent_case_id: str,
                        status: str, local_container_id: int = 0) -> dict:
    tasks = state.get("pending_tasks", {})
    entry = tasks.get(child_id, {}).get(parent_case_id)
    if entry:
        entry["status"]     = status
        entry["updated_at"] = now_iso()
        if local_container_id:
            entry["local_container_id"] = local_container_id
        if status == "accepted":
            entry["accepted_at"] = now_iso()
    state["pending_tasks"] = tasks
    return state


def get_pending_task_for_child(state: dict, child_id: str,
                                parent_case_id: str) -> dict:
    return (state.get("pending_tasks", {})
                 .get(child_id, {})
                 .get(parent_case_id, {}))


# ─── Local SOAR REST helpers ──────────────────────────────────────────────────

def build_local_rest_headers(phantom_token: str) -> dict:
    """Auth headers for SOAR internal loopback REST calls."""
    return {
        "ph-auth-token": phantom_token,
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


def fetch_local_notes(container_id: int, phantom_token: str,
                       page_size: int = 200,
                       debug_fn=None) -> list:
    """
    Returns all notes/comments on a local SOAR container.
    Uses SOAR internal REST API via loopback.
    debug_fn: optional callable(str) for logging — pass self.debug_print.
    """
    def _log(msg):
        if debug_fn:
            debug_fn(msg)

    if not HAS_REQUESTS:
        _log("fetch_local_notes: requests library not available")
        return []
    if not phantom_token:
        _log("fetch_local_notes: phantom_token is empty — loopback call will fail. "
             "Set 'phantom_token' in asset config or ensure PHANTOM_TOKEN env var is set.")
        return []

    url = f"{SOAR_LOCAL_BASE}/rest/note"
    params = {
        "_filter_container_id": int(container_id),
        "page_size": page_size,
    }
    try:
        resp = requests.get(
            url, params=params,
            headers=build_local_rest_headers(phantom_token),
            verify=False, timeout=15
        )
        _log(
            f"fetch_local_notes: GET {url} → HTTP {resp.status_code} "
            f"(container_id={container_id}, token_len={len(phantom_token)})"
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        _log(f"fetch_local_notes: returned {len(data)} note(s) for container {container_id}")
        return data
    except Exception as exc:
        _log(f"fetch_local_notes: exception — {type(exc).__name__}: {exc}")
        return []


def update_local_note(note_id: int, new_content: str,
                       phantom_token: str) -> bool:
    """Overwrites the text of a local SOAR note via /rest/note/{id}."""
    if not HAS_REQUESTS:
        return False
    url = f"{SOAR_LOCAL_BASE}/rest/note/{note_id}"
    try:
        resp = requests.post(
            url, json={"content": new_content},
            headers=build_local_rest_headers(phantom_token),
            verify=False, timeout=15
        )
        return resp.status_code in (200, 201)
    except Exception:
        return False


def fetch_local_evidence(phantom_token: str, since_ts: str = None,
                          container_id: int = None,
                          page_size: int = 200) -> list:
    """
    Returns Evidence items from the local SOAR instance.
    Optionally filters by creation time and/or container.
    Uses SOAR /rest/evidence endpoint.
    """
    if not HAS_REQUESTS:
        return []
    url = f"{SOAR_LOCAL_BASE}/rest/evidence"
    params = {"page_size": page_size}
    if since_ts:
        params["_filter_create_time__gt"] = f"'{since_ts}'"
    if container_id:
        params["_filter_container_id"] = f"eq({container_id})"
    try:
        resp = requests.get(
            url, params=params,
            headers=build_local_rest_headers(phantom_token),
            verify=False, timeout=15
        )
        resp.raise_for_status()
        return resp.json().get("data", [])
    except Exception:
        return []


def build_task_note(child_id: str, task_title: str,
                     task_description: str, severity: str,
                     due_date: str = "",
                     observables: list = None) -> str:
    """
    Builds the structured task note written to the Parent case by
    request_child_investigation. The Child's pull_from_parent detects
    the [TASK:{child_id}] prefix and auto-creates a local case.

    If observables is provided (list of CEF dicts), they are serialised as a
    JSON block after the description separator. pull_from_parent parses this
    block and calls save_artifact() for each item — the Child never sees raw
    JSON, it gets proper SOAR Artifacts.

    Observable dict format (CEF-native):
        {"name": "Suspicious IP", "type": "ip", "cef": {"sourceAddress": "1.2.3.4"}}
    """
    lines = [
        f"[TASK:{child_id}]",
        f"Title: {task_title}",
        f"Severity: {severity}",
    ]
    if due_date:
        lines.append(f"Due: {due_date}")
    lines += ["---", task_description]
    if observables:
        lines += [
            "",
            "OBSERVABLES:",
            json.dumps(observables, ensure_ascii=False),
        ]
    return "\n".join(lines)


def parse_task_note(content: str) -> dict:
    """
    Parses a [TASK:child_id] note. Returns dict with:
    { child_id, title, severity, due_date, description, observables } or {}.

    observables is a list of CEF dicts (may be empty list if not present).
    """
    stripped = content.strip()
    if not stripped.upper().startswith("[TASK:"):
        return {}
    try:
        first_line = stripped.splitlines()[0]
        child_id   = first_line[6:first_line.index("]")]
        rest       = stripped[len(first_line):].strip()
        result     = {"child_id": child_id, "raw": stripped, "observables": []}
        lines      = rest.splitlines()
        desc_lines = []
        in_desc    = False
        obs_json   = None

        for i, line in enumerate(lines):
            if line.startswith("Title: "):
                result["title"] = line[7:]
            elif line.startswith("Severity: "):
                result["severity"] = line[10:]
            elif line.startswith("Due: "):
                result["due_date"] = line[5:]
            elif line == "---":
                in_desc = True
            elif line == "OBSERVABLES:":
                in_desc = False
                # Next non-empty line is the JSON array
                for j in range(i + 1, len(lines)):
                    candidate = lines[j].strip()
                    if candidate:
                        obs_json = candidate
                        break
                break
            elif in_desc:
                desc_lines.append(line)

        result["description"] = "\n".join(desc_lines).strip()

        if obs_json:
            try:
                result["observables"] = json.loads(obs_json)
            except (json.JSONDecodeError, ValueError):
                result["observables"] = []

        return result
    except Exception:
        return {}


def create_local_artifacts(container_id: int, observables: list,
                            phantom_token: str,
                            debug_fn=None) -> int:
    """
    Creates SOAR artifacts on a LOCAL container for each observable in the list.
    Uses the /rest/artifact loopback endpoint.

    Each observable dict should have the shape:
        { "name": str, "type": str (optional), "cef": { ... CEF fields ... } }

    Returns the count of artifacts successfully created.
    """
    def _log(msg):
        if debug_fn:
            debug_fn(msg)

    if not HAS_REQUESTS:
        _log("create_local_artifacts: requests not available")
        return 0
    if not phantom_token:
        _log("create_local_artifacts: phantom_token empty — skipping artifact creation")
        return 0
    if not observables:
        return 0

    url     = f"{SOAR_LOCAL_BASE}/rest/artifact"
    headers = build_local_rest_headers(phantom_token)
    created = 0

    for obs in observables:
        if not isinstance(obs, dict):
            continue
        name    = obs.get("name", "Observable")
        obs_type = obs.get("type", "other")
        cef     = obs.get("cef", {})
        if not cef:
            _log(f"create_local_artifacts: skipping '{name}' — empty cef dict")
            continue
        payload = {
            "container_id":           container_id,
            "name":                   name,
            "label":                  "artifact",
            "source_data_identifier": f"ot_obs_{container_id}_{obs_type}_{name[:20]}",
            "cef":                    cef,
            "tags":                   ["from-parent"],
            "run_automation":         False,
        }
        try:
            resp = requests.post(
                url, json=payload, headers=headers, verify=False, timeout=15
            )
            if resp.status_code in (200, 201):
                created += 1
                _log(f"create_local_artifacts: created artifact '{name}' on container {container_id}")
            else:
                _log(
                    f"create_local_artifacts: artifact '{name}' failed "
                    f"HTTP {resp.status_code}: {resp.text[:200]}"
                )
        except Exception as exc:
            _log(f"create_local_artifacts: exception for '{name}': {exc}")

    return created
