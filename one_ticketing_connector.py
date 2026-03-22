# -*- coding: utf-8 -*-
# Copyright 2026 Andreas Buis
#
# one_ticketing_connector.py
# Main BaseConnector subclass — implements all 14 SOAR actions.

import json
import os
import sys
import time

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from one_ticketing_utils import (
    HAS_REQUESTS,
    OneTicketingClient,
    now_iso,
    build_child_case_payload,
    build_status_payload,
    get_case,
    create_case,
    update_case,
    get_notes,
    post_note,
    get_observables,
    update_observable_tags,
    parse_children_registry,
    SOAR_CONTAINERS_PATH,
    SOAR_CONTAINER_PATH,
    SOAR_NOTES_PATH,
    SOAR_ARTIFACTS_PATH,
    SOAR_ARTIFACT_PATH,
    TAG_SYNCED,
    SOAR_LOCAL_BASE,
    build_local_rest_headers,
    build_task_note,
    parse_task_note,
    fetch_local_evidence,
    create_local_artifacts,
    fetch_local_notes,
    update_local_note,
    cleanup_sync_registry,
    is_item_registered,
    register_pending_task,
    register_sync_item,
    update_child_status_in_registry,
)


# ── TLP helpers (v1.4.4) ───────────────────────────────────────────────────────
# Hierarchy: WHITE < GREEN < AMBER < RED
TLP_RANK: dict = {"white": 0, "green": 1, "amber": 2, "red": 3}


def _tlp_rank(tlp_str: str) -> int:
    """Return numeric rank for a TLP string (case-insensitive, dot-normalized)."""
    key = tlp_str.upper().replace("TLP.", "").lower().strip()
    return TLP_RANK.get(key, -1)


def _normalize_tlp(tlp_str: str) -> str:
    """Normalise any TLP variant to 'TLP.COLOR' uppercase format.

    Examples: 'amber' → 'TLP.AMBER', 'tlp:red' → 'TLP.RED'
    Unknown values are returned as-is after stripping whitespace.
    """
    clean = tlp_str.upper().strip().replace("TLP:", "").replace("TLP.", "").strip()
    if clean in ("WHITE", "GREEN", "AMBER", "RED"):
        return f"TLP.{clean}"
    return tlp_str.strip()


class OneTicketingConnector(BaseConnector):
    """
    Splunk SOAR connector for federated Parent-Child case synchronisation.

    Install on ALL instances (Parent + all Children).
    Configure one asset per connection:
      - On each Child: one asset pointing to the Parent.
      - On the Parent: one asset per Child.
    """

    APP_VERSION = "1.6.0"

    def __init__(self):
        super().__init__()
        self._state               = {}
        self._client              = None
        self._config              = {}
        self._queue               = None
        self._child_id            = "UNKNOWN"
        self._role                = "child"
        self._children_registry   = {}   # child_id -> {url, token}

    # ─── Local SOAR REST ──────────────────────────────────────────────────────

    def _phantom_token(self) -> str:
        """
        Returns the SOAR internal auth token for loopback REST calls.

        Detection order (first non-empty wins):
          1. PHANTOM_TOKEN          env var (set by SOAR in some versions)
          2. PHANTOM_AUTH_TOKEN     env var (alternative name in some SOAR builds)
          3. PH_AUTH_TOKEN          env var (legacy Phantom name)
          4. Asset config field 'phantom_token'
             → Set this manually if env vars are not available:
               Admin > User Management > Automation user > Copy token
        """
        return (
            os.environ.get("PHANTOM_TOKEN", "")
            or os.environ.get("PHANTOM_AUTH_TOKEN", "")
            or os.environ.get("PH_AUTH_TOKEN", "")
            or self._config.get("phantom_token", "")
        )

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def initialize(self):
        self._state  = self.load_state()
        self._config = self.get_config()

        self._role              = self._config.get("instance_role", "child").lower()
        self._child_id          = self._config.get("child_id", "UNKNOWN")

        if not HAS_REQUESTS:
            return self.set_status(
                phantom.APP_ERROR,
                "requests library is not installed. "
                "Run: phenv pip3 install requests"
            )

        # Parse children_registry JSON (new dispatch mode)
        _registry_raw = self._config.get("children_registry", "").strip()
        if _registry_raw:
            try:
                _parsed = json.loads(_registry_raw)
                if not isinstance(_parsed, dict):
                    return self.set_status(
                        phantom.APP_ERROR,
                        "children_registry must be a JSON object "
                        "mapping child_id to {url, token}."
                    )
                self._children_registry = _parsed
                self.debug_print(
                    f"children_registry loaded: "
                    f"{list(self._children_registry.keys())}"
                )
            except json.JSONDecodeError as exc:
                return self.set_status(
                    phantom.APP_ERROR,
                    f"children_registry is not valid JSON: {exc}"
                )

        # Build default client (optional when children_registry covers all routing)
        _server = self._config.get("server", "").strip()
        if _server:
            try:
                self._client = OneTicketingClient(self._config)
            except (ValueError, FileNotFoundError, ImportError) as exc:
                return self.set_status(phantom.APP_ERROR, str(exc))

        # Initialise offline queue
        state_dir = os.path.dirname(self.get_state_file_path())
        try:
            self._queue = SyncQueue(state_dir)
        except Exception as exc:
            self.debug_print(f"Queue init warning: {exc}")
            self._queue = None

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    # ─── Private helpers ──────────────────────────────────────────────────────

    def _note_on_local_case(self, container_id: int, content: str):
        """Post a note on a local SOAR container via phantom.rules."""
        try:
            import phantom.rules as ph_rules
            ph_rules.add_comment(container_id=container_id, comment=content)
        except Exception as exc:
            self.debug_print(f"Local note post failed: {exc}")

    def _get_local_container_status(self, container_id: int) -> dict:
        """
        Retrieve local container metadata via SOAR internal REST.
        Returns dict with 'status', 'severity', 'name', etc.
        """
        try:
            import phantom.rules as ph_rules
            containers = ph_rules.get_object(
                object_name="container",
                container_id=container_id
            )
            if containers:
                return containers[0]
        except Exception as exc:
            self.debug_print(f"get_local_container failed: {exc}")
        return {}

    def _close_local_container(self, container_id: int,
                                resolution: str) -> bool:
        """Set local container status to 'closed' via SOAR REST."""
        try:
            import phantom.rules as ph_rules
            ph_rules.update_object(
                object_name="container",
                container_id=container_id,
                update={"status": "closed", "close_reason": resolution}
            )
            return True
        except Exception as exc:
            self.debug_print(f"close_local_container failed: {exc}")
            return False

    def _queue_or_fail(self, action_result: ActionResult, operation_type: str,
                        parent_case_id: str, container_id: int,
                        payload: dict) -> int:
        """
        If offline queue is available, enqueues the request and returns the
        queue depth. Otherwise sets APP_ERROR and returns -1.
        """
        enable_queue = self._config.get("enable_offline_queue", True)
        if enable_queue and self._queue is not None:
            qid = self._queue.enqueue(
                operation_type=operation_type,
                parent_case_id=parent_case_id,
                container_id=container_id,
                payload=payload,
                priority="normal",
            )
            action_result.add_data({
                "queue_id":    qid,
                "queue_depth": self._queue.depth,
                "queued_at":   now_iso(),
                "priority":    "normal",
            })
            action_result.set_status(
                phantom.APP_SUCCESS,
                f"Parent unreachable. Request queued (id={qid}). "
                f"Queue depth: {self._queue.depth}"
            )
            return self._queue.depth
        return -1

    # ─── Action: test_connectivity ────────────────────────────────────────────

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        # ── Token sanity check — shown in logs so the user can verify ────────
        tok_len   = getattr(self._client, "ph_auth_token_len", 0)
        tok_token = self._client.ph_auth_token
        tok_hint  = (
            f"{tok_token[:4]}...{tok_token[-4:]}"
            if tok_len >= 8 else ("(empty)" if tok_len == 0 else "(too short)")
        )
        self.save_progress(
            f"Token loaded: length={tok_len}, value={tok_hint} | "
            f"Target: {self._client.base_url}"
        )

        if tok_len == 0:
            return action_result.set_status(
                phantom.APP_ERROR,
                "ph_auth_token is empty. Enter the REST API Authorization Token "
                "from the automation user on the remote SOAR instance."
            )

        self.save_progress(
            f"Checking connectivity to {self._client.base_url} ..."
        )
        reachable, latency, detail = self._client.health_check()

        if not reachable:
            # Distinguish auth failure from network failure in the status message
            if "401" in detail or "Authentication failed" in detail:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Connectivity OK but authentication failed. {detail}"
                )
            if "403" in detail or "Access denied" in detail:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Connectivity OK but access denied. {detail}"
                )
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Cannot reach {self._client.base_url}. {detail}"
            )

        self.save_progress(
            f"Connection OK ({latency} ms). Token accepted. {detail}"
        )

        self.save_progress(
            f"Instance role: {self._role.upper()} | "
            f"Child ID: {self._child_id} | "
            f"Queue enabled: {self._config.get('enable_offline_queue', True)}"
        )

        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Test Connectivity Passed. "
            f"Latency: {latency} ms | Role: {self._role.upper()} | "
            f"Auth: ph-auth-token | "
            f"Server: {self._client.base_url}"
        )

    # ─── Action: sync_to_parent ───────────────────────────────────────────────

    def _handle_create_child_case(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        parent_case_id  = param.get("parent_case_id")
        case_name       = param.get("case_name")
        description     = param.get("description")
        severity        = param.get("severity")
        assigned_to     = param.get("assigned_to")
        tags_str        = param.get("tags", "")
        due_date        = param.get("due_date")
        observables_raw = param.get("observables", "")
        # TLP: from explicit param first, then artifact CEF, then default AMBER
        _tlp_raw        = str(param.get("tlp", "") or "").strip()

        # Extract artifact_id from context early — used for SDI uniqueness (v1.3.29)
        _ctx = param.get("context") or {}
        if isinstance(_ctx, str):
            try:
                _ctx = json.loads(_ctx)
            except Exception:
                _ctx = {}
        _triggering_artifact_id = str(_ctx.get("artifact_id", "") or "").strip()

        # ── Multi-child routing via children_registry (v1.4.3) ──────────────
        # Priority: explicit param > artifact CEF
        target_child_id = str(param.get("target_child_id", "") or "").strip()

        # ── Read targetChildId AND TLP from triggering artifact CEF (v1.4.8) ──
        # Always look up the artifact when we have an artifact_id, regardless of
        # whether target_child_id was already set from a playbook param.
        # This ensures TLP is propagated even when the playbook fills in
        # target_child_id explicitly but leaves tlp empty.
        _art_task_title = ""   # v1.5.10: captured for artifact name back-fill
        _art_name_orig  = ""   # v1.5.10: original artifact name for back-fill
        if _HAS_REQUESTS and _triggering_artifact_id:
            try:
                _art_resp = _requests.get(
                    f"{SOAR_LOCAL_BASE}/rest/artifact/{_triggering_artifact_id}",
                    headers=build_local_rest_headers(self._phantom_token()),
                    verify=False,
                    timeout=10,
                )
                if _art_resp.ok:
                    _art_json = _art_resp.json()
                    _art_cef  = _art_json.get("cef", {})
                    _art_name_orig  = str(_art_json.get("name", "") or "").strip()
                    _art_task_title = str(_art_cef.get("taskTitle", "") or "").strip()
                    # targetChildId: only fill in if still empty
                    if not target_child_id:
                        target_child_id = str(
                            _art_cef.get("targetChildId", "") or ""
                        ).strip()
                        if target_child_id:
                            self.debug_print(
                                f"targetChildId='{target_child_id}' read from "
                                f"artifact {_triggering_artifact_id} CEF"
                            )
                    # TLP: always override from artifact CEF if param was empty (v1.4.8)
                    if not _tlp_raw:
                        _tlp_raw = str(_art_cef.get("tlp", "") or "").strip()
                        if _tlp_raw:
                            self.debug_print(
                                f"TLP='{_tlp_raw}' read from artifact "
                                f"{_triggering_artifact_id} CEF"
                            )
            except Exception as _tci_exc:
                self.debug_print(
                    f"Artifact CEF lookup failed (non-fatal): {_tci_exc}"
                )

        # Resolve which client (connection) to use for this child
        _active_client = self._client   # default: asset-configured connection

        if self._children_registry:
            # New mode: route via registry
            if not target_child_id:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "children_registry is configured but no targetChildId found "
                    "in artifact CEF or action parameters."
                )
            child_cfg = self._children_registry.get(target_child_id)
            if not child_cfg:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"No entry for '{target_child_id}' in children_registry. "
                    f"Known children: {list(self._children_registry.keys())}"
                )
            try:
                _active_client = OneTicketingClient({
                    "server":        child_cfg.get("url", ""),
                    "ph_auth_token": child_cfg.get("token", ""),
                    "child_id":      target_child_id,
                    "instance_role": "child",
                })
                self.save_progress(
                    f"Routing to child '{target_child_id}' "
                    f"at {child_cfg.get('url', '')}"
                )
            except Exception as _reg_exc:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Failed to build connection for '{target_child_id}': {_reg_exc}"
                )
        elif target_child_id and target_child_id != self._child_id:
            # Legacy mode: skip if child_id does not match this asset
            action_result.add_data({
                "child_case_id":        "",
                "parent_case_id":       parent_case_id,
                "child_instance_url":   _active_client.base_url if _active_client else "",
                "creation_status":      "skipped",
                "created_at":           now_iso(),
                "observable_artifacts": 0,
            })
            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Skipped — targetChildId='{target_child_id}' (from artifact CEF) "
                f"does not match this asset's child_id='{self._child_id}'.",
            )

        # Label resolution: action param → asset config → default "events"
        label = (
            param.get("label")
            or self._config.get("container_label", "")
            or "events"
        ).strip()

        tags = [t.strip() for t in tags_str.split(",") if t.strip()] \
               if tags_str else []
        tags.append("parent-distributed")

        # ── TLP tag (v1.4.4) ─────────────────────────────────────────────────
        tlp = _normalize_tlp(_tlp_raw) if _tlp_raw else "TLP.AMBER"
        if tlp not in tags:
            tags.append(tlp)
        self.debug_print(f"create_child_case: TLP={tlp}")

        # ── Resolve workbook template BEFORE creating the container (v1.3.27) ─
        # Include container_type="case" and template_id in the INITIAL creation
        # POST so SOAR creates the Case and assigns the workbook atomically.
        # (template_id is only valid on creation; updating an existing container
        #  with template_id returns 400 Bad Request.)
        _template_id  = None
        _template_src = ""
        try:
            wb_name = self._config.get("default_workbook", "").strip()
            if wb_name:
                _r = _active_client.get(
                    "/rest/workbook_template",
                    params={"_filter_name": f'"{wb_name}"', "page_size": 1},
                )
                _d = _r.get("data", [])
                if _d:
                    _template_id  = _d[0]["id"]
                    _template_src = f"name='{wb_name}'"
            if not _template_id:
                _r = _active_client.get(
                    "/rest/workbook_template",
                    params={"_filter_is_default": "true", "page_size": 1},
                )
                _d = _r.get("data", [])
                if _d:
                    _template_id  = _d[0]["id"]
                    _template_src = "system default"
        except Exception as _tmpl_exc:
            self.debug_print(f"workbook_template lookup failed (non-fatal): {_tmpl_exc}")

        self.save_progress(
            f"Creating Child case on {_active_client.base_url} "
            f"(Parent: {parent_case_id}, label={label}, "
            f"workbook={_template_src or 'none'}) ..."
        )

        try:
            payload = build_child_case_payload(
                parent_case_id=parent_case_id,
                case_name=case_name,
                description=description,
                severity=severity,
                child_id=target_child_id or self._child_id,  # v1.5.4: use destination ID, not local asset ID
                assigned_to=assigned_to,
                tags=tags,
                due_date=due_date,
                label=label,
                artifact_id=_triggering_artifact_id or None,
            )
            # Promote to Case + assign workbook in one shot
            payload["container_type"] = "case"
            if _template_id:
                payload["template_id"] = int(_template_id)

            case_resp     = create_case(_active_client, payload)
            child_case_id = str(case_resp.get("id", case_resp.get("case_id", "")))

            # ── POST artifact: Parent Case Reference ─────────────────────────
            # Creates a permanent, queryable link back to the originating
            # Parent case using SOAR's native artifact/CEF model.
            if child_case_id:
                self.save_progress(
                    f"Creating 'Parent Case Reference' artifact on "
                    f"container {child_case_id}..."
                )
                try:
                    artifact_payload = {
                        "container_id":           int(child_case_id),
                        "name":                   "Parent Case Reference",
                        # v1.5.16: dedicated label so it is not counted as an observable
                        # artifact (get_children_status uses _filter_label="artifact") and
                        # does not appear in the child replay/update selection lists.
                        # Also the SOLE artifact with run_automation=True so that the child
                        # playbook fires exactly once (no race condition with observables).
                        "label":                  "parent_case_reference",
                        "source_data_identifier": f"ot_parent_ref_{parent_case_id}",
                        "cef": {
                            "parent_case_id":  parent_case_id,   # unified field name
                            "parent_soar_url": "",               # filled by child if known
                            "origin_child_id": self._child_id,
                            "distributed_at":  now_iso(),
                        },
                        "cef_types": {
                            "parent_case_id": ["splunk container id"],
                        },
                        # v1.5.16: moved run_automation from individual observables to here
                        # so the child playbook is triggered exactly once per case setup.
                        "run_automation": True,
                    }
                    _active_client.post(SOAR_ARTIFACTS_PATH, artifact_payload)
                    self.save_progress("Parent Case Reference artifact created.")
                except Exception as art_exc:
                    # Non-fatal — container was created; artifact is supplemental
                    self.debug_print(
                        f"Artifact creation failed (non-fatal): {art_exc}"
                    )

            # ── POST note: description as human-readable note ─────────────────
            # Makes the task scope immediately visible in the child Activity tab
            # without having to open the case description field.
            if child_case_id and description:
                try:
                    post_note(
                        _active_client,
                        child_case_id,
                        content=description,
                        title="Task Description (from Parent)",
                    )
                    self.save_progress("Description note added to child case.")
                except Exception as note_exc:
                    self.debug_print(
                        f"Description note creation failed (non-fatal): {note_exc}"
                    )

            # ── POST artifacts: one per observable ───────────────────────────
            # Each observable becomes a first-class SOAR artifact so that
            # child playbooks can query them via filter / action inputs.
            obs_count = 0
            if child_case_id and observables_raw:
                try:
                    obs_list = json.loads(observables_raw) if isinstance(observables_raw, str) else observables_raw
                    for obs in (obs_list if isinstance(obs_list, list) else []):
                        obs_name = obs.get("name", "Observable")
                        obs_type = obs.get("type", "network")
                        obs_cef  = obs.get("cef", {})
                        # Fill cef_types so SOAR knows which field is an IP/domain etc.
                        cef_types = {}
                        for field in obs_cef:
                            if "address" in field.lower() or "ip" in field.lower():
                                cef_types[field] = ["ip"]
                            elif "domain" in field.lower() or "url" in field.lower():
                                cef_types[field] = ["domain"]
                            elif "hash" in field.lower():
                                cef_types[field] = ["hash"]
                            elif "email" in field.lower():
                                cef_types[field] = ["email"]
                        obs_artifact = {
                            "container_id":           int(child_case_id),
                            "name":                   obs_name,
                            "label":                  "artifact",
                            "type":                   obs_type,
                            "source_data_identifier": f"ot_obs_{parent_case_id}_{obs_count}",
                            "cef":                    obs_cef,
                            "cef_types":              cef_types,
                            "tags":                   ["from-parent"],
                            # v1.5.16: run_automation moved to parent_case_reference artifact
                            # (created above). Setting True here caused the child playbook to
                            # fire once per observable (race condition → duplicate heartbeats).
                            "run_automation":         False,
                        }
                        _active_client.post(SOAR_ARTIFACTS_PATH, obs_artifact)
                        obs_count += 1
                    self.save_progress(
                        f"{obs_count} observable artifact(s) created on child case."
                    )
                except Exception as obs_exc:
                    self.debug_print(
                        f"Observable artifact creation failed (non-fatal): {obs_exc}"
                    )

            # ── Registry: record this child so get_children_status works ─────
            # Key by child_id (e.g. "DE_OT") so get_children_status can display
            # meaningful names. Falls back to URL if target_child_id is unknown.
            if child_case_id:
                registry = parse_children_registry(self._state)
                child_key = target_child_id or _active_client.base_url

                # v1.5.5 Bug 1: Remove any legacy URL-keyed entries for this
                # same child URL so get_children_status won't show duplicates.
                _base = _active_client.base_url.rstrip("/")
                _stale = [k for k, v in list(registry.items())
                          if k != child_key
                          and v.get("server", "").rstrip("/") == _base]
                for _sk in _stale:
                    del registry[_sk]
                    self.debug_print(
                        f"Removed stale URL-keyed registry entry '{_sk}' "
                        f"(replaced by '{child_key}')"
                    )

                if child_key not in registry:
                    registry[child_key] = {}
                registry[child_key].update({
                    "server":              _active_client.base_url,
                    # v1.5.5 Bug 2: store the child's own token, not the parent
                    # asset token — get_children_status needs it to authenticate
                    # against the child SOAR instance.
                    "ph_auth_token":       _active_client.ph_auth_token,
                    "last_child_case_id":  child_case_id,
                    "last_parent_case_id": parent_case_id,
                    "last_sync":           now_iso(),
                    "last_known_status":   "new",
                })
                self._state["children_registry"] = registry

            # v1.5.7: Back-fill triggering artifact CEF with child case ID so the
            # widget's "Active Tasks" table shows a clickable #id link immediately,
            # without waiting for a get_children_status run.
            if _triggering_artifact_id and _HAS_REQUESTS:
                try:
                    _child_case_url = (
                        f"{_active_client.base_url}/mission/{child_case_id}/analyst"
                    )
                    # v1.5.10: also patch artifact name to include #childCaseId
                    # New format: "Child Task [DE_OT] #127: Phishing Investigation"
                    _title_part = _art_task_title or _art_name_orig
                    _new_art_name = (
                        f"Child Task [{target_child_id}] #{child_case_id}: {_title_part}"
                        if _title_part
                        else f"Child Task [{target_child_id}] #{child_case_id}"
                    )
                    # v1.5.11: MERGE original CEF so targetChildId, taskTitle etc.
                    # are preserved — SOAR POST replaces the entire cef field,
                    # it does NOT do a field-level merge.
                    _merged_cef = dict(_art_cef)   # copy original
                    _merged_cef["childCaseId"]      = child_case_id
                    _merged_cef["childInstanceUrl"] = _active_client.base_url
                    _merged_cef["childCaseUrl"]     = _child_case_url
                    _cef_patch = {
                        "name": _new_art_name,
                        "cef":  _merged_cef,
                    }
                    _art_patch_resp = _requests.post(
                        f"{SOAR_LOCAL_BASE}/rest/artifact/{_triggering_artifact_id}",
                        headers=build_local_rest_headers(self._phantom_token()),
                        json=_cef_patch,
                        verify=False,
                        timeout=10,
                    )
                    if _art_patch_resp.ok:
                        self.debug_print(
                            f"v1.5.10: Patched artifact {_triggering_artifact_id} "
                            f"name='{_new_art_name}', CEF childCaseId={child_case_id}"
                        )
                    else:
                        self.debug_print(
                            f"v1.5.10: Artifact back-fill returned "
                            f"HTTP {_art_patch_resp.status_code} (non-fatal)"
                        )
                except Exception as _cef_patch_exc:
                    self.debug_print(
                        f"v1.5.10: Artifact back-fill failed (non-fatal): "
                        f"{_cef_patch_exc}"
                    )

            created_at = now_iso()
            action_result.add_data({
                "child_case_id":          child_case_id,
                "parent_case_id":         parent_case_id,
                "child_instance_url":     _active_client.base_url,
                "label_used":             label,
                "creation_status":        "created",
                "created_at":             created_at,
                "observable_artifacts":   obs_count,
            })
            # v1.3.19: Auto-start per-case monitor (heartbeat)
            # Registers mapping in app state and creates monitor_heartbeat artifact.
            try:
                self._handle_start_case_monitor({
                    "container_id":          child_case_id,
                    "parent_case_id":        parent_case_id,
                    "check_interval_minutes": 5,
                })
                self.save_progress(
                    f"create_child_case: monitor started for container {child_case_id}."
                )
            except Exception as mon_exc:
                self.debug_print(
                    f"create_child_case: monitor start failed (non-fatal): {mon_exc}"
                )

            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Child case {child_case_id} created on "
                f"{_active_client.base_url} (label={label}). Monitor active."
            )

        except Exception as exc:
            # Handle duplicate SDI gracefully — child case already exists
            exc_str = str(exc).lower()
            if "400" in exc_str and ("duplicate" in exc_str or "already" in exc_str or "conflict" in exc_str):
                action_result.add_data({
                    "child_case_id": "",
                    "parent_case_id": parent_case_id,
                    "child_instance_url": _active_client.base_url,
                    "creation_status": "already_exists",
                    "created_at": now_iso(),
                    "observable_artifacts": 0,
                })
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Child case already exists for parent={parent_case_id} child={target_child_id or self._child_id} "
                    f"(SDI conflict — use 'update child case' to push new context)."
                )
            return action_result.set_status(
                phantom.APP_ERROR,
                f"create_child_case failed: {exc}"
            )

    # ─── Action: update_child_case ───────────────────────────────────────────
    # v1.5.7: Complete rewrite — registry mode + severity/new_observables params
    #         + parent_update artifact on child for playbook triggering.

    def _handle_update_child_case(self, param):
        """
        Pushes an update from the Parent to an existing Child case.

        Registry mode (preferred): supply target_child_id — the action looks up
        the child URL and token from children_registry and locates the child case
        via the registry's last_child_case_id.

        Legacy mode: omit target_child_id — the action connects to self._client
        and finds the child case by SDI (ot_{parent_case_id}_{child_id}).

        Supported updates (all optional, at least one recommended):
          comment         — posted as a note [PARENT_UPDATE] on the child case
          severity        — new severity (low / medium / high / critical)
          new_observables — JSON array of {name, type, cef} objects
          artifact_ids    — comma-sep parent artifact IDs to copy to child
          due_date        — ISO 8601 due time

        After all updates a parent_update artifact (run_automation=True) is
        created on the child case so child-side playbooks can react.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        parent_case_id   = str(param.get("parent_case_id",   "") or "").strip()
        target_child_id  = str(param.get("target_child_id",  "") or "").strip()
        comment          = str(param.get("comment",          "") or "").strip()
        artifact_ids_str = str(param.get("artifact_ids",     "") or "").strip()
        due_date         = str(param.get("due_date",         "") or "").strip()
        severity         = str(param.get("severity",         "") or "").strip().lower()
        new_obs_str      = str(param.get("new_observables",  "") or "").strip()

        if not parent_case_id:
            return action_result.set_status(
                phantom.APP_ERROR,
                "update_child_case: parent_case_id is required."
            )

        # ── Resolve child client and case ID ──────────────────────────────────
        child_client  = None
        child_case_id = ""
        display_child = target_child_id or self._child_id

        if target_child_id and self._children_registry:
            # ── Registry mode ──────────────────────────────────────────────
            child_cfg = self._children_registry.get(target_child_id)
            if not child_cfg:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"No entry for '{target_child_id}' in children_registry. "
                    f"Known: {list(self._children_registry.keys())}"
                )
            try:
                child_client = OneTicketingClient({
                    "server":        child_cfg.get("url", ""),
                    "ph_auth_token": child_cfg.get("token", ""),
                    "child_id":      target_child_id,
                    "instance_role": "child",
                })
            except Exception as exc:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Failed to build connection for '{target_child_id}': {exc}"
                )

            # Prefer registry's stored case ID; fall back to SDI lookup
            registry     = parse_children_registry(self._state)
            child_info   = registry.get(target_child_id, {})
            child_case_id = str(child_info.get("last_child_case_id", "")).strip()

            if not child_case_id:
                sdi = f"ot_{parent_case_id}_{target_child_id}"
                try:
                    resp = child_client.get(
                        SOAR_CONTAINERS_PATH,
                        params={
                            "_filter_source_data_identifier": f'"{sdi}"',
                            "_fields": "id,name,status",
                        },
                    )
                    data = resp.get("data", []) if isinstance(resp, dict) else []
                    if not data:
                        action_result.add_data({
                            "update_status": "skipped",
                            "child_id": target_child_id,
                            "message": (
                                f"No child case found for parent {parent_case_id} "
                                f"/ child {target_child_id}"
                            ),
                        })
                        return action_result.set_status(
                            phantom.APP_SUCCESS,
                            f"No child case found for {target_child_id} (SDI: {sdi})"
                        )
                    child_case_id = str(data[0]["id"])
                except Exception as exc:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        f"Failed to locate child case via SDI: {exc}"
                    )

        else:
            # ── Legacy mode: use self._client + SDI ───────────────────────
            child_client = self._client
            sdi          = f"ot_{parent_case_id}_{self._child_id}"
            try:
                resp = child_client.get(
                    SOAR_CONTAINERS_PATH,
                    params={
                        "_filter_source_data_identifier": f'"{sdi}"',
                        "_fields": "id,name,status",
                    },
                )
                data = resp.get("data", []) if isinstance(resp, dict) else []
                if not data:
                    action_result.add_data({
                        "update_status": "skipped",
                        "child_id": self._child_id,
                        "message": (
                            f"No child case found for parent {parent_case_id} "
                            f"(SDI: {sdi})"
                        ),
                    })
                    return action_result.set_status(
                        phantom.APP_SUCCESS,
                        f"No child case found for parent {parent_case_id} "
                        f"(SDI: {sdi})"
                    )
                child_case_id = str(data[0]["id"])
            except Exception as exc:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Failed to search for child case: {exc}"
                )

        self.save_progress(
            f"Updating child case {child_case_id} (child={display_child})"
        )

        result_data = {
            "update_status":     "updated",
            "child_id":          display_child,
            "child_case_id":     child_case_id,
            "child_instance_url": child_client.base_url,
            "note_posted":       False,
            "artifacts_copied":  0,
            "severity_updated":  False,
            "due_date_updated":  False,
            "obs_added":         0,
        }
        _update_parts = []   # summary list for status message and artifact CEF

        # ── Update severity / due_date on child case ──────────────────────────
        _VALID_SEV = {"low", "medium", "high", "critical"}
        case_update: dict = {}
        if severity and severity in _VALID_SEV:
            case_update["severity"] = severity
        if due_date:
            case_update["due_time"] = due_date
        if case_update:
            try:
                child_client.post(
                    SOAR_CONTAINER_PATH.format(container_id=child_case_id),
                    case_update,
                )
                if "severity" in case_update:
                    result_data["severity_updated"] = True
                    _update_parts.append(f"severity→{severity}")
                    self.save_progress(f"Severity updated to '{severity}'.")
                if "due_time" in case_update:
                    result_data["due_date_updated"] = True
                    _update_parts.append("due_date")
                    self.save_progress("Due date updated.")
            except Exception as exc:
                self.save_progress(f"Error updating case fields (non-fatal): {exc}")

        # ── Post comment as a note ────────────────────────────────────────────
        if comment:
            try:
                child_client.post(
                    "/rest/note",
                    {
                        "container_id": int(child_case_id),
                        "title":        "[PARENT_UPDATE] New information from Parent SOAR",
                        "content":      comment,
                        "note_type":    "general",
                    },
                )
                result_data["note_posted"] = True
                _update_parts.append("note")
                self.save_progress("Note posted to child case.")
            except Exception as exc:
                self.save_progress(f"Error posting note (non-fatal): {exc}")

        # ── Copy existing parent artifacts ────────────────────────────────────
        if artifact_ids_str and _HAS_REQUESTS:
            _token   = self._phantom_token()
            _headers = build_local_rest_headers(_token)
            for _aid in [a.strip() for a in artifact_ids_str.split(",") if a.strip()]:
                try:
                    _r = _requests.get(
                        f"{SOAR_LOCAL_BASE}/rest/artifact/{_aid}",
                        headers=_headers, verify=False, timeout=10,
                    )
                    if _r.status_code == 200:
                        _art = _r.json()
                        child_client.post(
                            SOAR_ARTIFACTS_PATH,
                            {
                                "container_id":   int(child_case_id),
                                "name":           _art.get("name", f"Observable {_aid}"),
                                "label":          "artifact",
                                "type":           _art.get("type", "network"),
                                "cef":            _art.get("cef", {}),
                                # v1.5.17: tag so the child widget can exclude these from
                                # the replay/update list (same as create_child_case observables)
                                "tags":           ["from-parent"],
                                "run_automation": False,
                            },
                        )
                        result_data["artifacts_copied"] += 1
                    else:
                        self.save_progress(
                            f"Could not fetch artifact {_aid}: "
                            f"HTTP {_r.status_code}"
                        )
                except Exception as exc:
                    self.save_progress(
                        f"Error copying artifact {_aid} (non-fatal): {exc}"
                    )
            if result_data["artifacts_copied"]:
                _update_parts.append(
                    f"{result_data['artifacts_copied']} artifact(s)"
                )

        # ── Add new inline observables ────────────────────────────────────────
        if new_obs_str:
            try:
                import json as _json
                _obs_list = _json.loads(new_obs_str)
                if not isinstance(_obs_list, list):
                    _obs_list = [_obs_list]
                for _obs in _obs_list:
                    try:
                        child_client.post(
                            SOAR_ARTIFACTS_PATH,
                            {
                                "container_id":   int(child_case_id),
                                "name":           _obs.get("name", "New Observable"),
                                "label":          "artifact",
                                "type":           _obs.get("type", "network"),
                                "cef":            _obs.get("cef", {}),
                                # v1.5.17: tag so the child widget excludes these from
                                # the replay/update selection list
                                "tags":           ["from-parent"],
                                "run_automation": False,
                            },
                        )
                        result_data["obs_added"] += 1
                    except Exception as _obs_exc:
                        self.save_progress(
                            f"Error adding observable (non-fatal): {_obs_exc}"
                        )
                if result_data["obs_added"]:
                    _update_parts.append(f"{result_data['obs_added']} new_obs")
            except Exception as _parse_exc:
                self.save_progress(
                    f"Could not parse new_observables JSON (non-fatal): {_parse_exc}"
                )

        # ── parent_update artifact on child case (playbook trigger) ───────────
        # run_automation=True so child SOAR playbooks with a rule on label
        # "parent_update" are triggered automatically.
        try:
            _ts_tag  = now_iso().replace(":", "").replace("-", "")[:15]
            _pu_sdi  = f"ot_pupdate_{parent_case_id}_{_ts_tag}_{display_child}"
            _pu_name = (
                f"[Parent Update] "
                f"{', '.join(_update_parts) or 'message'} "
                f"from case #{parent_case_id}"
            )
            # v1.5.10: each update dimension is its own CEF field so child
            # playbooks can act on them selectively.
            _pu_cef = {
                "parentCaseId":   parent_case_id,
                "childId":        display_child,
                "updateType":     ", ".join(_update_parts) or "message",
                "updatedAt":      now_iso(),
            }
            if comment:
                _pu_cef["note"] = comment
            if severity:
                _pu_cef["severity"] = severity
            if due_date:
                _pu_cef["dueDate"] = due_date
            if result_data.get("artifacts_copied"):
                _pu_cef["artifactsCopied"] = str(result_data["artifacts_copied"])
            if artifact_ids_str:
                _pu_cef["artifactIds"] = artifact_ids_str
            if result_data.get("obs_added"):
                _pu_cef["newObsAdded"] = str(result_data["obs_added"])
            child_client.post(
                SOAR_ARTIFACTS_PATH,
                {
                    "container_id":           int(child_case_id),
                    "label":                  "parent_update",
                    "name":                   _pu_name,
                    "type":                   "network",
                    "source_data_identifier": _pu_sdi,
                    "cef":                    _pu_cef,
                    "run_automation":         True,
                },
            )
            self.save_progress(
                "parent_update artifact created on child case "
                "(playbook trigger active)."
            )
        except Exception as _pu_exc:
            self.debug_print(
                f"parent_update artifact creation failed (non-fatal): {_pu_exc}"
            )

        # ── Registry: refresh last_sync ───────────────────────────────────────
        if target_child_id:
            try:
                _reg = parse_children_registry(self._state)
                if target_child_id in _reg:
                    _reg[target_child_id]["last_sync"] = now_iso()
                    self._state["children_registry"] = _reg
            except Exception:
                pass

        _summary = ", ".join(_update_parts) if _update_parts else "no changes"
        action_result.add_data(result_data)
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Child case {child_case_id} updated ({_summary})."
        )

    # ─── Action: get_children_status ─────────────────────────────────────────

    def _handle_get_children_status(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        parent_case_id = param.get("parent_case_id")

        self.save_progress(
            f"Retrieving child statuses for Parent case {parent_case_id}..."
        )

        registry = parse_children_registry(self._state)

        # ── v1.5.6: Purge legacy URL-keyed ghost entries at query time ─────────
        # Before v1.5.5, create_child_case sometimes stored entries keyed by the
        # child's base URL (e.g. "https://childsoar.soar4rookies.com:8443") instead
        # of the child_id (e.g. "DE_OT").  Those stale entries cause duplicate
        # rows in the status table.  Remove any URL-keyed entry whose URL already
        # has a corresponding child_id-keyed entry.
        if registry:
            _id_keyed_urls = {
                v.get("server", "").rstrip("/")
                for k, v in registry.items()
                if not k.startswith("http")
            }
            _ghosts = [
                k for k in list(registry.keys())
                if k.startswith("http") and k.rstrip("/") in _id_keyed_urls
            ]
            if _ghosts:
                for _gk in _ghosts:
                    del registry[_gk]
                self._state["children_registry"] = registry
                self.save_progress(
                    f"Purged {len(_ghosts)} legacy URL-keyed ghost registry "
                    f"entry(s): {_ghosts}"
                )

        # ── Auto-populate registry from asset config when state is empty ──────
        # This handles the case where create_child_case has not yet run under
        # the current asset configuration (e.g. fresh install, or after an
        # asset reconfiguration).  For each child_id in self._children_registry
        # (the asset config JSON field), we query the child SOAR directly using
        # the well-known SDI pattern ot_{parent_case_id}_{child_id} — the same
        # SDI that build_child_case_payload() assigns at creation time.
        if not registry and self._children_registry:
            self.save_progress(
                "State registry empty — auto-discovering child cases via SDI "
                f"lookup across {len(self._children_registry)} configured child(ren)."
            )
            for _cfg_child_id, _cfg in self._children_registry.items():
                _cfg_url   = _cfg.get("url", "")
                _cfg_token = _cfg.get("token", "")
                if not _cfg_url:
                    continue
                try:
                    _disc_client = OneTicketingClient({
                        "server":        _cfg_url,
                        "ph_auth_token": _cfg_token,
                        "instance_role": "child",
                        "child_id":      _cfg_child_id,
                    })
                    _sdi = f"ot_{parent_case_id}_{_cfg_child_id}"
                    _disc_resp = _disc_client.get(
                        SOAR_CONTAINERS_PATH,
                        params={
                            "_filter_source_data_identifier": f'"{_sdi}"',
                            "_fields": "id,status,severity,create_time",
                            "page_size": 1,
                        },
                    )
                    _disc_data = _disc_resp.get("data", [])
                    if _disc_data:
                        _c = _disc_data[0]
                        registry[_cfg_child_id] = {
                            "server":             _cfg_url,
                            "ph_auth_token":      _cfg_token,
                            "last_child_case_id": str(_c.get("id", "")),
                            "last_known_status":  _c.get("status", "unknown"),
                            "last_known_severity": _c.get("severity", "unknown"),
                            "last_sync":          _c.get("create_time", "auto-discovered"),
                        }
                        self.save_progress(
                            f"Auto-discovered child case {_c['id']} for "
                            f"{_cfg_child_id} at {_cfg_url}"
                        )
                    else:
                        self.save_progress(
                            f"No case found for {_cfg_child_id} at {_cfg_url} "
                            f"(SDI={_sdi}) — run create_child_case first."
                        )
                except Exception as _disc_exc:
                    self.debug_print(
                        f"SDI auto-discovery for {_cfg_child_id} failed "
                        f"(non-fatal): {_disc_exc}"
                    )
            # Persist discovered entries so next call is instant
            if registry:
                self._state["children_registry"] = registry
            else:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "No child cases found via SDI lookup. "
                    "Run create_child_case first to create child containers, "
                    "or check that children_registry in the asset config is correct."
                )
        elif not registry:
            # ── Fallback C: legacy single-child asset (server + child_id) ─────
            # Old-style assets configure one asset per child with a direct
            # server URL and child_id field.  No children_registry needed.
            # Try SDI lookup on self._client using self._child_id.
            if self._client and self._child_id and self._child_id != "UNKNOWN":
                self.save_progress(
                    f"No registry configured — falling back to legacy single-child "
                    f"lookup for child_id='{self._child_id}' on {self._client.base_url}"
                )
                try:
                    _sdi = f"ot_{parent_case_id}_{self._child_id}"
                    _fb_resp = self._client.get(
                        SOAR_CONTAINERS_PATH,
                        params={
                            "_filter_source_data_identifier": f'"{_sdi}"',
                            "_fields": "id,status,severity,create_time",
                            "page_size": 1,
                        },
                    )
                    _fb_data = _fb_resp.get("data", [])
                    if _fb_data:
                        _c = _fb_data[0]
                        registry[self._child_id] = {
                            "server":              self._client.base_url,
                            "ph_auth_token":       self._config.get("ph_auth_token", ""),
                            "last_child_case_id":  str(_c.get("id", "")),
                            "last_known_status":   _c.get("status", "unknown"),
                            "last_known_severity": _c.get("severity", "unknown"),
                            "last_sync":           _c.get("create_time", "legacy-discovered"),
                        }
                        self._state["children_registry"] = registry
                        self.save_progress(
                            f"Legacy discovery: found child case {_c['id']} "
                            f"for {self._child_id}"
                        )
                    else:
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            f"No child case found for parent_case_id={parent_case_id} "
                            f"and child_id={self._child_id} (SDI={_sdi}). "
                            "Run create_child_case first."
                        )
                except Exception as _fb_exc:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        f"Legacy SDI lookup failed for {self._child_id}: {_fb_exc}"
                    )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Registry is empty. Either: (1) configure children_registry in "
                    "the asset, or (2) ensure child_id is set in the asset config, "
                    "or (3) run create_child_case first to auto-populate the registry."
                )

        # ── Get parent case TLP for escalation detection (v1.4.4) ────────────
        parent_tlp      = "TLP.AMBER"   # default if we cannot read parent tags
        parent_tlp_rank = _tlp_rank(parent_tlp)
        if parent_case_id and _HAS_REQUESTS:
            try:
                _pr = _requests.get(
                    f"{SOAR_LOCAL_BASE}{SOAR_CONTAINER_PATH.format(container_id=parent_case_id)}",
                    headers=build_local_rest_headers(self._phantom_token()),
                    verify=False,
                    timeout=10,
                )
                if _pr.ok:
                    _ptags = _pr.json().get("tags") or []
                    for _t in _ptags:
                        if str(_t).upper().startswith("TLP."):
                            parent_tlp      = _normalize_tlp(str(_t))
                            parent_tlp_rank = _tlp_rank(parent_tlp)
                            break
            except Exception as _plookup_exc:
                self.debug_print(
                    f"parent TLP lookup failed (non-fatal): {_plookup_exc}"
                )

        # ── Approach A: use registry (populated by create_child_case) ────────
        for child_id, child_info in registry.items():
            child_url_base = child_info.get("server", child_info.get("base_url", ""))
            child_token    = child_info.get("ph_auth_token", "")
            reachable      = False
            status         = child_info.get("last_known_status", "unknown")
            severity       = child_info.get("last_known_severity", "unknown")
            last_sync      = child_info.get("last_sync", "never")
            child_case_id  = child_info.get("last_child_case_id", "")
            tlp            = "unknown"
            assigned_user  = ""
            artifact_count = 0
            tlp_escalated  = False
            case_title     = ""
            child_case_url = (
                f"{child_url_base}/mission/{child_case_id}/analyst"
                if child_url_base and child_case_id
                else ""
            )

            if child_url_base and child_case_id:
                try:
                    child_config = {
                        "server":        child_url_base,
                        "ph_auth_token": child_token or self._config.get("ph_auth_token", ""),
                        "instance_role": "child",
                        "child_id":      child_id,
                    }
                    child_client   = OneTicketingClient(child_config)
                    case_data      = get_case(child_client, child_case_id)
                    status         = case_data.get("status", status)
                    severity       = case_data.get("severity", severity)
                    assigned_user  = case_data.get("owner_name", "")
                    case_title     = case_data.get("name", "")
                    # v1.5.3: count only observable artifacts (label="artifact"),
                    # not admin artifacts (heartbeat, parent_case_reference, etc.)
                    try:
                        _obs_resp = child_client.get(
                            SOAR_ARTIFACTS_PATH,
                            params={
                                "_filter_container_id": child_case_id,
                                "_filter_label":        '"artifact"',
                                "page_size":            0,
                            },
                        )
                        artifact_count = int(_obs_resp.get("count", 0) or 0)
                    except Exception:
                        artifact_count = int(case_data.get("artifact_count", 0) or 0)
                    reachable      = True
                    notes          = get_notes(child_client, child_case_id)
                    findings_count = len(notes)

                    # Extract TLP tag from child case tags
                    child_tags = case_data.get("tags") or []
                    for tag in child_tags:
                        if str(tag).upper().startswith("TLP."):
                            tlp = _normalize_tlp(str(tag))
                            break

                    # TLP escalation detection: child TLP > parent TLP
                    child_tlp_rank = _tlp_rank(tlp)
                    if child_tlp_rank > parent_tlp_rank and child_tlp_rank >= 0:
                        tlp_escalated = True
                        self.debug_print(
                            f"TLP escalation detected: child={child_id} "
                            f"childTlp={tlp} parentTlp={parent_tlp}"
                        )
                        # Create escalation artifact on Parent case
                        if parent_case_id and _HAS_REQUESTS:
                            try:
                                _esc_sdi = f"ot_tlp_esc_{parent_case_id}_{child_id}"
                                _esc_payload = {
                                    "container_id":           int(parent_case_id),
                                    "label":                  "tlp_escalation",
                                    "name":                   f"TLP Escalation: {child_id} ({tlp})",
                                    "type":                   "network",
                                    "source_data_identifier": _esc_sdi,
                                    "cef": {
                                        "childId":    child_id,
                                        "parentTlp":  parent_tlp,
                                        "childTlp":   tlp,
                                        "detectedAt": now_iso(),
                                    },
                                    "run_automation": False,
                                }
                                _requests.post(
                                    f"{SOAR_LOCAL_BASE}{SOAR_ARTIFACTS_PATH}",
                                    headers=build_local_rest_headers(self._phantom_token()),
                                    json=_esc_payload,
                                    verify=False,
                                    timeout=10,
                                )
                            except Exception as _esc_exc:
                                self.debug_print(
                                    f"TLP escalation artifact creation failed "
                                    f"(non-fatal): {_esc_exc}"
                                )

                except Exception:
                    reachable      = False
                    findings_count = 0
            else:
                findings_count = 0

            # v1.5.3: child_id display — if stored as URL (legacy), use registry key
            display_child_id = child_id
            if display_child_id.startswith("http") and self._children_registry:
                # Reverse-lookup: find registry key matching this URL
                for _reg_key, _reg_cfg in self._children_registry.items():
                    if _reg_cfg.get("url", "").rstrip("/") == child_url_base.rstrip("/"):
                        display_child_id = _reg_key
                        break
                else:
                    # Fallback: use hostname only
                    try:
                        from urllib.parse import urlparse as _up
                        display_child_id = _up(display_child_id).hostname or display_child_id
                    except Exception:
                        pass

            action_result.add_data({
                "child_id":       display_child_id,
                "child_case_id":  child_case_id,
                "case_title":     case_title,
                "status":         status,
                "severity":       severity,
                "last_sync":      last_sync,
                "findings_count": findings_count,
                "reachable":      reachable,
                "source":         "registry",
                "tlp":            tlp,
                "assigned_user":  assigned_user,
                "artifact_count": artifact_count,
                "child_url":      child_case_url,
                "tlp_escalated":  tlp_escalated,
                "retrieved_at":   now_iso(),
            })

        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Retrieved status for {len(registry)} child instance(s) from registry."
        )

    # ─── Action: update_case_status ───────────────────────────────────────────

    def _handle_update_case_status(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        case_id      = param.get("case_id")
        new_status   = param.get("new_status")
        new_severity = param.get("new_severity")
        reason       = param.get("reason")

        self.save_progress(f"Updating case {case_id} → status={new_status}...")

        try:
            # Get current values for before/after comparison
            current   = get_case(self._client, case_id)
            old_status   = current.get("status", "")
            old_severity = current.get("severity", "")

            payload = build_status_payload(new_status, new_severity)
            update_case(self._client, case_id, payload)

            # Post reason as a note if provided
            if reason:
                note_content = (
                    f"[STATUS UPDATE by {self._child_id}]\n"
                    f"{old_status} → {new_status}"
                    + (f" | {old_severity} → {new_severity}" if new_severity else "")
                    + f"\nReason: {reason}"
                )
                post_note(self._client, case_id, note_content)

            action_result.add_data({
                "case_id":      case_id,
                "old_status":   old_status,
                "new_status":   new_status,
                "old_severity": old_severity,
                "new_severity": new_severity or old_severity,
                "updated_at":   now_iso(),
            })
            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Case {case_id} updated: {old_status} → {new_status}."
            )

        except Exception as exc:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"update_case_status failed: {exc}"
            )

    # ─── Action: close_child_case ─────────────────────────────────────────────

    def _handle_close_child_case(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id      = param.get("container_id")
        parent_case_id    = param.get("parent_case_id")
        resolution_note   = param.get("resolution_note")
        resolution_outcome = param.get("resolution_outcome", "resolved")
        notify_parent     = param.get("notify_parent", True)

        self.save_progress(f"Closing Child case (container={container_id})...")

        try:
            # Close the container on the remote (Child) SOAR via REST API.
            # POST /rest/container/{id} {"status":"closed"} — SOAR uses POST
            # for updates. _close_local_container used phantom.rules which is
            # local-only and would close a container on the running SOAR
            # (Parent), not on the connected Child SOAR.
            self.save_progress(
                f"Closing container {container_id} on {self._client.base_url} "
                "via REST ..."
            )
            update_case(
                self._client,
                str(container_id),
                {
                    "status":      "closed",
                    "close_reason": resolution_outcome,
                },
            )
            close_ts = now_iso()

            # Notify Parent if requested
            parent_notified = False
            if notify_parent and parent_case_id:
                self.save_progress("Notifying Parent of closure...")
                try:
                    closure_note = (
                        f"[CHILD CLOSED: {self._child_id}]\n"
                        f"Outcome: {resolution_outcome}\n"
                        f"Closed at: {close_ts}\n\n"
                        f"{resolution_note}"
                    )
                    post_note(self._client, parent_case_id, closure_note)
                    # Update child status in parent registry
                    self._state = update_child_status_in_registry(
                        self._state, self._child_id, "closed"
                    )
                    parent_notified = True
                except Exception as exc:
                    self.debug_print(f"Parent notification failed: {exc}")
                    # Queue notification for later
                    if self._queue is not None:
                        self._queue.enqueue(
                            operation_type="close_notification",
                            parent_case_id=parent_case_id,
                            container_id=container_id,
                            payload={
                                "resolution_note":    resolution_note,
                                "resolution_outcome": resolution_outcome,
                                "closed_at":          close_ts,
                            }
                        )
                        self.save_progress(
                            "Parent unreachable. Closure notification queued."
                        )

            # ── Registry cleanup ─────────────────────────────────────────────
            # Remove all sync registry entries tied to this parent_case_id so
            # that App State stays lean and future mappings start clean.
            if parent_case_id:
                self.save_progress(
                    f"close_child_case: cleaning up registry for {parent_case_id}..."
                )
                self._state = cleanup_sync_registry(self._state, parent_case_id)

            action_result.add_data({
                "closed_case_id":     str(container_id),
                "closure_timestamp":  close_ts,
                "parent_notified":    parent_notified,
                "resolution_outcome": resolution_outcome,
                "registry_cleaned":   bool(parent_case_id),
            })
            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Child case {container_id} closed (outcome={resolution_outcome}). "
                f"Parent notified: {parent_notified}. "
                f"Registry cleaned: {bool(parent_case_id)}."
            )

        except Exception as exc:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"close_child_case failed: {exc}"
            )

    # ─── Action: get_parent_case ──────────────────────────────────────────────

    def _handle_scan_evidence(self, param):
        """
        Scans the local SOAR Evidence store for items added since the last
        on_poll run. For each new evidence item not yet in the sync registry,
        creates an Evidence Sync Trigger container so the downstream playbook
        can pick it up and sync it to the Parent.

        Also called internally by _handle_on_poll — can be run standalone
        for manual/playbook-driven evidence sync.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        since_ts     = param.get("since_timestamp",
                                  self._state.get("last_poll_timestamp", ""))
        filter_cid   = param.get("container_id")

        token = self._phantom_token()
        self.save_progress(
            f"Scanning Evidence items since {since_ts or 'all time'}..."
        )

        evidence_items = fetch_local_evidence(
            phantom_token=token,
            since_ts=since_ts,
            container_id=int(filter_cid) if filter_cid else None,
        )

        if not evidence_items:
            action_result.add_data({
                "new_evidence_count":     0,
                "triggered_containers":   [],
                "already_synced_count":   0,
            })
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "No new Evidence items found."
            )

        triggered      = []
        already_synced = 0

        for ev in evidence_items:
            ev_id        = str(ev.get("id", ev.get("ID", "")))
            container_id = int(ev.get("container_id", 0))
            vault_id     = ev.get("vault_id", "")
            artifact_id  = ev.get("artifact_id", "")

            # Skip if already in registry
            if is_item_registered(self._state, "evidence", ev_id):
                already_synced += 1
                continue

            # Find parent_case_id from case_mappings for this container
            parent_case_id = ""
            for pcid, mapping in self._state.get("case_mappings", {}).items():
                if mapping.get("local_container_id") == container_id:
                    parent_case_id = pcid
                    break

            if not parent_case_id:
                self.debug_print(
                    f"scan_evidence: no case_mapping for container "
                    f"{container_id}, skipping evidence {ev_id}."
                )
                continue

            # Register as 'syncing' in App State
            self._state = register_sync_item(
                self._state, "evidence", ev_id,
                status="syncing",
                parent_case_id=parent_case_id,
                container_id=container_id,
            )

            # Create Evidence Sync Trigger container
            ev_container = {
                "name":  f"Evidence Sync | {self._child_id} → {parent_case_id}",
                "label": "evidence_sync_trigger",
                "description": (
                    f"New Evidence item ready for sync to Parent case.\n"
                    f"Child: {self._child_id} | Parent: {parent_case_id} | "
                    f"Evidence ID: {ev_id}"
                ),
                "source_data_identifier": f"ev_sync_{self._child_id}_{ev_id}",
                "status":   "new",
                "severity": "low",
                "tags":     ["one_ticketing", "evidence_sync"],
                "custom_fields": {
                    "evidence_id":        ev_id,
                    "vault_id":           vault_id,
                    "artifact_id":        artifact_id,
                    "parent_case_id":     parent_case_id,
                    "local_container_id": container_id,
                    "child_id":           self._child_id,
                },
            }
            ret_val, _msg, cid = self.save_container(ev_container)
            if ret_val:
                # CEF artifact so playbook can read parameters
                self.save_artifact({
                    "container_id": cid,
                    "name": "Evidence Sync Parameters",
                    "label": "evidence_sync_trigger",
                    "source_data_identifier": f"ev_art_{ev_id}",
                    "cef": {
                        "evidence_id":    ev_id,
                        "vault_id":       vault_id,
                        "parent_case_id": parent_case_id,
                        "child_id":       self._child_id,
                        "container_id":   container_id,
                    },
                    "run_automation": True,
                })
                triggered.append({"evidence_id": ev_id, "trigger_container": cid})

        action_result.add_data({
            "new_evidence_count":   len(triggered),
            "triggered_containers": triggered,
            "already_synced_count": already_synced,
        })
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Evidence scan complete: {len(triggered)} new trigger(s) created, "
            f"{already_synced} already synced."
        )

    # ─── Action: request_child_investigation ──────────────────────────────────

    def _handle_request_child_investigation(self, param):
        """
        Parent action: sends a structured investigation task to a specific Child.

        Writes a [TASK:child_id] note to the Parent case. The Child detects this
        note during its next pull_from_parent run, auto-creates a local SOAR case,
        and posts back a [TASK_ACCEPTED:child_id] confirmation note.

        Registers the task in App State as 'pending' until acceptance is confirmed.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        parent_case_id   = param.get("parent_case_id")
        target_child_id  = param.get("target_child_id")
        task_title       = param.get("task_title")
        task_description = param.get("task_description", "")
        severity         = param.get("severity", "medium")
        due_date         = param.get("due_date", "")
        observables_json = param.get("observables", "")   # optional JSON string
        tlp              = _normalize_tlp(param.get("tlp", "") or "TLP.AMBER")

        # Parse observables — accepts a JSON array string or empty string
        observables = []
        if observables_json:
            try:
                parsed = json.loads(observables_json)
                if isinstance(parsed, list):
                    observables = parsed
                else:
                    self.debug_print(
                        "request_child_investigation: observables must be a "
                        "JSON array — ignoring non-list input."
                    )
            except (json.JSONDecodeError, ValueError) as exc:
                self.debug_print(
                    f"request_child_investigation: invalid observables JSON: {exc}"
                )

        self.save_progress(
            f"Sending investigation task to {target_child_id} "
            f"via Parent case {parent_case_id} "
            f"({len(observables)} observable(s))..."
        )

        try:
            # Build structured task note (observables embedded as JSON block)
            task_content = build_task_note(
                child_id=target_child_id,
                task_title=task_title,
                task_description=task_description,
                severity=severity,
                due_date=due_date,
                observables=observables if observables else None,
            )

            # Post note to Parent case
            note_resp    = post_note(self._client, parent_case_id, task_content)
            task_note_id = note_resp.get("id", note_resp.get("comment_id", ""))

            # Register in App State as 'pending'
            self._state = register_pending_task(
                self._state,
                child_id=target_child_id,
                parent_case_id=parent_case_id,
                task_title=task_title,
                task_note_id=str(task_note_id),
            )

            dispatched_at = now_iso()
            action_result.add_data({
                "task_note_id":          task_note_id,
                "parent_case_id":        parent_case_id,
                "target_child_id":       target_child_id,
                "task_status":           "pending",
                "dispatched_observables": len(observables),
                "dispatched_at":         dispatched_at,
                "tlp":                   tlp,
            })
            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Task note posted to Parent case {parent_case_id} "
                f"({len(observables)} observable(s) embedded, TLP={tlp}). "
                f"Waiting for {target_child_id} to accept via pull_from_parent."
            )

        except Exception as exc:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"request_child_investigation failed: {exc}"
            )

    # ─── Internal: evidence scan (shared by on_poll and scan_evidence) ────────

    def _run_scan_evidence_inline(self, since_ts: str) -> dict:
        """
        Core evidence-scan logic extracted from _handle_scan_evidence so that
        on_poll can call it without creating a duplicate ActionResult.

        Returns a summary dict:
          { 'evidence_triggers_created': int, 'already_synced': int }
        """
        token = self._phantom_token()
        evidence_items = fetch_local_evidence(
            phantom_token=token,
            since_ts=since_ts,
        )

        triggered = 0
        already_synced = 0

        for ev in (evidence_items or []):
            ev_id        = str(ev.get("id", ev.get("ID", "")))
            container_id = int(ev.get("container_id", 0))
            vault_id     = ev.get("vault_id", "")
            artifact_id  = ev.get("artifact_id", "")

            if is_item_registered(self._state, "evidence", ev_id):
                already_synced += 1
                continue

            # Find parent_case_id from case_mappings
            parent_case_id = ""
            for pcid, mapping in self._state.get("case_mappings", {}).items():
                if mapping.get("local_container_id") == container_id:
                    parent_case_id = pcid
                    break

            if not parent_case_id:
                self.debug_print(
                    f"_run_scan_evidence_inline: no case_mapping for "
                    f"container {container_id}, skipping evidence {ev_id}."
                )
                continue

            self._state = register_sync_item(
                self._state, "evidence", ev_id,
                status="syncing",
                parent_case_id=parent_case_id,
                container_id=container_id,
            )

            ev_container = {
                "name":  f"Evidence Sync | {self._child_id} → {parent_case_id}",
                "label": "evidence_sync_trigger",
                "description": (
                    f"New Evidence item ready for sync to Parent case.\n"
                    f"Child: {self._child_id} | Parent: {parent_case_id} | "
                    f"Evidence ID: {ev_id}"
                ),
                "source_data_identifier": f"ev_sync_{self._child_id}_{ev_id}",
                "status":   "new",
                "severity": "low",
                "tags":     ["one_ticketing", "evidence_sync"],
                "custom_fields": {
                    "evidence_id":        ev_id,
                    "vault_id":           vault_id,
                    "artifact_id":        artifact_id,
                    "parent_case_id":     parent_case_id,
                    "local_container_id": container_id,
                    "child_id":           self._child_id,
                },
            }
            ret_val, _msg, cid = self.save_container(ev_container)
            if ret_val:
                self.save_artifact({
                    "container_id": cid,
                    "name": "Evidence Sync Parameters",
                    "label": "evidence_sync_trigger",
                    "source_data_identifier": f"ev_art_{ev_id}",
                    "cef": {
                        "evidence_id":    ev_id,
                        "vault_id":       vault_id,
                        "parent_case_id": parent_case_id,
                        "child_id":       self._child_id,
                        "container_id":   container_id,
                    },
                    "run_automation": True,
                })
                triggered += 1

        return {
            "evidence_triggers_created": triggered,
            "already_synced":            already_synced,
        }

    # ─── Action: reply_to_parent ─────────────────────────────────────────────
    #
    # Called by a playbook on the Child when a child_reply artifact is created
    # (by the "Reply to Parent" widget).
    #
    # What it does:
    #   LOCAL (Child):
    #     1. Save new_observables as local artifacts + pre-tag synced-to-parent
    #     2. Tag selected_artifact_ids as synced-to-parent
    #     3. Post a log note: [REPLY_SENT→Parent #X] timestamp + free text
    #     4. Tag the triggering child_reply artifact as reply-sent
    #   REMOTE (Parent via oneticketparent asset):
    #     5. Transfer selected + new observables (deduplicated by source_data_identifier)
    #     6. Post note [CHILD_REPLY:{child_id}] with free text
    #     7. Add tag child-replied to parent container
    #     8. Create child_reply_received notification artifact on parent
    #
    # TODO (loop/polling redesign): if remote calls fail, add to retry queue
    # TODO: handle case where parent_case_id is missing / parent unreachable

    def _handle_reply_to_parent(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        parent_case_id      = param.get("parent_case_id", "").strip()
        container_id        = param.get("container_id", "")
        note_content        = param.get("note_content", "").strip()
        note_title          = param.get("note_title", "").strip()
        selected_ids_str    = param.get("selected_artifact_ids", "").strip()
        new_obs_str         = param.get("new_observables", "").strip()

        # ── Widget-Display-Mode (v1.3.20) ──────────────────────────────────────
        # When called from a playbook without parameters (to activate the widget
        # on the container), return APP_SUCCESS immediately so SOAR renders the
        # custom HTML widget. The widget JS handles everything via direct REST calls.
        # Only validate required fields when note_content is actually provided.
        if not parent_case_id and not note_content:
            action_result.add_data({"mode": "widget_display", "status": "ready"})
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "Reply to Parent widget ready — use the form to compose your reply."
            )

        if not parent_case_id:
            return action_result.set_status(
                phantom.APP_ERROR,
                "reply_to_parent: parent_case_id is required but was empty."
            )
        if not note_content:
            return action_result.set_status(
                phantom.APP_ERROR, "reply_to_parent: note_content is required."
            )

        selected_ids = [s.strip() for s in selected_ids_str.split(",") if s.strip()] \
                       if selected_ids_str else []
        try:
            new_obs = json.loads(new_obs_str) if new_obs_str else []
            if not isinstance(new_obs, list):
                new_obs = []
        except Exception:
            new_obs = []

        token   = self._phantom_token()
        headers = build_local_rest_headers(token) if token else {}
        local_cid = int(container_id) if container_id else 0
        ts = now_iso()
        errors  = []

        # ── 1. Save new_observables locally + pre-tag synced-to-parent ────────
        new_local_art_ids = []
        if _HAS_REQUESTS and token and new_obs:
            for i, obs in enumerate(new_obs):
                if not isinstance(obs, dict) or not obs.get("cef"):
                    continue
                obs_cef = dict(obs.get("cef", {}))
                obs_payload = {
                    "container_id":           local_cid,
                    "name":                   obs.get("name", f"Observable {i+1}"),
                    "label":                  "artifact",
                    "type":                   obs.get("type", "network"),
                    "source_data_identifier": f"ot_reply_{parent_case_id}_{self._child_id}_{i}_{ts[:10]}",
                    "cef":                    obs_cef,
                    "tags":                   [TAG_SYNCED],
                    "run_automation":         False,
                }
                try:
                    resp = _requests.post(
                        f"{SOAR_LOCAL_BASE}/rest/artifact",
                        json=obs_payload, headers=headers,
                        verify=False, timeout=15
                    )
                    if resp.status_code in (200, 201):
                        art_id = resp.json().get("id")
                        if art_id:
                            new_local_art_ids.append(str(art_id))
                    else:
                        errors.append(f"local new obs [{i}]: HTTP {resp.status_code}")
                except Exception as exc:
                    errors.append(f"local new obs [{i}]: {exc}")

        # ── 2. Tag selected artifacts as synced-to-parent ─────────────────────
        if _HAS_REQUESTS and token:
            for art_id in selected_ids:
                try:
                    r = _requests.get(
                        f"{SOAR_LOCAL_BASE}/rest/artifact/{art_id}",
                        headers=headers, verify=False, timeout=10
                    )
                    if r.status_code == 200:
                        existing_tags = list(r.json().get("tags") or [])
                        if TAG_SYNCED not in existing_tags:
                            existing_tags.append(TAG_SYNCED)
                        _requests.post(
                            f"{SOAR_LOCAL_BASE}/rest/artifact/{art_id}",
                            json={"tags": existing_tags},
                            headers=headers, verify=False, timeout=10
                        )
                except Exception as exc:
                    errors.append(f"tag local art {art_id}: {exc}")

        # ── 3. Post log note locally ───────────────────────────────────────────
        n_transferred = len(selected_ids) + len(new_obs)
        log_note = (
            f"[REPLY_SENT→Parent #{parent_case_id}] "
            f"{ts[:16].replace('T', ' ')} — {n_transferred} observable(s) transferred\n\n"
            f"{note_content}"
        )
        try:
            post_note(
                self._client.__class__(self._config)  # dummy — we need local call
                if False else None,  # handled below via direct requests
                parent_case_id, log_note
            )
        except Exception:
            pass
        # Local note via direct requests (self._client points to parent, not local)
        if _HAS_REQUESTS and token and local_cid:
            try:
                note_payload = {
                    "container_id": local_cid,
                    "content":      log_note,
                    "title":        note_title or "Reply sent to Parent",
                    "note_type":    "general",
                }
                _requests.post(
                    f"{SOAR_LOCAL_BASE}/rest/note",
                    json=note_payload, headers=headers,
                    verify=False, timeout=15
                )
                self.save_progress("Local log note created.")
            except Exception as exc:
                errors.append(f"local note: {exc}")

        # ── 4. Tag child_reply artifact as reply-sent ─────────────────────────
        if _HAS_REQUESTS and token and local_cid:
            try:
                r = _requests.get(
                    f"{SOAR_LOCAL_BASE}/rest/artifact",
                    params={
                        "_filter_container_id": local_cid,
                        "_filter_label":        "child_reply",
                        "sort": "id", "order": "desc", "page_size": 1
                    },
                    headers=headers, verify=False, timeout=10
                )
                if r.status_code == 200:
                    data = r.json().get("data", [])
                    if data:
                        reply_art = data[0]
                        reply_tags = list(reply_art.get("tags") or [])
                        if "reply-sent" not in reply_tags:
                            reply_tags.append("reply-sent")
                        _requests.post(
                            f"{SOAR_LOCAL_BASE}/rest/artifact/{reply_art['id']}",
                            json={"tags": reply_tags},
                            headers=headers, verify=False, timeout=10
                        )
            except Exception as exc:
                errors.append(f"tag child_reply artifact: {exc}")

        # ── 5. Transfer observables to parent ─────────────────────────────────
        obs_transferred = 0
        all_ids_to_transfer = selected_ids + new_local_art_ids
        if _HAS_REQUESTS and token and all_ids_to_transfer:
            for art_id in all_ids_to_transfer:
                try:
                    r = _requests.get(
                        f"{SOAR_LOCAL_BASE}/rest/artifact/{art_id}",
                        headers=headers, verify=False, timeout=10
                    )
                    if r.status_code != 200:
                        continue
                    art = r.json()
                    obs_cef = dict(art.get("cef") or {})
                    # Enrich with origin metadata
                    obs_cef["originChildId"]  = self._child_id
                    obs_cef["originCaseId"]   = str(local_cid)
                    obs_cef["transferredAt"]  = ts

                    src_id = f"ot_child_{self._child_id}_{art_id}"
                    # Deduplicate: skip if already on parent
                    try:
                        chk = self._client.get(
                            SOAR_ARTIFACTS_PATH,
                            params={
                                "_filter_source_data_identifier__icontains": src_id,
                                "_filter_container_id": parent_case_id,
                                "page_size": 1,
                            }
                        )
                        if int(chk.get("count", 0)) > 0:
                            self.debug_print(f"reply_to_parent: artifact {art_id} already on parent — skip")
                            continue
                    except Exception:
                        pass

                    parent_art = {
                        "container_id":           int(parent_case_id),
                        "name":                   art.get("name", f"Observable from {self._child_id}"),
                        "label":                  "artifact",
                        "type":                   art.get("type", "network"),
                        "source_data_identifier": src_id,
                        "cef":                    obs_cef,
                        "tags":                   ["from-child"],   # v1.3.18: mark as originated from child
                        "run_automation":         False,
                    }
                    self._client.post(SOAR_ARTIFACTS_PATH, parent_art)
                    obs_transferred += 1
                except Exception as exc:
                    errors.append(f"transfer art {art_id}: {exc}")

        self.save_progress(f"reply_to_parent: {obs_transferred} observable(s) transferred to parent.")

        # ── 6. Post note on parent ─────────────────────────────────────────────
        parent_note_id = None
        try:
            prefix = f"[CHILD_REPLY:{self._child_id}]"
            full_parent_note = f"{prefix}\n\n{note_content}"
            resp = post_note(
                self._client, parent_case_id,
                content=full_parent_note,
                title=note_title or f"Reply from {self._child_id}",
            )
            parent_note_id = resp.get("id")
            self.save_progress("Parent note created.")
        except Exception as exc:
            errors.append(f"parent note: {exc}")

        # ── 7. Add tag child-replied to parent container ───────────────────────
        try:
            cont = self._client.get(
                SOAR_CONTAINER_PATH.format(container_id=parent_case_id)
            )
            p_tags = list(cont.get("tags") or [])
            if "child-replied" not in p_tags:
                p_tags.append("child-replied")
            self._client.post(
                SOAR_CONTAINER_PATH.format(container_id=parent_case_id),
                {"tags": p_tags}
            )
        except Exception as exc:
            self.debug_print(f"reply_to_parent: parent tag update failed (non-fatal): {exc}")

        # ── 8. Create notification artifact on parent (with idempotency guard) ───
        # v1.5.2: before creating, check whether a child_reply_received from this
        # child already exists on the parent case within the last 5 minutes.
        # This prevents duplicate notifications when the action is triggered twice
        # (e.g. due to a second playbook run or a SOAR retry).
        notif_sdi = f"ot_reply_received_{self._child_id}_{ts[:16]}"
        _notif_already_exists = False
        try:
            _dup_check = self._client.get(
                SOAR_ARTIFACTS_PATH,
                params={
                    "_filter_container_id":             parent_case_id,
                    "_filter_label":                    "child_reply_received",
                    "_filter_source_data_identifier":   f'"{notif_sdi}"',
                    "page_size": 1,
                }
            )
            if int(_dup_check.get("count", 0)) > 0:
                _notif_already_exists = True
                self.debug_print(
                    f"reply_to_parent: child_reply_received with SDI '{notif_sdi}' "
                    "already exists on parent — skipping duplicate notification (v1.5.2)."
                )
        except Exception as _dc_exc:
            self.debug_print(f"reply_to_parent: idempotency check failed (non-fatal): {_dc_exc}")

        if not _notif_already_exists:
            try:
                notif_art = {
                    "container_id":           int(parent_case_id),
                    "name":                   f"Reply from {self._child_id}",
                    "label":                  "child_reply_received",
                    "type":                   "network",
                    "source_data_identifier": notif_sdi,
                    "cef": {
                        "childId":          self._child_id,
                        "noteTitle":        note_title or f"Reply from {self._child_id}",
                        "noteContent":      note_content[:500],
                        "observableCount":  obs_transferred,
                        "repliedAt":        ts,
                        "parentCaseId":     parent_case_id,
                        "parentNoteId":     str(parent_note_id) if parent_note_id else "",
                    },
                    "tags":           ["from-child"],
                    "run_automation": True,
                }
                self._client.post(SOAR_ARTIFACTS_PATH, notif_art)
                self.save_progress("Notification artifact created on parent.")
            except Exception as exc:
                errors.append(f"parent notification artifact: {exc}")

        # ── Result ─────────────────────────────────────────────────────────────
        action_result.add_data({
            "parent_case_id":          parent_case_id,
            "child_id":                self._child_id,
            "observables_transferred": obs_transferred,
            "parent_note_id":          parent_note_id,
            "replied_at":              ts,
            "non_fatal_errors":        errors if errors else None,
        })

        if errors:
            self.save_progress(
                f"reply_to_parent completed with {len(errors)} non-fatal error(s). "
                "TODO: add failed items to retry queue — see loop/polling redesign backlog."
            )

        status_msg = (
            f"Reply sent to Parent #{parent_case_id}: "
            f"{obs_transferred} observable(s), 1 note."
        )
        if errors:
            status_msg += f" ({len(errors)} non-fatal error(s) — see debug log)"
        return action_result.set_status(phantom.APP_SUCCESS, status_msg)

    # ─── Action: on_poll ──────────────────────────────────────────────────────


    # ─── Action: start_case_monitor ──────────────────────────────────────────

    def _handle_start_case_monitor(self, param):
        """
        Activates per-case monitoring for a child container.
        Creates a monitor_heartbeat artifact and registers the mapping in
        app state so check_for_parent_updates knows which cases to watch.
        Called automatically by _handle_create_child_case.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id   = int(param.get("container_id", 0) or 0)
        parent_case_id = str(param.get("parent_case_id", "")).strip()
        interval_min   = int(param.get("check_interval_minutes", 5) or 5)

        if not container_id or not parent_case_id:
            return action_result.set_status(
                phantom.APP_ERROR,
                "start_case_monitor: container_id and parent_case_id are required."
            )

        token   = self._phantom_token()
        headers = build_local_rest_headers(token) if token else {}
        ts      = now_iso()
        errors  = []

        # Register in app state
        mappings = self._state.setdefault("case_mappings", {})
        mappings[parent_case_id] = {
            "local_container_id":   container_id,
            "enabled":              True,
            "monitor_active":       True,
            "check_interval_min":   interval_min,
            "last_check":           ts,
            "started_at":           ts,
            "sync_direction":       "both",
        }

        # Create monitor_heartbeat artifact on the child container
        heartbeat_art_id = None
        if _HAS_REQUESTS and token:
            sdi = f"ot_monitor_heartbeat_{container_id}"
            # Check if heartbeat already exists (idempotent)
            try:
                r = _requests.get(
                    f"{SOAR_LOCAL_BASE}/rest/artifact",
                    params={
                        "_filter_container_id":          container_id,
                        "_filter_label":                 "monitor_heartbeat",
                        "_filter_source_data_identifier__icontains": f"ot_monitor_heartbeat_{container_id}",
                        "page_size": 1,
                    },
                    headers=headers, verify=False, timeout=10
                )
                if r.status_code == 200:
                    existing = r.json().get("data", [])
                    if existing:
                        heartbeat_art_id = existing[0]["id"]
            except Exception:
                pass

            payload = {
                "container_id":           container_id,
                "name":                   "OneTicketing Monitor Heartbeat",
                "label":                  "monitor_heartbeat",
                "type":                   "network",
                "source_data_identifier": sdi,
                "cef": {
                    "monitorActive":        "true",
                    "parentCaseId":         parent_case_id,
                    "checkIntervalMinutes": str(interval_min),
                    "lastCheck":            ts,
                    "startedAt":            ts,
                },
                "tags":           ["monitor"],
                "run_automation": False,
            }
            try:
                method = "POST"
                url    = f"{SOAR_LOCAL_BASE}/rest/artifact"
                if heartbeat_art_id:
                    method = "POST"  # SOAR uses POST for update with existing ID too
                    url    = f"{SOAR_LOCAL_BASE}/rest/artifact/{heartbeat_art_id}"
                resp = _requests.post(url, json=payload, headers=headers,
                                      verify=False, timeout=15)
                if resp.status_code in (200, 201):
                    heartbeat_art_id = resp.json().get("id") or heartbeat_art_id
                else:
                    errors.append(f"heartbeat artifact: HTTP {resp.status_code}")
            except Exception as exc:
                errors.append(f"heartbeat artifact: {exc}")

        action_result.add_data({
            "container_id":        container_id,
            "parent_case_id":      parent_case_id,
            "heartbeat_artifact_id": heartbeat_art_id,
            "check_interval_min":  interval_min,
            "started_at":          ts,
            "errors":              "; ".join(errors) if errors else "",
        })
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Monitor started for container {container_id} ↔ parent {parent_case_id} "
            f"(interval: {interval_min}min). Heartbeat artifact: {heartbeat_art_id}."
        )

    # ─── Action: check_for_parent_updates ────────────────────────────────────

    def _update_heartbeat_last_check(self, container_id, parent_case_id, ts, headers):
        """Update lastCheck + lastCheckParentId in the monitor_heartbeat artifact."""
        try:
            r = _requests.get(
                f"{SOAR_LOCAL_BASE}/rest/artifact",
                params={
                    "_filter_container_id": container_id,
                    "_filter_label":        "monitor_heartbeat",
                    "page_size": 1,
                },
                headers=headers, verify=False, timeout=10
            )
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    art = data[0]
                    cef = dict(art.get("cef") or {})
                    cef["lastCheck"]          = ts
                    cef["lastCheckParentId"]  = parent_case_id
                    _requests.post(
                        f"{SOAR_LOCAL_BASE}/rest/artifact/{art['id']}",
                        json={"cef": cef},
                        headers=headers, verify=False, timeout=10
                    )
        except Exception:
            pass

    def _deactivate_monitor(self, parent_case_id, child_cid, token, headers):
        """Mark monitor inactive in app state and heartbeat artifact."""
        mappings = self._state.get("case_mappings", {})
        if parent_case_id in mappings:
            mappings[parent_case_id]["monitor_active"] = False
            mappings[parent_case_id]["stopped_at"]     = now_iso()
        if not token or not _HAS_REQUESTS:
            return
        try:
            r = _requests.get(
                f"{SOAR_LOCAL_BASE}/rest/artifact",
                params={
                    "_filter_container_id": child_cid,
                    "_filter_label":        "monitor_heartbeat",
                    "page_size": 1,
                },
                headers=headers, verify=False, timeout=10
            )
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    art = data[0]
                    cef = dict(art.get("cef") or {})
                    cef["monitorActive"] = "false"
                    cef["stoppedAt"]     = now_iso()
                    _requests.post(
                        f"{SOAR_LOCAL_BASE}/rest/artifact/{art['id']}",
                        json={"cef": cef},
                        headers=headers, verify=False, timeout=10
                    )
        except Exception:
            pass

    # ─── Action: stop_case_monitor ───────────────────────────────────────────

    def _handle_stop_case_monitor(self, param):
        """
        Deactivates monitoring for a child container.
        Sets monitorActive=false in the heartbeat artifact and app state.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id   = param.get("container_id")
        parent_case_id = str(param.get("parent_case_id", "")).strip()

        token   = self._phantom_token()
        headers = build_local_rest_headers(token) if token else {}
        ts      = now_iso()

        # Resolve container_id from parent_case_id if not given
        if not container_id and parent_case_id:
            mapping = self._state.get("case_mappings", {}).get(parent_case_id, {})
            container_id = mapping.get("local_container_id")

        if not container_id:
            return action_result.set_status(
                phantom.APP_ERROR,
                "stop_case_monitor: provide container_id or parent_case_id."
            )
        container_id = int(container_id)

        # Resolve parent_case_id from app state if not given
        if not parent_case_id:
            for pid, m in self._state.get("case_mappings", {}).items():
                if int(m.get("local_container_id", 0)) == container_id:
                    parent_case_id = pid
                    break

        self._deactivate_monitor(parent_case_id or "", container_id, token, headers)

        action_result.add_data({
            "container_id":  container_id,
            "parent_case_id": parent_case_id or "",
            "stopped_at":    ts,
        })
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Monitor stopped for container {container_id} "
            f"(parent: {parent_case_id or 'unknown'})."
        )

    def handle_action(self, param):
        action_id = self.get_action_identifier()

        handlers = {
            "test_connectivity":         self._handle_test_connectivity,
            "create_child_case":         self._handle_create_child_case,
            "update_child_case":         self._handle_update_child_case,
            "get_children_status":       self._handle_get_children_status,
            "update_case_status":        self._handle_update_case_status,
            "close_child_case":          self._handle_close_child_case,
            "scan_evidence":             self._handle_scan_evidence,
            "request_child_investigation": self._handle_request_child_investigation,
            "reply_to_parent":           self._handle_reply_to_parent,
            "start_case_monitor":        self._handle_start_case_monitor,
            "stop_case_monitor":         self._handle_stop_case_monitor,
        }

        handler = handlers.get(action_id)
        if handler:
            return handler(param)

        self.debug_print(f"Unknown action_id: {action_id}")
        return phantom.APP_SUCCESS


# ─── CLI entry point for local testing ───────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: phenv python3 one_ticketing_connector.py <test_json_file>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        in_json = json.loads(f.read())

    connector = OneTicketingConnector()
    connector.print_progress_message = True

    ret_val = connector.handle_action(json.dumps(in_json), None)

    print(json.dumps(json.loads(connector.get_action_results()), indent=4))
    sys.exit(0 if phantom.APP_SUCCESS == ret_val else 1)
