# -*- coding: utf-8 -*-
# Copyright 2026 Andreas Buis
#
# one_ticketing_view.py
# Custom widget context builders for the SOAR Investigation panel.
# v1.3.6: widget uses LocMemLoader injection instead of filesystem patching
# v1.3.10: wrap template in .widget-body>.scoller so load_widget_content()
#          finds content; use document (not window.parent) for toolbar injection
# v1.3.11: fix action_run payload — use container_id at top level + assets list
# v1.4.4: display_get_children_status enriched with TLP badge, escalation flag,
#         assigned_user, artifact_count, child_url; create_child_task.html now
#         loaded from disk (TLP selector + active children table added)

import json
import os

import phantom.app as phantom


# ---------------------------------------------------------------------------
# Inline HTML for the status/connectivity sidebar view (one_ticketing_view.html).
# Loaded from disk once at import time and injected via _ensure_locmem_template
# so Django can find it regardless of SOAR's template search path.
# ---------------------------------------------------------------------------
_VIEW_HTML = open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "one_ticketing_view.html"),
    encoding="utf-8"
).read() if os.path.exists(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "one_ticketing_view.html")
) else "<div style='padding:12px;color:#c00'>one_ticketing_view.html not found.</div>"

# ---------------------------------------------------------------------------
# Inline HTML fragment for the "Create Child Task" widget.
# Stored here so the widget works even if the on-disk template file is missing
# or Django's template search path doesn't include the app directory.
# ---------------------------------------------------------------------------
_CREATE_CHILD_TASK_HTML = open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "widgets", "create_child_task.html"),
    encoding="utf-8"
).read() if os.path.exists(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "widgets", "create_child_task.html")
) else "<div>Create Child Task widget not found.</div>"


def _ensure_locmem_template(template_name, html_content):
    """
    Register html_content in Django's LocMemLoader so it can be found by
    template_name without any filesystem lookup.

    Strategy:
      1. For every Django engine, walk both the engine's direct loaders AND
         sub-loaders inside any CachedLoader wrappers.
      2. If a LocMemLoader already exists, update its templates_dict.
      3. If not, prepend a new LocMemLoader so it is tried first.
      4. Clear any negative-cache entries for template_name.

    Idempotent — safe to call on every widget request.
    """
    try:
        from django.template import engines
        try:
            from django.template.loaders.locmem import Loader as LocMemLoader
        except ImportError:
            return  # very old Django – bail out gracefully

        for alias in list(engines):
            try:
                engine    = engines[alias]
                inner     = getattr(engine, "engine", None)
                if inner is None:
                    continue

                # --- Walk every loader level: direct + wrapped sub-loaders ---
                loader_containers = [(inner, "template_loaders")]
                for ldr in list(inner.template_loaders):
                    if getattr(ldr, "loaders", None) is not None:
                        loader_containers.append((ldr, "loaders"))

                for parent_obj, attr_name in loader_containers:
                    loader_list = list(getattr(parent_obj, attr_name, []))

                    # Find existing LocMemLoader
                    locmem = next(
                        (l for l in loader_list if isinstance(l, LocMemLoader)),
                        None,
                    )
                    if locmem is not None:
                        locmem.templates_dict[template_name] = html_content
                    else:
                        new_ldr = LocMemLoader(inner, {template_name: html_content})
                        loader_list.insert(0, new_ldr)
                        setattr(parent_obj, attr_name, loader_list)

                # --- Clear negative caches for this template name ---
                for ldr in inner.template_loaders:
                    for ca in ("template_cache", "_cache", "get_contents_cache"):
                        cache = getattr(ldr, ca, None)
                        if isinstance(cache, dict):
                            for k in [k for k in cache if template_name in str(k)]:
                                del cache[k]
                    for sub in getattr(ldr, "loaders", []):
                        for ca in ("template_cache", "_cache", "get_contents_cache"):
                            cache = getattr(sub, ca, None)
                            if isinstance(cache, dict):
                                for k in [k for k in cache if template_name in str(k)]:
                                    del cache[k]

            except Exception:
                continue
    except Exception:
        pass


def _register_app_template_dir():
    """
    Legacy helper: patch Django's FileSystemLoader dirs to include this app's
    directory.  Kept for the other two view functions that still use a
    template file (one_ticketing_view.html).
    """
    app_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        from django.template import engines
        for alias in list(engines):
            try:
                engine = engines[alias]
                inner  = getattr(engine, "engine", None)
                if inner is None:
                    continue
                for loader in inner.template_loaders:
                    for ca in ("get_contents_cache", "template_cache", "_cache"):
                        cache = getattr(loader, ca, None)
                        if isinstance(cache, dict):
                            cache.clear()
                    if hasattr(loader, "dirs") and app_dir not in loader.dirs:
                        loader.dirs = list(loader.dirs) + [app_dir]
                    for sub in getattr(loader, "loaders", []):
                        for ca in ("get_contents_cache", "template_cache", "_cache"):
                            cache = getattr(sub, ca, None)
                            if isinstance(cache, dict):
                                cache.clear()
                        if hasattr(sub, "dirs") and app_dir not in sub.dirs:
                            sub.dirs = list(sub.dirs) + [app_dir]
            except Exception:
                continue
    except Exception:
        pass


def display_get_children_status(provides, all_app_runs, context):
    """
    Widget for the 'get children status' action.
    Renders a status dashboard showing all Child instances with
    live reachability, case status, severity and last sync time.
    """
    context["results"] = []

    for _summary, action_results in all_app_runs:
        for result in action_results:
            data_list = result.get_data()
            if not data_list:
                continue

            # Compute summary counters (v1.5.3: New/Open/Closed — no In Progress)
            total      = len(data_list)
            reachable  = sum(1 for d in data_list if d.get("reachable"))
            closed     = sum(1 for d in data_list if d.get("status") == "closed")
            open_cases = sum(1 for d in data_list if d.get("status") == "open")
            new_cases  = sum(1 for d in data_list if d.get("status") in ("new", "")
                             or not d.get("status"))

            # Severity colour mapping
            severity_colours = {
                "critical": "#dc3545",
                "high":     "#fd7e14",
                "medium":   "#ffc107",
                "low":      "#28a745",
                "unknown":  "#6c757d",
            }

            children = []
            for d in data_list:
                sev = d.get("severity", "unknown").lower()
                tlp = d.get("tlp", "")
                # CSS key: "TLP.AMBER" → "amber", anything else → "unknown"
                tlp_key = (
                    tlp.replace("TLP.", "").lower()
                    if tlp and tlp.upper().startswith("TLP.")
                    else "unknown"
                )
                child = {
                    "child_id":       d.get("child_id", ""),
                    "child_case_id":  d.get("child_case_id", ""),
                    "case_title":     d.get("case_title", ""),    # v1.5.3
                    "status":         d.get("status", "new") or "new",
                    "severity":       sev,
                    "sev_colour":     severity_colours.get(sev, "#6c757d"),
                    "last_sync":      d.get("last_sync", "never"),
                    "findings_count": d.get("findings_count", 0),
                    "reachable":      d.get("reachable", False),
                    "reachable_icon": "✅" if d.get("reachable") else "❌",
                    # v1.4.4
                    "tlp":            tlp,
                    "tlp_key":        tlp_key,
                    "assigned_user":  d.get("assigned_user", ""),
                    "artifact_count": d.get("artifact_count", 0),
                    "child_url":      d.get("child_url", ""),
                    "tlp_escalated":  d.get("tlp_escalated", False),
                }
                children.append(child)

            # Use the retrieved_at from the last child entry (all share the same run time)
            retrieved_at = data_list[-1].get("retrieved_at", "") if data_list else ""

            context["results"].append({
                "children":     children,
                "retrieved_at": retrieved_at,
                "summary": {
                    "total":       total,
                    "reachable":   reachable,
                    "unreachable": total - reachable,
                    "new":         new_cases,
                    "open":        open_cases,
                    "closed":      closed,
                },
                "param":   result.get_param(),
            })

    # v1.5.17: Render create_child_task.html instead of one_ticketing_view.html.
    # When the Refresh button triggers a new get_children_status action_run, SOAR
    # automatically switches to that run's result widget. Previously this caused SOAR
    # to render one_ticketing_view.html (the old static table), losing all toolbar
    # buttons and the modern sidebar. By returning create_child_task.html here, the
    # full modern widget is displayed regardless of which action triggered the view
    # switch — and the widget JS re-initialises toolbar buttons and sidebar on load.
    _ensure_locmem_template("widgets/create_child_task.html", _CREATE_CHILD_TASK_HTML)
    return "widgets/create_child_task.html"


def display_check_parent_connectivity(provides, all_app_runs, context):
    """
    Widget for the 'check parent connectivity' action.
    Shows a connectivity health card with latency, queue depth and last sync.
    """
    context["connectivity"] = []

    for _summary, action_results in all_app_runs:
        for result in action_results:
            data_list = result.get_data()
            if not data_list:
                continue

            d = data_list[0]
            reachable  = d.get("reachable", False)
            latency    = d.get("latency_ms", -1)
            queue_depth = d.get("queue_depth", 0)
            last_sync  = d.get("last_successful_sync", "never")
            checked_at = d.get("checked_at", "")

            # Latency classification
            if latency < 0:
                latency_class = "danger"
                latency_label = "N/A"
            elif latency < 200:
                latency_class = "success"
                latency_label = f"{latency} ms"
            elif latency < 1000:
                latency_class = "warning"
                latency_label = f"{latency} ms"
            else:
                latency_class = "danger"
                latency_label = f"{latency} ms"

            context["connectivity"].append({
                "reachable":     reachable,
                "status_icon":   "🟢" if reachable else "🔴",
                "status_label":  "ONLINE" if reachable else "OFFLINE",
                "status_class":  "success" if reachable else "danger",
                "latency_ms":    latency,
                "latency_label": latency_label,
                "latency_class": latency_class,
                "queue_depth":   queue_depth,
                "queue_class":   "danger" if queue_depth > 10 else
                                  "warning" if queue_depth > 0 else "success",
                "last_sync":     last_sync,
                "checked_at":    checked_at,
                "param":         result.get_param(),
            })

    _ensure_locmem_template("one_ticketing_view.html", _VIEW_HTML)
    return "one_ticketing_view.html"


# ─── View / Widget: Create Child Task ─────────────────────────────────────────
#
# Pattern (Phantom Bag of Tricks style):
#   The JS injects a "📋 Create Child Task" button into the container toolbar.
#   Clicking opens a modal overlay with:
#     - Child ID input, Task title + description, Severity selector, Due date
#     - Dynamic observable rows (CEF field picker + value, + / ✕ buttons)
#   On submit the JS serialises observables as JSON and fires
#   request_child_investigation via /rest/action_run.
#
# Activation:
#   Add to one_ticketing.json action render block:
#     "render": { "type": "custom",
#                 "view": "one_ticketing_view.display_create_child_task_widget" }

_CEF_FIELDS = [
    "sourceAddress", "destinationAddress", "domainName", "requestURL",
    "fileHashMd5", "fileHashSha1", "fileHashSha256",
    "emailAddress", "fileName", "filePath",
    "sourcePort", "destinationPort", "userAgent", "subject",
]


def display_create_child_task_widget(provides, all_app_runs, context):
    """
    Renders the 'Create Child Task' widget.

    Injects the widget HTML directly into Django's LocMemLoader so it is
    found under "widgets/create_child_task.html" without any filesystem
    lookup.  This is the most reliable approach for old-style SOAR apps
    where SOAR does not add the app directory to Django's template search
    path automatically.
    """
    _ensure_locmem_template("widgets/create_child_task.html", _CREATE_CHILD_TASK_HTML)
    return "widgets/create_child_task.html"


def get_create_child_task_html(cef_fields=None):
    """
    Returns a self-contained HTML + JS string for the Create Child Task overlay.

    The form collects target_child_id, task_title, task_description, severity,
    due_date and dynamic observable rows. On submit it calls /rest/action_run
    with action=request_child_investigation and observables serialised as JSON.
    The Child CERT never sees raw JSON — pull_from_parent converts the embedded
    block into proper SOAR Artifacts automatically.
    """
    fields      = cef_fields if cef_fields else _CEF_FIELDS
    fields_json = json.dumps(fields)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  #ot-widget-btn{{background:#005a8e;color:#fff;border:none;padding:6px 14px;
    border-radius:4px;cursor:pointer;font-size:13px;margin:8px 0}}
  #ot-widget-btn:hover{{background:#003f6b}}
  #ot-overlay{{display:none;position:fixed;top:0;left:0;width:100%;height:100%;
    background:rgba(0,0,0,.55);z-index:9999;align-items:center;justify-content:center}}
  #ot-modal{{background:#1e2126;color:#cdd;border-radius:8px;padding:24px;
    width:560px;max-height:90vh;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.6)}}
  #ot-modal h3{{margin:0 0 16px;color:#fff;font-size:16px}}
  #ot-modal label{{display:block;font-size:12px;color:#aaa;margin:12px 0 4px}}
  #ot-modal input,#ot-modal textarea,#ot-modal select{{width:100%;box-sizing:border-box;
    background:#2a2f3a;border:1px solid #444;color:#eee;padding:6px 8px;
    border-radius:4px;font-size:13px}}
  #ot-modal textarea{{height:80px;resize:vertical}}
  .ot-obs-row{{display:flex;gap:6px;align-items:center;margin-bottom:6px}}
  .ot-obs-row select{{flex:0 0 190px}}.ot-obs-row input{{flex:1}}
  .ot-obs-rm{{background:#555;color:#fff;border:none;padding:4px 8px;
    border-radius:3px;cursor:pointer}}
  #ot-add-obs{{background:#2a5;color:#fff;border:none;padding:4px 12px;
    border-radius:3px;cursor:pointer;font-size:16px;margin-top:4px}}
  .ot-footer{{display:flex;gap:8px;justify-content:flex-end;margin-top:20px}}
  .ot-btn-cancel{{background:#444;color:#eee;border:none;padding:7px 18px;
    border-radius:4px;cursor:pointer}}
  .ot-btn-submit{{background:#005a8e;color:#fff;border:none;padding:7px 18px;
    border-radius:4px;cursor:pointer}}
  .ot-btn-submit:disabled{{opacity:.5;cursor:not-allowed}}
  #ot-status{{margin-top:10px;font-size:12px;min-height:16px}}
</style>
</head>
<body>
<button id="ot-widget-btn">&#x1F4CB; Create Child Task</button>
<div id="ot-overlay">
 <div id="ot-modal">
  <h3>&#x1F4CB; Create Child Investigation Task</h3>
  <label>Target Child ID *</label>
  <input id="ot-child" type="text" placeholder="e.g. CERT_NO_OT">
  <label>Task Title *</label>
  <input id="ot-title" type="text" placeholder="Short title">
  <label>Description *</label>
  <textarea id="ot-desc" placeholder="Scope and context for the Child CERT..."></textarea>
  <label>Severity *</label>
  <select id="ot-sev">
   <option value="low">Low</option>
   <option value="medium" selected>Medium</option>
   <option value="high">High</option>
   <option value="critical">Critical</option>
  </select>
  <label>Due Date (optional)</label>
  <input id="ot-due" type="date">
  <label>Observables / IOCs</label>
  <div id="ot-obs-list"></div>
  <button id="ot-add-obs" title="Add observable">+</button>
  <div class="ot-footer">
   <button class="ot-btn-cancel" id="ot-cancel">Cancel</button>
   <button class="ot-btn-submit" id="ot-submit">Dispatch Task</button>
  </div>
  <div id="ot-status"></div>
 </div>
</div>
<script>
(function(){{
  var CEF={fields_json};
  function mkRow(){{
    var row=document.createElement('div');row.className='ot-obs-row';
    var sel=document.createElement('select');
    CEF.forEach(function(f){{var o=document.createElement('option');o.value=f;o.textContent=f;sel.appendChild(o);}});
    var inp=document.createElement('input');inp.type='text';inp.placeholder='indicator value';
    var rm=document.createElement('button');rm.className='ot-obs-rm';rm.textContent='X';
    rm.onclick=function(){{row.remove();}};
    row.appendChild(sel);row.appendChild(inp);row.appendChild(rm);
    return row;
  }}
  function collectObs(){{
    var rows=document.querySelectorAll('#ot-obs-list .ot-obs-row'),obs=[];
    rows.forEach(function(row){{
      var f=row.querySelector('select').value,v=row.querySelector('input').value.trim();
      if(v) obs.push({{name:f+': '+v,type:'indicator',cef:{{[f]:v}}}});
    }});
    return obs;
  }}
  document.getElementById('ot-widget-btn').onclick=function(){{
    document.getElementById('ot-overlay').style.display='flex';
  }};
  document.getElementById('ot-cancel').onclick=function(){{
    document.getElementById('ot-overlay').style.display='none';
    document.getElementById('ot-status').textContent='';
  }};
  document.getElementById('ot-add-obs').onclick=function(e){{
    e.preventDefault();document.getElementById('ot-obs-list').appendChild(mkRow());
  }};
  document.getElementById('ot-submit').onclick=function(){{
    var child=document.getElementById('ot-child').value.trim();
    var title=document.getElementById('ot-title').value.trim();
    var desc=document.getElementById('ot-desc').value.trim();
    var sev=document.getElementById('ot-sev').value;
    var due=document.getElementById('ot-due').value;
    var obs=collectObs();
    var st=document.getElementById('ot-status');
    if(!child||!title||!desc){{st.textContent='Child ID, Title and Description are required.';return;}}
    var btn=document.getElementById('ot-submit');btn.disabled=true;
    st.textContent='Dispatching...';
    var m=window.location.pathname.match(/\\/mission\\/(\\d+)/);
    var cid=m?m[1]:'';
    fetch('/rest/action_run',{{method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{action:'request child investigation',
        targets:[{{type:'container',id:parseInt(cid,10)}}],
        parameters:[{{parent_case_id:cid,target_child_id:child,task_title:title,
          task_description:desc,severity:sev,
          due_date:due?due+'T00:00:00Z':'',
          observables:JSON.stringify(obs)}}]}})
    }})
    .then(function(r){{return r.json();}})
    .then(function(d){{
      if(d.id||d.action_run_id){{
        st.textContent='Task dispatched!';
        setTimeout(function(){{
          document.getElementById('ot-overlay').style.display='none';
          st.textContent='';btn.disabled=false;
        }},1800);
      }}else{{st.textContent='Error: '+JSON.stringify(d);btn.disabled=false;}}
    }})
    .catch(function(e){{st.textContent=e.message;btn.disabled=false;}});
  }};
}})();
</script>
</body>
</html>"""


# ─── View / Widget: Reply to Parent ───────────────────────────────────────────
#
# This widget is the Child-side counterpart to create_child_task.
# It renders on both Parent and Child instances; the JS detects context by
# checking for a "Parent Case Reference" artifact in the container.
# If found  → child mode: injects "↩ Reply to Parent" toolbar button
# If absent → parent mode: nothing injected (the create_child_task widget
#             handles the Parent side, including reply notifications).
#
# Widget also adds a notification banner in create_child_task for received replies.
# The banner reads child_reply_received artifacts from /rest/artifact.

def display_reply_to_parent_widget(provides, all_app_runs, context):
    """
    Renders the 'Reply to Parent' widget.
    Registered as the render view for the dummy 'reply_to_parent' action.
    On load the embedded JS detects whether a Parent Case Reference artifact
    exists in the container; if yes it injects the Reply toolbar button.
    """
    _ensure_locmem_template("widgets/reply_to_parent.html", _REPLY_TO_PARENT_HTML)
    return "widgets/reply_to_parent.html"


# The HTML is loaded from the on-disk template file.
# _REPLY_TO_PARENT_HTML is kept as a fallback in case the filesystem template
# is unavailable (mirrors the pattern used by _CREATE_CHILD_TASK_HTML).
# Content is identical to widgets/reply_to_parent.html — updated together.
_REPLY_TO_PARENT_HTML = open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "widgets", "reply_to_parent.html"),
    encoding="utf-8"
).read() if os.path.exists(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "widgets", "reply_to_parent.html")
) else "<div>Reply to Parent widget not found.</div>"
