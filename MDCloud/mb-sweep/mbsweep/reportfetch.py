"""
Reading results back: scan payloads and sandbox reports.

Turns raw API responses into the normalised shapes the
reports consume. Every function here is a single
non-blocking read: the poller owns all the waiting.
"""

import json
from collections import defaultdict

import requests

from .config import MDC_BASE_URL


def file_scan_finished(api_key, data_id):
    """
    Return the /v4/file payload if the scan has finished, else None.

    Deliberately a single non-blocking check: the poller owns the waiting, so
    this must never sit in a loop of its own.
    """
    try:
        resp = requests.get(f"{MDC_BASE_URL}/file/{data_id}",
                            headers={"apikey": api_key}, timeout=60)
        if resp.status_code != 200:
            return None
        payload = resp.json()
    except (requests.RequestException, json.JSONDecodeError):
        return None

    progress = (payload.get("scan_results") or {}).get("progress_percentage", 0)
    return payload if progress >= 100 else None


def mdc_walk_chain(api_key, sandbox_id, depth=0, seen=None):
    """
    Walk a sandbox report and all of its descendants.

    An archive submission produces a *parent* report for the container plus
    child reports for what was extracted, linked by
    ``reports.next_level[]``. The container itself is inert, so the parent's
    verdict is meaningless on its own - the real finding is somewhere below
    it. Returns a flat list of nodes, each with its depth.
    """
    seen = seen if seen is not None else set()
    if sandbox_id in seen or depth > 8:
        return []
    seen.add(sandbox_id)

    resp = requests.get(f"{MDC_BASE_URL}/sandbox/{sandbox_id}",
                        headers={"apikey": api_key})
    if resp.status_code != 200:
        return []
    meta = resp.json()

    node = {
        "sandbox_id": sandbox_id,
        "depth": depth,
        "sha256": (meta.get("sha256") or "").lower(),
        "verdict": (meta.get("final_verdict") or {}).get("verdict"),
        "threat_level": (meta.get("final_verdict") or {}).get("threatLevel"),
        "report_url": (meta.get("full_report") or {}).get("json"),
    }
    nodes = [node]
    for child in (meta.get("reports") or {}).get("next_level") or []:
        nodes.extend(mdc_walk_chain(api_key, child, depth + 1, seen))
    return nodes


def mdc_report_summary(api_key, report_url):
    """
    Fetch a sandbox report and pull out everything the product team needs.

    Returns the behavioural detail, not just counts: the signal groups that
    produced the verdict, YARA hits, tags, MITRE techniques and the IOCs,
    grouped by type. This is the material an engine team acts on when a
    known-bad sample scores lower than expected.
    """
    empty = {"signal_groups": [], "yara": [], "mdc_tags": [], "mitre": {},
             "iocs_by_type": {}, "ioc_count": 0}
    try:
        resp = requests.get(report_url, headers={"apikey": api_key}, timeout=180)
        if resp.status_code != 200:
            return empty
        document = resp.json()
    except (requests.RequestException, json.JSONDecodeError):
        return empty

    overview = document.get("overview_report") or {}

    # Signal groups, strongest first - the "why" behind the verdict.
    groups = []
    for group in overview.get("signal_groups") or []:
        strengths = [float(s.get("strength") or 0.0)
                     for s in group.get("signals") or []]
        groups.append({
            "description": group.get("description") or "(no description)",
            "verdict": group.get("verdict") or "UNKNOWN",
            "peak_strength": max(strengths) if strengths else 0.0,
            "signal_count": len(strengths),
        })
    groups.sort(key=lambda g: (-g["peak_strength"], g["description"]))

    yara = [{
        "rule": y.get("rule_name") or "(unnamed)",
        "verdict": y.get("verdict") or "UNKNOWN",
        "description": y.get("rule_description") or "",
    } for y in overview.get("yara_matches") or []]

    # IOCs arrive as a list of lists, one per analysed sub-file, so the same
    # indicator repeats and has to be de-duplicated.
    iocs_by_type = defaultdict(set)
    for sublist in overview.get("iocs") or []:
        for ioc in sublist or []:
            if ioc.get("data"):
                iocs_by_type[ioc.get("type_display_name")
                             or ioc.get("type") or "unknown"].add(ioc["data"])
    iocs_by_type = {k: sorted(v) for k, v in iocs_by_type.items()}

    # MITRE mappings live in the inner report, which is a JSON *string*.
    mitre = {}
    inner = document.get("full_report")
    if isinstance(inner, str):
        try:
            inner = json.loads(inner)
        except json.JSONDecodeError:
            inner = {}
    if isinstance(inner, dict):
        for pattern in (inner.get("summary") or {}).get("behaviorPatterns") or []:
            for technique in pattern.get("MITRETechniques") or []:
                if technique.get("ID"):
                    mitre[technique["ID"]] = technique.get("name") or ""

    tags = [t.get("name") for t in overview.get("tags") or [] if t.get("name")]
    return {
        "signal_groups": groups,
        "yara": yara,
        "mdc_tags": tags or (overview.get("unique_tags") or []),
        "mitre": dict(sorted(mitre.items())),
        "iocs_by_type": iocs_by_type,
        "ioc_count": sum(len(v) for v in iocs_by_type.values()),
    }


def collect_av(scan_payload, api_key=None):
    """
    Normalise the per-engine multiscan view from ``scan_results``.

    Archives need care. Malware arrives inside an encrypted container, and the
    container itself is clean - so the top level reports
    ``scan_all_result_a: "Infected"`` (aggregated from what was extracted) while
    ``total_detected_avs`` is 0 and every engine row is empty. Reading only the
    top level therefore produces the contradiction "Infected - 0 of 12
    engines". The real numbers are on the extracted child, in
    ``extracted_files.files_in_archive[]``, where ``detected_by`` is the engine
    count; the per-engine threat names come from fetching that child's own
    scan.

    ``scanned`` distinguishes "the engines ran and found nothing" from "no AV
    pass happened", which are very different results on a known-bad sample.
    """
    payload = scan_payload or {}
    results = payload.get("scan_results") or {}

    engines = _engine_rows(results.get("scan_details"))
    detected = results.get("total_detected_avs") or 0
    total = results.get("total_avs") or 0
    overall = results.get("scan_all_result_a")
    from_extracted = ""

    # Container clean but the archive's contents may not be.
    children = ((payload.get("extracted_files") or {})
                .get("files_in_archive") or [])
    if detected == 0 and children:
        worst = max(children, key=lambda c: c.get("detected_by") or 0)
        child_detected = worst.get("detected_by") or 0
        if child_detected > 0:
            detected = child_detected
            from_extracted = worst.get("display_name") or worst.get("sha256", "")
            child_engines, child_total = _fetch_child_engines(
                api_key, worst.get("data_id"))
            if child_engines:
                engines = child_engines
            if child_total:
                total = child_total

    return {
        "overall": overall,
        "detected": detected,
        "total": total,
        "engines": engines,
        # True when engines actually ran against something.
        "scanned": bool(total) and (overall or "") != "Not Scanned",
        # Set when the numbers describe a file extracted from the submission.
        "from_extracted": from_extracted,
    }


def _engine_rows(scan_details):
    """Flatten scan_details into a sorted list, detections first."""
    engines = []
    for name, entry in (scan_details or {}).items():
        engines.append({
            "engine": name,
            "threat": (entry or {}).get("threat_found") or "",
            "code": (entry or {}).get("scan_result_i"),
            "def_time": ((entry or {}).get("def_time") or "")[:10],
        })
    engines.sort(key=lambda e: (not e["threat"], e["engine"].lower()))
    return engines


def _fetch_child_engines(api_key, data_id):
    """Fetch an extracted file's own scan, for the per-engine threat names."""
    if not api_key or not data_id:
        return [], 0
    try:
        resp = requests.get(f"{MDC_BASE_URL}/file/{data_id}",
                            headers={"apikey": api_key}, timeout=60)
        if resp.status_code != 200:
            return [], 0
        results = (resp.json().get("scan_results") or {})
    except (requests.RequestException, ValueError):
        return [], 0
    return _engine_rows(results.get("scan_details")), results.get("total_avs") or 0


def collect_cdr(scan_payload):
    """
    Normalise the Deep CDR view from ``process_info`` and ``sanitized``.

    ``sanitization_details.details[]`` is the valuable part: one entry per
    class of active content removed, naming the objects and where they sat.
    """
    payload = scan_payload or {}
    process = payload.get("process_info") or {}
    post = process.get("post_processing") or {}
    sanitized = payload.get("sanitized") or {}

    details = post.get("sanitization_details")
    description, objects = "", []
    if isinstance(details, dict):
        description = details.get("description") or ""
        if isinstance(details.get("details"), list):
            objects = details["details"]
    elif isinstance(details, str):
        description = details

    # When the submission was an archive, CDR acted on the container. Saying so
    # matters: "Sanitized, 0 objects removed" on a malware sample means the zip
    # was rebuilt, not that the payload inside was found to be free of active
    # content.
    children = ((payload.get("extracted_files") or {})
                .get("files_in_archive") or [])

    return {
        "on_container": bool(children),
        "profile": process.get("profile"),
        "result": process.get("result"),
        "actions_ran": post.get("actions_ran") or "",
        "actions_failed": post.get("actions_failed") or "",
        "converted_to": post.get("converted_to") or "",
        "description": description,
        "objects": objects,
        "sanitized_result": sanitized.get("result") or "",
        "sanitized_reason": sanitized.get("reason") or "",
        "has_clean_copy": bool(sanitized.get("file_path")),
        "ran": bool("sanitized" in (post.get("actions_ran") or "").lower()
                    or sanitized.get("file_path")),
    }
