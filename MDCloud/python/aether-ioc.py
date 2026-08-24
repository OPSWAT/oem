"""
aether-ioc.py
=============

Submit a file to the OPSWAT MetaDefender Aether sandbox (MetaDefender Cloud
dynamic analysis) and print the *indicators of compromise* the sandbox found,
together with the signals that drove the verdict.

Where ``aether-file.py`` saves the raw behavioural report, this sample walks
that report and renders the analyst-facing view: verdict, the signal groups
that produced it, YARA rule hits, tags, MITRE ATT&CK techniques, and every
IOC (domains, URLs, IPs, hashes, registry paths, wallets, e-mail addresses).

Every output section names the endpoint that produced it.

Sandbox workflow
----------------
1. POST /v4/file                  -> upload with a ``sandbox`` header
2. GET  /v4/file/{data_id}        -> poll until the scan completes, then read
                                     the ``sandbox_id``
3. GET  /v4/sandbox/{sandbox_id}  -> poll until dynamic analysis produces a
                                     verdict, then take ``full_report.json``
4. GET  full_report.json URL      -> the report itself; extract and render

Given a hash instead of a file path, steps 1-3 are replaced by a single
``GET /v4/hash/{hash}/sandbox`` lookup - no upload, and it does not consume
a sandbox run.

Multiscan and Deep CDR
----------------------
Those are separate MDC workflows, selected by the ``rule`` header, and only
ONE rule is accepted per submission - ``multiscan``, ``cdr``, ``dlp``,
``sanitize`` or ``unarchive``. The combination forms are rejected with
HTTP 400, so each extra view costs its own submission:

* ``--multiscan``  POST /v4/file with ``rule: multiscan``, then poll
                   /v4/file/{data_id} and read ``scan_results``
                   (``scan_details`` per engine, ``total_detected_avs``).
* ``--cdr``        POST /v4/file with ``rule: cdr``, then read
                   ``process_info.post_processing`` and ``sanitized``.

For a hash target both come from one ``GET /v4/hash/{hash}`` call instead -
no upload, nothing billed against the sandbox quota. And when the sandbox
submission happens to return cached AV results, the multiscan section reuses
them rather than paying for a second submission.

Usage
-----
    python aether-ioc.py <api_key> <file>
    python aether-ioc.py <api_key> <sha256>              # existing report
    python aether-ioc.py <api_key> <file> --sandbox linux
    python aether-ioc.py <api_key> <file> --multiscan --cdr
    python aether-ioc.py <api_key> <file> --archive-password infected
    python aether-ioc.py <api_key> <file> --detail signals
    python aether-ioc.py <api_key> <file> --all-iocs
    python aether-ioc.py <api_key> <file> --csv
    python aether-ioc.py <api_key> <file> --save-report

Flags
-----
--sandbox      Sandbox image: windows10 (default), windows7, or linux.
--multiscan    Also gather multi-engine AV results (one extra submission
               for a file target; free for a hash target).
--cdr          Also gather Deep CDR results (likewise).
--archive-password
               Password for an encrypted archive, sent as ``archivepwd`` so
               the service opens it server-side. Nothing is extracted
               locally, which keeps a sealed sample sealed.
--detail       Signal verbosity: ``summary`` (one line per behaviour, the
               default), ``signals`` (a few examples per behaviour), or
               ``all``. A real sample emits hundreds of signals.
--all-iocs     Print every IOC. By default each type is capped at 10 rows,
               because a single office document can yield hundreds of URLs.
--min-strength Hide signals weaker than this (0.0 - 1.0). Default 0.0.
--csv [PATH]   Write the collected IOCs to CSV. Defaults to
               ``iocs_<name>.csv`` in the current directory.
--save-report  Also save the raw report as ``Aether_result_<name>.json``.
--no-color     Disable ANSI colour (also disabled automatically when stdout
               is redirected).

Report structure notes
----------------------
The document returned by ``full_report.json`` has two useful views:

* ``overview_report`` - a flattened, snake_case summary. This sample reads
  it, because it is stable and already normalised per sub-report:
  ``final_verdict``, ``signal_groups[]``, ``yara_matches[]``, ``tags[]``,
  ``iocs[][]`` (a list *of lists* - one inner list per analysed sub-file).
* ``full_report`` - the complete camelCase sandbox report. Note that this
  field is a JSON **string**, not an object; it has to be parsed a second
  time. This sample does that only to pull MITRE technique mappings out of
  ``summary.behaviorPatterns[]``.

IOC verdicts are per-indicator (``UNKNOWN`` for an observed-but-unrated
resource, up to ``MALICIOUS``), and ``is_interesting`` marks the subset the
sandbox considers worth an analyst's attention.

Security note: the ``full_report.json`` / ``pdf`` / ``html`` URLs carry a
long token in the path and are honoured *without* the ``apikey`` header.
Treat them as bearer credentials for that one report - don't log them, put
them in tickets, or pass them to a browser you don't control.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* https://www.opswat.com/products/metadefender/aether

Author:    Chris Seiler
Copyright: (c) 2026 OPSWAT, Inc. All rights reserved.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL = "https://api.metadefender.com/v4"

# Polling for the initial file scan (fast - AV multiscan timings).
FILE_POLL_INTERVAL_SECONDS = 3
FILE_POLL_TIMEOUT_SECONDS = 300        # 5 minutes

# Polling for the sandbox report (slower - dynamic analysis is expensive).
SANDBOX_POLL_INTERVAL_SECONDS = 15
SANDBOX_POLL_TIMEOUT_SECONDS = 1800    # 30 minutes

# Hex-length -> algorithm, used to auto-detect raw hash input.
HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}

# Rows printed per IOC type unless --all-iocs is given.
IOC_ROWS_PER_TYPE = 10

# Example signals printed per group when --detail signals is given.
SIGNAL_EXAMPLES = 3

# Removed-object entries printed per CDR object class.
CDR_OBJECTS_PER_CLASS = 3

# Most severe first. Used to sort IOCs and to colour verdicts.
VERDICT_ORDER = [
    "MALICIOUS", "LIKELY_MALICIOUS", "SUSPICIOUS",
    "UNKNOWN", "INFORMATIONAL", "NO_THREAT", "BENIGN",
]

WIDTH = 78


# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------
class Style:
    """
    Minimal ANSI styling. Every attribute becomes an empty string when
    colour is disabled, so call sites can interpolate unconditionally.
    """

    CODES = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "red": "\033[31m",
        "bright_red": "\033[91m",
        "yellow": "\033[33m",
        "green": "\033[32m",
        "cyan": "\033[36m",
        "magenta": "\033[35m",
    }

    def __init__(self, enabled):
        for name, code in self.CODES.items():
            setattr(self, name, code if enabled else "")

    def paint(self, text, *names):
        """Wrap ``text`` in the named styles (a no-op when colour is off)."""
        return "".join(getattr(self, n) for n in names) + text + self.reset


def enable_ansi_on_windows():
    """
    Turn on virtual-terminal processing so ANSI escapes render in the
    classic Windows console. No-op elsewhere, and harmless if the call
    fails (Windows Terminal already handles ANSI).
    """
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # -11 = STD_OUTPUT_HANDLE, 0x4 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x4)
    except Exception:
        pass


def verdict_style(verdict):
    """Map a sandbox verdict string to a tuple of Style attribute names."""
    v = (verdict or "").upper()
    if v == "MALICIOUS":
        return ("bright_red", "bold")
    if v == "LIKELY_MALICIOUS":
        return ("red", "bold")
    if v == "SUSPICIOUS":
        return ("yellow", "bold")
    if v in ("NO_THREAT", "BENIGN"):
        return ("green",)
    return ("cyan",)


def verdict_rank(verdict):
    """Index into VERDICT_ORDER - lower is more severe."""
    v = (verdict or "").upper()
    return VERDICT_ORDER.index(v) if v in VERDICT_ORDER else len(VERDICT_ORDER)


def heading(style, text, api=None):
    """
    Print a section rule, e.g. ``--- IOCs -----------------``.

    ``api`` names the endpoint the section's data came from, so a reader can
    see which call produces which part of the output.
    """
    bar = "-" * max(3, WIDTH - len(text) - 5)
    print("\n" + style.paint(f"--- {text} {bar}", "bold"))
    if api:
        print(style.paint(f"    API: {api}", "dim"))


# ---------------------------------------------------------------------------
# Input resolution
# ---------------------------------------------------------------------------
def compute_sha256(file_path):
    """SHA256 of a file, read in 1 MB chunks so large files stay cheap."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def looks_like_hash(value):
    """True if ``value`` is a bare MD5, SHA1 or SHA256 hex digest."""
    stripped = value.strip()
    return (
        bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))
        and len(stripped) in HASH_LENGTHS
    )


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------
def submit_file(api_key, file_path, sandbox=None, rule=None, archive_password=None):
    """
    POST /v4/file and return the data_id.

    ``sandbox`` selects a sandbox image and is what triggers dynamic
    analysis; ``rule`` selects an MDC workflow (``multiscan``, ``cdr``,
    ``dlp``, ``sanitize``, ``unarchive``). They are independent headers, and
    only ONE rule may be given - the combination forms are rejected, so
    gathering multiscan *and* CDR results takes one submission each.

    ``archive_password`` sends ``archivepwd``, which lets the service open an
    encrypted archive and analyse what is inside. That keeps a password-
    protected sample (the ``infected`` convention used by malware feeds)
    sealed on the submitting host - nothing is ever extracted locally.
    """
    url = f"{BASE_URL}/file"
    headers = {
        "apikey": api_key,
        "Content-Type": "application/octet-stream",
        "filename": os.path.basename(file_path),
    }
    if sandbox:
        headers["sandbox"] = sandbox
    if rule:
        headers["rule"] = rule
    if archive_password:
        headers["archivepwd"] = archive_password

    described = ", ".join(
        part for part in (
            f"sandbox={sandbox}" if sandbox else "",
            f"rule={rule}" if rule else "",
            "archivepwd set" if archive_password else "",
        ) if part
    )
    print(f"[+] POST {url}  ({described})")
    with open(file_path, "rb") as f:
        resp = requests.post(url, headers=headers, data=f.read())
    if resp.status_code == 429:
        # Sandbox runs are metered separately from ordinary scans and the
        # daily allowance is small - check limit_sandbox on GET /v4/apikey.
        raise RuntimeError(
            f"Rate limit reached (HTTP 429): {resp.text}\n"
            f"    Sandbox runs have their own small daily allowance, separate "
            f"from scans. GET /v4/apikey shows yours as 'limit_sandbox'. A "
            f"hash target reads an existing report without spending one."
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Upload failed (HTTP {resp.status_code}): {resp.text}")

    body = resp.json()
    data_id = body.get("data_id")
    if not data_id:
        raise RuntimeError(f"No data_id in upload response: {body}")
    print(f"[+] Upload OK. data_id = {data_id}")
    return data_id


def poll_file_result(api_key, data_id):
    """Poll /v4/file/{data_id} to 100% and return the whole payload."""
    url = f"{BASE_URL}/file/{data_id}"
    headers = {"apikey": api_key}
    start = time.time()

    print(f"[+] GET {url}  (waiting for the file scan)")
    while True:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(
                f"File fetch failed (HTTP {resp.status_code}): {resp.text}"
            )
        result = resp.json()
        progress = result.get("scan_results", {}).get("progress_percentage", 0)
        print(f"    file scan progress: {progress}%")
        if progress >= 100:
            return result
        if time.time() - start > FILE_POLL_TIMEOUT_SECONDS:
            raise TimeoutError(
                f"File scan timed out after {FILE_POLL_TIMEOUT_SECONDS}s"
            )
        time.sleep(FILE_POLL_INTERVAL_SECONDS)


def extract_sandbox_id(result):
    """Pull the sandbox_id out of a /v4/file/{data_id} payload."""
    # Current MDC puts the id at the top level; older responses list it under
    # last_sandbox_id[]. aether-file.py carries the full fallback chain.
    sandbox_id = result.get("sandbox_id")
    if not sandbox_id:
        last = result.get("last_sandbox_id")
        if isinstance(last, list) and last and isinstance(last[0], dict):
            sandbox_id = last[0].get("sandbox_id")
    if not sandbox_id:
        raise RuntimeError(
            "The scan completed but returned no sandbox_id. Common causes: the "
            "API key has no sandbox entitlement, the daily sandbox quota is "
            "exhausted, or the file type is not supported by the sandbox. Run "
            "aether-file.py --dump for a full diagnostic."
        )
    print(f"[+] sandbox_id = {sandbox_id}")
    return sandbox_id


def wait_for_sandbox_report(api_key, sandbox_id):
    """
    Poll /v4/sandbox/{sandbox_id} until the run finishes.

    While analysis is in flight the endpoint returns HTTP 200 carrying only
    submission metadata (data_id, hashes, sandbox_id). Completion is
    signalled by the arrival of ``final_verdict`` / ``full_report``.
    """
    url = f"{BASE_URL}/sandbox/{sandbox_id}"
    headers = {"apikey": api_key}
    start = time.time()

    print(f"[+] GET {url}  (waiting for dynamic analysis)")
    while True:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 202:
            print("    sandbox report not ready yet (HTTP 202)")
        elif resp.status_code == 200:
            report = resp.json()
            if report.get("final_verdict") or report.get("full_report"):
                return report
            print("    sandbox still running (only metadata returned so far)")
        else:
            raise RuntimeError(
                f"Sandbox fetch failed (HTTP {resp.status_code}): {resp.text}"
            )

        if time.time() - start > SANDBOX_POLL_TIMEOUT_SECONDS:
            raise TimeoutError(
                f"Sandbox report timed out after {SANDBOX_POLL_TIMEOUT_SECONDS}s"
            )
        time.sleep(SANDBOX_POLL_INTERVAL_SECONDS)


def lookup_hash(api_key, file_hash):
    """GET /v4/hash/{hash}/sandbox - the last sandbox report for a hash."""
    url = f"{BASE_URL}/hash/{file_hash}/sandbox"
    print(f"[+] GET {url}")
    resp = requests.get(url, headers={"apikey": api_key})

    if resp.status_code == 404:
        raise RuntimeError(
            f"No sandbox report exists for hash {file_hash}. Pass the file "
            f"itself to detonate it and generate one."
        )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Hash lookup failed (HTTP {resp.status_code}): {resp.text}"
        )
    return resp.json()


def lookup_hash_scan(api_key, file_hash):
    """
    GET /v4/hash/{hash} - the cached multiscan *and* CDR view for a hash.

    Distinct from /v4/hash/{hash}/sandbox, which returns the dynamic-analysis
    report. This one carries ``scan_results`` (per-engine AV verdicts) plus
    ``process_info`` / ``sanitized`` (Deep CDR), so a single call fills both
    of those sections without uploading anything. Returns None on 404.
    """
    url = f"{BASE_URL}/hash/{file_hash}"
    print(f"[+] GET {url}  (cached multiscan / CDR results)")
    resp = requests.get(url, headers={"apikey": api_key})

    if resp.status_code == 404:
        print("    no cached scan results for this hash")
        return None
    if resp.status_code != 200:
        raise RuntimeError(
            f"Hash scan lookup failed (HTTP {resp.status_code}): {resp.text}"
        )
    return resp.json()


def download_report(api_key, sandbox_meta):
    """Follow ``full_report.json`` (or ``store_at``) and return the report."""
    url = (
        (sandbox_meta.get("full_report") or {}).get("json")
        or sandbox_meta.get("store_at")
    )
    if not url:
        # A hash lookup can return submission metadata and a sandbox_id while
        # still having no report attached - typically because that run never
        # finished. Report the state rather than just saying "no URL".
        state = (sandbox_meta.get("scan_results") or {}).get("scan_all_result_a")
        detail = f" Its state is '{state}'." if state else ""
        raise RuntimeError(
            f"A sandbox run exists for this file (sandbox_id "
            f"{sandbox_meta.get('sandbox_id')}) but it has no report attached."
            f"{detail} The run most likely did not complete, so there is "
            f"nothing to extract. Submit the file itself to trigger a fresh "
            f"run."
        )

    print("[+] Downloading report ...")
    resp = requests.get(url, headers={"apikey": api_key})
    if resp.status_code != 200:
        raise RuntimeError(
            f"Report download failed (HTTP {resp.status_code}): {resp.text}"
        )
    return resp.json()


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------
def parse_inner_report(report):
    """
    Return the detailed camelCase report as a dict, or ``{}``.

    ``report["full_report"]`` is a JSON-encoded *string*, so it needs a
    second json.loads() pass. Older responses nest the object directly.
    """
    inner = report.get("full_report")
    if isinstance(inner, str):
        try:
            return json.loads(inner)
        except json.JSONDecodeError:
            return {}
    return inner if isinstance(inner, dict) else {}


def collect_signal_groups(overview, min_strength):
    """
    Flatten ``overview_report.signal_groups`` into
    ``[(peak_strength, verdict, description, [(strength, text, origin), ...])]``
    sorted strongest first, dropping signals below ``min_strength``.
    """
    groups = []
    for group in overview.get("signal_groups") or []:
        signals = []
        for signal in group.get("signals") or []:
            strength = float(signal.get("strength") or 0.0)
            if strength < min_strength:
                continue
            signals.append((
                strength,
                signal.get("signalReadable") or "",
                signal.get("originType") or "",
            ))
        if not signals:
            continue
        signals.sort(key=lambda s: -s[0])
        groups.append((
            signals[0][0],                                  # peak strength
            group.get("verdict") or "UNKNOWN",
            group.get("description") or "(no description)",
            signals,
        ))

    # Strongest groups first; ties broken by verdict severity, then text.
    groups.sort(key=lambda g: (-g[0], verdict_rank(g[1]), g[2]))
    return groups


def collect_iocs(overview):
    """
    Flatten and de-duplicate ``overview_report.iocs``.

    That field is a list of lists - one inner list per analysed sub-file -
    so the same domain routinely appears several times. Returns
    ``{display_name: [ioc, ...]}``, most severe first within each type.
    """
    merged = {}
    for sublist in overview.get("iocs") or []:
        for ioc in sublist or []:
            value = ioc.get("data")
            if not value:
                continue
            ioc_type = ioc.get("type") or "unknown"
            key = (ioc_type, value)
            existing = merged.get(key)
            if existing is None:
                merged[key] = {
                    "type": ioc_type,
                    "display_name": ioc.get("type_display_name") or ioc_type,
                    "value": value,
                    "verdict": ioc.get("verdict") or "UNKNOWN",
                    "interesting": bool(ioc.get("is_interesting")),
                }
                continue
            # Keep the most severe verdict, and OR the "interesting" flag.
            if verdict_rank(ioc.get("verdict")) < verdict_rank(existing["verdict"]):
                existing["verdict"] = ioc.get("verdict")
            existing["interesting"] = (
                existing["interesting"] or bool(ioc.get("is_interesting"))
            )

    by_type = {}
    for ioc in merged.values():
        by_type.setdefault(ioc["display_name"], []).append(ioc)
    for iocs in by_type.values():
        iocs.sort(
            key=lambda i: (verdict_rank(i["verdict"]), not i["interesting"], i["value"])
        )

    # Biggest groups first so the noisiest indicator types lead the table.
    return dict(sorted(by_type.items(), key=lambda kv: (-len(kv[1]), kv[0])))


def collect_multiscan(scan_payload):
    """
    Normalise the multi-engine AV view from ``scan_results``.

    ``scan_details`` maps engine name -> ``{scan_result_i, threat_found,
    scan_time, def_time}``. ``scan_result_i`` is 0 for clean; a non-zero code
    with a populated ``threat_found`` is a detection.
    """
    results = (scan_payload or {}).get("scan_results") or {}
    engines = []
    for name, entry in (results.get("scan_details") or {}).items():
        engines.append({
            "engine": name,
            "threat": (entry or {}).get("threat_found") or "",
            "code": (entry or {}).get("scan_result_i"),
            "scan_time": (entry or {}).get("scan_time"),
            "def_time": (entry or {}).get("def_time") or "",
        })
    # Detections first, then alphabetically.
    engines.sort(key=lambda e: (not e["threat"], e["engine"].lower()))

    return {
        "overall": results.get("scan_all_result_a"),
        "total": results.get("total_avs"),
        "detected": results.get("total_detected_avs"),
        "total_time": results.get("total_time"),
        "engines": engines,
    }


def collect_cdr(scan_payload):
    """
    Normalise the Deep CDR view from ``process_info`` and ``sanitized``.

    ``post_processing.actions_ran`` contains "Sanitized" when CDR rebuilt the
    file. ``sanitized.file_path`` is a pre-signed URL to the clean copy and
    is only retained for 24 hours. ``sanitization_details`` arrives as either
    a dict or a string depending on MDC version.
    """
    payload = scan_payload or {}
    process = payload.get("process_info") or {}
    post = process.get("post_processing") or {}
    sanitized = payload.get("sanitized") or {}

    details = post.get("sanitization_details")
    description, items = "", []
    if isinstance(details, dict):
        description = details.get("description") or ""
        raw_items = details.get("details")
        if isinstance(raw_items, list):
            items = raw_items
    elif isinstance(details, str):
        description = details

    return {
        "profile": process.get("profile"),
        "result": process.get("result"),
        "blocked_reason": process.get("blocked_reason") or "",
        "actions_ran": post.get("actions_ran") or "",
        "actions_failed": post.get("actions_failed") or "",
        "converted_to": post.get("converted_to") or "",
        "converted_destination": post.get("converted_destination") or "",
        "description": description,
        "details": items,
        "sanitized_result": sanitized.get("result") or "",
        "sanitized_reason": sanitized.get("reason") or "",
        "sanitized_url": sanitized.get("file_path") or "",
        # True when CDR actually rebuilt the file, matching cdr-file.py.
        "ran": bool(
            "sanitized" in (post.get("actions_ran") or "").lower()
            or sanitized.get("file_path")
        ),
    }


def collect_mitre(inner):
    """
    Pull MITRE ATT&CK techniques out of ``summary.behaviorPatterns[]``.

    ``fingerprint.mitre_techniques`` also exists but is a numeric feature
    vector for the scoring model, not a human-readable mapping.
    """
    techniques = {}
    for pattern in (inner.get("summary") or {}).get("behaviorPatterns") or []:
        for technique in pattern.get("MITRETechniques") or []:
            tid = technique.get("ID")
            if tid:
                techniques[tid] = technique.get("name") or ""
    return dict(sorted(techniques.items()))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def print_header(style, label, sandbox_meta, overview, api=None):
    """Verdict banner: what was analysed, and how the sandbox rated it."""
    final = overview.get("final_verdict") or sandbox_meta.get("final_verdict") or {}
    verdict = final.get("verdict") or "UNKNOWN"
    threat = final.get("threat_level", final.get("threatLevel"))
    confidence = final.get("confidence")

    print("\n" + style.paint("=" * WIDTH, "bold"))
    print(style.paint(f" SANDBOX IOC REPORT - {label}", "bold"))
    print(style.paint("=" * WIDTH, "bold"))
    if api:
        print(style.paint(f" API: {api}", "dim"))

    detail = []
    if threat is not None:
        detail.append(f"threat level {float(threat):.2f}")
    if confidence is not None:
        detail.append(f"confidence {float(confidence):.2f}")
    painted = style.paint(verdict, *verdict_style(verdict))
    print(f" Verdict     : {painted}" + (f"  ({', '.join(detail)})" if detail else ""))

    if "blocked" in final:
        print(f" Blocked     : {'yes' if final['blocked'] else 'no'}")
    for field, caption in (("sha256", "SHA256"), ("sandbox_id", "Sandbox ID")):
        if sandbox_meta.get(field):
            print(f" {caption:<11} : {sandbox_meta[field]}")
    if overview.get("analysis_state"):
        print(f" State       : {overview['analysis_state']}")


def print_multiscan(style, multiscan, api):
    """Per-engine AV results: the static verdict, next to the dynamic one."""
    heading(style, "MULTISCAN (anti-malware engines)", api)

    if not multiscan:
        print(" Not gathered. Pass --multiscan to run the multiscan workflow.")
        return

    overall = multiscan["overall"] or "Not Scanned"
    total, detected = multiscan["total"] or 0, multiscan["detected"] or 0
    colour = ("bright_red", "bold") if detected else ("green",)
    print(f" Overall     : {style.paint(overall, *colour)}")
    print(f" Engines     : {detected} of {total} flagged this file")
    if multiscan["total_time"] is not None:
        print(f" Scan time   : {multiscan['total_time']} ms")

    if not multiscan["engines"]:
        print("\n No per-engine detail returned. 'Not Scanned' usually means the"
              "\n submission ran sandbox-only - add --multiscan for AV results.")
        return

    print()
    print(style.paint(f" {'ENGINE':<22} {'THREAT NAME':<40} DEFS", "bold"))
    for engine in multiscan["engines"]:
        threat = engine["threat"] or "-"
        painted = (
            style.paint(f"{threat:<40}", "bright_red", "bold")
            if engine["threat"] else f"{threat:<40}"
        )
        # Definition timestamps are ISO-8601; the date is the useful part.
        defs = (engine["def_time"] or "")[:10]
        # Engine names can exceed the column (e.g. "OPSWAT Predictive AI").
        # Plain ASCII here - a Windows console in cp1252 mangles "…".
        name = engine["engine"]
        name = name if len(name) <= 22 else name[:19] + "..."
        print(f" {name:<22} {painted} {defs}")


def capped(values, expand, limit=CDR_OBJECTS_PER_CLASS):
    """
    Return ``(shown, hidden_count)`` for a list field.

    Deep CDR can report hundreds of removed objects of one class, so each
    list is trimmed unless ``--detail all`` asked for everything.
    """
    items = [v for v in (values or []) if v not in (None, "")]
    if expand or len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def print_cdr(style, cdr, api, expand=False):
    """
    Deep CDR outcome: what was detected and removed, and where the clean
    copy lives.

    The interesting part is ``sanitization_details.details[]``. Each entry
    describes one class of active content CDR acted on:

    * ``object_name``     what it was - JavaScript, Macro, Hyperlink, ...
    * ``action``/``count``what CDR did to it, and to how many
    * ``object_metadata`` where it sat in the document structure
    * ``object_details``  the removed content itself
    * ``object_sha256``   a digest per removed object

    That is the audit trail for a sanitization: not just "file was cleaned"
    but exactly which active content was stripped out of it.
    """
    heading(style, "DEEP CDR (sanitization)", api)

    if not cdr:
        print(" Not gathered. Pass --cdr to run the Deep CDR workflow.")
        return

    if not cdr["ran"]:
        reason = cdr["sanitized_reason"] or cdr["description"] or "not requested"
        print(f" Deep CDR did not sanitize this file ({reason}).")
        if cdr["sanitized_result"]:
            print(f" Sanitize result : {cdr['sanitized_result']}")
        if cdr["profile"]:
            print(f" Workflow        : {cdr['profile']}")
        return

    print(f" Workflow        : {cdr['profile'] or '-'}")
    print(f" Process result  : {cdr['result'] or '-'}")
    print(f" Actions ran     : {style.paint(cdr['actions_ran'], 'green')}")
    if cdr["actions_failed"]:
        print(f" Actions failed  : {style.paint(cdr['actions_failed'], 'red')}")
    if cdr["converted_to"]:
        print(f" Rebuilt as      : {cdr['converted_to']}"
              f"  ({cdr['converted_destination'] or 'no destination name'})")
    if cdr["description"]:
        print(f" Summary         : {cdr['description']}")

    if cdr["details"]:
        total = sum(
            (item.get("count") or 1) if isinstance(item, dict) else 1
            for item in cdr["details"]
        )
        print(f"\n Detected and sanitized: {total} object(s) across "
              f"{len(cdr['details'])} class(es)")

        for item in cdr["details"]:
            if not isinstance(item, dict):
                print(f"   - {item}")
                continue

            name = item.get("object_name") or "object"
            action = item.get("action") or "handled"
            count = item.get("count")
            headline = f"   - {name}: {action}"
            if count is not None:
                headline += f" x{count}"
            print(style.paint(headline, "yellow", "bold"))

            # Where in the document structure the object lived.
            shown, hidden = capped(item.get("object_metadata"), expand)
            for meta in shown:
                print(f"       location : {meta}")
            if hidden:
                print(style.paint(f"       ... {hidden} more location(s)", "dim"))

            # The removed content itself - inert text, but it can be long.
            shown, hidden = capped(item.get("object_details"), expand)
            for detail in shown:
                text = " ".join(str(detail).split())
                if len(text) > 96:
                    text = text[:93] + "..."
                print(f"       content  : {text}")
            if hidden:
                print(style.paint(
                    f"       ... {hidden} more object(s) "
                    f"(use --detail all)", "dim"))

            shown, hidden = capped(item.get("object_sha256"), expand)
            for digest in shown:
                print(style.paint(f"       sha256   : {digest}", "dim"))
            if hidden:
                print(style.paint(f"       ... {hidden} more digest(s)", "dim"))
    elif cdr["ran"]:
        # Sanitized, but nothing active was found to strip.
        print("\n No active content was detected to remove; CDR rebuilt the "
              "file structure only.")

    if cdr["sanitized_url"]:
        print(f" Clean copy      : available for 24h "
              f"({len(cdr['sanitized_url'])}-char pre-signed URL)")
        print(style.paint("                   fetch it with cdr-file.py, or "
                          "GET sanitized.file_path", "dim"))


def strength_label(index, strength, verdict):
    """
    Caption for one strength bucket.

    The strongest bucket is what pushed the file over the line, so it is
    named after the verdict; weaker buckets are described by band.
    """
    if index == 0:
        return f"Driving the verdict ({verdict}, strength {strength:.2f})"
    if strength >= 0.5:
        return f"Suspicious signals (strength {strength:.2f} each)"
    if strength > 0:
        return f"Weak signals (strength {strength:.2f} each)"
    return "Informational (strength 0)"


def print_signals(style, groups, overview, detail, api=None):
    """
    Print signal groups bucketed by peak strength, strongest bucket first.

    ``detail`` controls how much of each group is shown: ``summary`` prints
    just the group description (one line per behaviour), ``signals`` adds a
    few example signals, and ``all`` prints every signal. Real samples emit
    hundreds of signals, so ``summary`` is the readable default.
    """
    heading(style, "WHY: signals behind the verdict", api)
    if not groups:
        print(" (no signals reported)")
        return

    total_signals = sum(len(g[3]) for g in groups)
    print(f" {len(groups)} signal group(s), {total_signals} signal(s) total.")

    final_verdict = (overview.get("final_verdict") or {}).get("verdict") or "UNKNOWN"

    # Bucket by peak strength, preserving the strongest-first ordering.
    buckets = []
    for group in groups:
        if buckets and abs(buckets[-1][0] - group[0]) < 1e-9:
            buckets[-1][1].append(group)
        else:
            buckets.append((group[0], [group]))

    for index, (strength, bucket) in enumerate(buckets):
        verdict = final_verdict if index == 0 else bucket[0][1]
        caption = strength_label(index, strength, verdict)
        colour = verdict_style(verdict) if index == 0 else ("dim",)
        print("\n " + style.paint(caption + ":", *colour))

        for _peak, _verdict, description, signals in bucket:
            count = f" ({len(signals)} signals)" if len(signals) > 1 else ""
            print(f"   - {description}{style.paint(count, 'dim')}")

            if detail == "summary":
                continue
            shown = signals if detail == "all" else signals[:SIGNAL_EXAMPLES]
            for _, text, origin in shown:
                origin_note = style.paint(f"  [{origin}]", "dim") if origin else ""
                print(f"       {text}{origin_note}")
            hidden = len(signals) - len(shown)
            if hidden:
                print(style.paint(f"       ... {hidden} more", "dim"))


def print_yara_and_tags(style, overview, api=None):
    """YARA rule hits and the sandbox's tag set."""
    matches = overview.get("yara_matches") or []
    if matches:
        heading(style, "YARA matches", api)
        for match in matches:
            name = style.paint(match.get("rule_name") or "(unnamed)", "magenta")
            verdict = match.get("verdict") or "UNKNOWN"
            painted = style.paint(verdict, *verdict_style(verdict))
            description = match.get("rule_description") or ""
            suffix = f" - {description}" if description else ""
            print(f" {name}  [{painted}]{suffix}")

    tags = [t.get("name") for t in overview.get("tags") or [] if t.get("name")]
    if not tags:
        tags = overview.get("unique_tags") or []
    if tags:
        heading(style, "Tags", api)
        print(" " + ", ".join(style.paint(t, "cyan") for t in sorted(set(tags))))


def print_mitre(style, techniques, api=None):
    """MITRE ATT&CK techniques the behaviour patterns mapped to."""
    if not techniques:
        return
    heading(style, "MITRE ATT&CK techniques", api)
    for tid, name in techniques.items():
        print(f" {style.paint(tid, 'magenta')}  {name}")


def print_iocs(style, by_type, show_all, api=None):
    """The IOC table: type, verdict, value. '*' marks interesting indicators."""
    heading(style, "IOCs collected by the sandbox", api)
    if not by_type:
        print(" (no IOCs extracted)")
        return

    total = sum(len(iocs) for iocs in by_type.values())
    print(
        f" {total} unique indicator(s) across {len(by_type)} type(s)."
        f"  '*' = flagged interesting by the sandbox.\n"
    )
    print(style.paint(f" {'TYPE':<16} {'VERDICT':<17} INDICATOR", "bold"))

    for display_name, iocs in by_type.items():
        shown = iocs if show_all else iocs[:IOC_ROWS_PER_TYPE]
        for ioc in shown:
            marker = "*" if ioc["interesting"] else " "
            verdict = style.paint(
                f"{ioc['verdict']:<17}", *verdict_style(ioc["verdict"])
            )
            value = ioc["value"]
            if len(value) > 90:
                value = value[:87] + "..."
            print(f"{marker}{display_name:<16} {verdict} {value}")
        hidden = len(iocs) - len(shown)
        if hidden:
            print(style.paint(
                f" {'':<16} {'':<17} ... {hidden} more of type "
                f"{display_name} (use --all-iocs)", "dim"
            ))


def write_ioc_csv(path, by_type):
    """Write the flattened IOC set so it can be fed to a SIEM or TIP."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["type", "type_display_name", "indicator", "verdict", "is_interesting"]
        )
        for display_name, iocs in by_type.items():
            for ioc in iocs:
                writer.writerow([
                    ioc["type"], display_name, ioc["value"],
                    ioc["verdict"], "true" if ioc["interesting"] else "false",
                ])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    """Command-line entry point."""
    ap = argparse.ArgumentParser(
        description=(
            "Submit a file to the MetaDefender Aether sandbox and report the "
            "IOCs and signals it found. Accepts a hash instead of a file to "
            "read an existing report without re-uploading."
        )
    )
    ap.add_argument("api_key", help="Your MetaDefender Cloud API key")
    ap.add_argument("target", help="Path to a file, or an MD5/SHA1/SHA256 hash")
    ap.add_argument(
        "--sandbox", default="windows10",
        choices=["windows10", "windows7", "linux"],
        help="Sandbox image to use (default: windows10).",
    )
    ap.add_argument(
        "--multiscan", action="store_true",
        help=(
            "Also gather multi-engine AV results. For a file this costs one "
            "extra submission with 'rule: multiscan', because a single "
            "submission cannot combine workflows."
        ),
    )
    ap.add_argument(
        "--cdr", action="store_true",
        help=(
            "Also gather Deep CDR results. For a file this costs one extra "
            "submission with 'rule: cdr'."
        ),
    )
    ap.add_argument(
        "--archive-password", default=None, metavar="PWD",
        help=(
            "Password for an encrypted archive, sent as the 'archivepwd' "
            "header so the service opens it server-side. Malware feeds "
            "commonly use 'infected'. Nothing is extracted locally."
        ),
    )
    ap.add_argument(
        "--detail", default="summary", choices=["summary", "signals", "all"],
        help=(
            "How much signal detail to print: 'summary' (one line per "
            f"behaviour, the default), 'signals' (up to {SIGNAL_EXAMPLES} "
            "examples per behaviour), or 'all'."
        ),
    )
    ap.add_argument(
        "--all-iocs", action="store_true",
        help=f"Print every IOC instead of the first {IOC_ROWS_PER_TYPE} per type.",
    )
    ap.add_argument(
        "--min-strength", type=float, default=0.0, metavar="N",
        help="Hide signals with a strength below N (0.0 - 1.0). Default 0.0.",
    )
    ap.add_argument(
        "--csv", nargs="?", const="", default=None, metavar="PATH",
        help="Write the IOCs to CSV (default: iocs_<name>.csv).",
    )
    ap.add_argument(
        "--save-report", action="store_true",
        help="Also save the raw report as Aether_result_<name>.json.",
    )
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colour.")
    args = ap.parse_args()

    use_colour = sys.stdout.isatty() and not args.no_color
    if use_colour:
        enable_ansi_on_windows()
    style = Style(use_colour)

    # Each view records the endpoint that produced it, for display.
    multiscan = cdr = None
    multiscan_api = cdr_api = None

    try:
        # ---- 1. Get a finished sandbox report, by upload or by hash lookup.
        if os.path.isfile(args.target):
            label = os.path.basename(args.target)
            name = os.path.splitext(label)[0]
            print(f"[+] {label}  (SHA256 {compute_sha256(args.target)})")
            data_id = submit_file(
                args.api_key, args.target, sandbox=args.sandbox,
                archive_password=args.archive_password,
            )
            file_result = poll_file_result(args.api_key, data_id)
            sandbox_id = extract_sandbox_id(file_result)
            sandbox_api = f"GET /v4/sandbox/{sandbox_id}"
            sandbox_meta = wait_for_sandbox_report(args.api_key, sandbox_id)

            # The sandbox submission sometimes returns cached AV results
            # already; only pay for a second submission when it did not.
            if ((file_result.get("scan_results") or {}).get("total_avs") or 0) > 0:
                multiscan = collect_multiscan(file_result)
                multiscan_api = (
                    f"GET /v4/file/{data_id}  (cached AV results from the "
                    f"sandbox submission)"
                )
            elif args.multiscan:
                ms_id = submit_file(
                    args.api_key, args.target, rule="multiscan",
                    archive_password=args.archive_password,
                )
                multiscan = collect_multiscan(
                    poll_file_result(args.api_key, ms_id)
                )
                multiscan_api = (
                    f"POST /v4/file  (rule: multiscan)  ->  GET /v4/file/{ms_id}"
                )

            if args.cdr:
                cdr_id = submit_file(
                    args.api_key, args.target, rule="cdr",
                    archive_password=args.archive_password,
                )
                cdr = collect_cdr(poll_file_result(args.api_key, cdr_id))
                cdr_api = (
                    f"POST /v4/file  (rule: cdr)  ->  GET /v4/file/{cdr_id}"
                )
        elif looks_like_hash(args.target):
            algo = HASH_LENGTHS[len(args.target.strip())]
            print(f"[+] Looking up an existing sandbox report by {algo}")
            label = name = args.target.strip().lower()
            sandbox_meta = lookup_hash(args.api_key, label)
            sandbox_api = f"GET /v4/hash/{label}/sandbox"

            # One /v4/hash/{hash} call carries both the AV and the CDR view,
            # so a hash target needs no upload for either section.
            if args.multiscan or args.cdr:
                scan_payload = lookup_hash_scan(args.api_key, label)
                if scan_payload:
                    api = f"GET /v4/hash/{label}"
                    if args.multiscan:
                        multiscan, multiscan_api = collect_multiscan(scan_payload), api
                    if args.cdr:
                        cdr, cdr_api = collect_cdr(scan_payload), api
        else:
            print(
                f"Error: '{args.target}' is neither a readable file nor a valid "
                f"MD5/SHA1/SHA256 hash.",
                file=sys.stderr,
            )
            return 1

        report = download_report(args.api_key, sandbox_meta)
        report_api = "GET full_report.json  (URL from the sandbox response)"

        # ---- 2. Extract the two views and derive the collections we print.
        overview = report.get("overview_report") or {}
        inner = parse_inner_report(report)
        if not overview and not inner:
            raise RuntimeError(
                "The report contained neither overview_report nor full_report."
            )

        groups = collect_signal_groups(overview, args.min_strength)
        by_type = collect_iocs(overview)
        techniques = collect_mitre(inner)

        # ---- 3. Render, one section per source of truth.
        print_header(style, label, sandbox_meta, overview, sandbox_api)
        print_multiscan(style, multiscan, multiscan_api)
        print_cdr(style, cdr, cdr_api, expand=args.detail == "all")
        print_signals(style, groups, overview, args.detail, report_api)
        print_yara_and_tags(style, overview, report_api)
        print_mitre(style, techniques, report_api)
        print_iocs(style, by_type, args.all_iocs, report_api)

        # ---- 4. Optional exports.
        if args.csv is not None:
            csv_path = args.csv or f"iocs_{name}.csv"
            write_ioc_csv(csv_path, by_type)
            total = sum(len(iocs) for iocs in by_type.values())
            print(f"\n[+] Wrote {total} IOC(s) to {csv_path}")
        if args.save_report:
            json_path = f"Aether_result_{name}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"[+] Saved raw report to {json_path}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
