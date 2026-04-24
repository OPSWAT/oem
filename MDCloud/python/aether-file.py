"""
aether-file.py
==============

Detonate a file in the OPSWAT MetaDefender Aether sandbox (MetaDefender
Cloud dynamic analysis) and save the full behavioral report.

Workflow
--------
1. POST /v4/file                           -> upload with a ``sandbox`` header
2. GET  /v4/file/{data_id}                 -> poll until scan completes, then
                                              extract the ``sandbox_id``
3. GET  /v4/sandbox/{sandbox_id}           -> poll until dynamic analysis
                                              produces a verdict report
4. GET  full_report.json URL               -> download the complete
                                              behavioral report and save it
                                              as ``Aether_result_<name>.json``

Usage
-----
    python aether-file.py <api_key> <file>
    python aether-file.py <api_key> <file> --sandbox linux
    python aether-file.py <api_key> <file> --dump

Flags
-----
--sandbox   Sandbox image: windows10 (default), windows7, or linux.
--rule      Optional MDC workflow rule (``multiscan``, ``cdr``, ``dlp``,
            ``sanitize``, ``unarchive``, or combinations). There is NO
            ``sandbox`` rule - dynamic analysis is controlled solely by
            the ``sandbox`` header.
--dump      Print the full /v4/file JSON response for debugging.

Notes
-----
* Sandbox analysis is a paid/entitled feature on most MetaDefender Cloud
  tiers. If your API key lacks a sandbox entitlement, the upload still
  succeeds but the response contains no ``sandbox_id`` - the script's
  diagnostic routine will explain likely causes.
* Dynamic analysis typically takes 1-5 minutes per file.
* MDC caches results by file hash. Re-uploading the same file may return
  the cached report immediately instead of running a fresh detonation.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* https://www.opswat.com/products/metadefender/aether

Author:    Chris Seiler
Copyright: (c) 2026 OPSWAT, Inc. All rights reserved.
"""

import argparse
import json
import os
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


def analyze_file(api_key, file_path, sandbox, rule):
    """
    Upload a file and request sandbox analysis.

    The ``sandbox`` header selects the sandbox image; the optional ``rule``
    header can be combined to run other MDC workflows in the same call.
    """
    url = f"{BASE_URL}/file"
    headers = {
        "apikey": api_key,
        "Content-Type": "application/octet-stream",
        "filename": os.path.basename(file_path),
        "sandbox": sandbox,
    }
    if rule:
        headers["rule"] = rule

    print(f"[+] POST {url}")
    print(f"    headers: sandbox={sandbox}, rule={rule or '(not set)'}")
    with open(file_path, "rb") as f:
        resp = requests.post(url, headers=headers, data=f.read())

    if resp.status_code != 200:
        raise RuntimeError(f"Upload failed (HTTP {resp.status_code}): {resp.text}")

    body = resp.json()
    data_id = body.get("data_id")
    if not data_id:
        raise RuntimeError(f"No data_id in upload response: {body}")

    print(f"[+] Upload OK. data_id = {data_id}")
    # Surface any sandbox-related acknowledgement the server echoed back.
    for key in ("sandbox", "rest_ip", "in_queue"):
        if key in body:
            print(f"    upload response['{key}'] = {body[key]}")
    return data_id


def fetch_file_result(api_key, data_id):
    """Poll /v4/file/{data_id} until the scan reaches 100% progress."""
    url = f"{BASE_URL}/file/{data_id}"
    headers = {"apikey": api_key}

    print(f"[+] GET {url}  (polling file result)")
    start = time.time()
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


def find_sandbox_id(file_result):
    """
    Extract the sandbox_id from a /v4/file response.

    Different MDC versions place the sandbox id in different locations.
    Current responses put it at the top level as ``sandbox_id`` and also
    list it in ``last_sandbox_id[]`` with a ``system`` field naming the
    sandbox engine (e.g. ``filescanio``). We check each known path in
    order and return (id, location, system-or-None).
    """
    # 1) Top-level sandbox_id (current MDC behaviour).
    sid = file_result.get("sandbox_id")
    if sid:
        return sid, "sandbox_id", None

    # 2) last_sandbox_id list - take the most recent entry.
    last = file_result.get("last_sandbox_id")
    if isinstance(last, list) and last:
        entry = last[0]
        if isinstance(entry, dict) and entry.get("sandbox_id"):
            return entry["sandbox_id"], "last_sandbox_id[0].sandbox_id", entry.get("system")

    # 3) Legacy nested paths - kept for older MDC deployments.
    legacy = [
        ("sandbox", "sandbox_id"),
        ("sandbox", "id"),
        ("process_info", "sandbox", "sandbox_id"),
        ("additional_info", "sandbox", "sandbox_id"),
    ]
    for path in legacy:
        node = file_result
        for key in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        if node:
            return node, ".".join(path), None

    return None, None, None


def diagnose_missing_sandbox(file_result):
    """Explain why sandbox analysis didn't run (or wasn't acknowledged)."""
    print("\n[!] No sandbox_id found. Diagnostic dump follows:\n")

    fi = file_result.get("file_info", {})
    print(f"  file_type_description : {fi.get('file_type_description')}")
    print(f"  file_type_extension   : {fi.get('file_type_extension')}")
    print(f"  sha256                : {fi.get('sha256')}")

    sr = file_result.get("scan_results", {})
    print(f"  scan_all_result_a     : {sr.get('scan_all_result_a')}")
    print(f"  rest_version          : {file_result.get('rest_version')}")
    pi = file_result.get("process_info") or {}
    print(f"  process_info.profile  : {pi.get('profile')}")
    print(f"  process_info.result   : {pi.get('result')}")

    print(f"\n  sandbox object        : {json.dumps(file_result.get('sandbox', {}), indent=2)}")

    print("\n  Likely causes:")
    print("    1) Your API key does not include a Cloud Sandbox entitlement.")
    print("       Check https://metadefender.opswat.com/account - the sandbox row")
    print("       should show a non-zero daily limit.")
    print("    2) The file hash was already cached without sandbox results. Try a")
    print("       different file, or add --rule to force a specific workflow.")
    print("    3) The file type isn't supported by the sandbox.")
    print("       See https://www.opswat.com/docs/filescan/datasheet/supported-file-types")


def _sandbox_report_is_complete(report):
    """
    Decide whether a /v4/sandbox/{id} response is a FINISHED report.

    The API returns HTTP 200 even while analysis is still running - in that
    state the body contains only submission metadata (data_id, hashes,
    sandbox_id). A finished report additionally contains one of the
    verdict/result-shaped fields listed below.
    """
    if not isinstance(report, dict):
        return False

    verdict_keys = (
        "overall_verdict", "verdict", "final_verdict",
        "scan_results", "report", "results",
        "signals", "signatures", "behavior", "behaviour",
        "mitre_attack", "mitre_techniques", "iocs",
        "processes", "tags",
    )
    if any(k in report for k in verdict_keys):
        return True

    status = report.get("status") or (report.get("sandbox") or {}).get("status")
    if isinstance(status, str) and status.lower() in {
        "done", "finished", "completed", "success"
    }:
        return True

    return False


def fetch_sandbox_report(api_key, sandbox_id):
    """Poll /v4/sandbox/{sandbox_id} until the dynamic analysis report is ready."""
    url = f"{BASE_URL}/sandbox/{sandbox_id}"
    headers = {"apikey": api_key}

    print(f"[+] GET {url}  (polling sandbox report)")
    start = time.time()
    while True:
        resp = requests.get(url, headers=headers)

        if resp.status_code == 202:
            # Some MDC deployments return 202 Accepted while the run is in
            # progress. Treat it the same as "keep polling".
            print("    sandbox report not ready yet (HTTP 202)")
        elif resp.status_code == 200:
            report = resp.json()

            if _sandbox_report_is_complete(report):
                return report

            # Show whatever progress signal the in-flight body gives us.
            status = (
                report.get("status")
                or (report.get("sandbox") or {}).get("status")
                or (report.get("scan_results") or {}).get("progress_percentage")
            )
            if status is not None:
                print(f"    sandbox progress/status: {status}")
            else:
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


def main():
    """Command-line entry point."""
    ap = argparse.ArgumentParser(
        description="Detonate a file in the MetaDefender Aether sandbox."
    )
    ap.add_argument("api_key", help="Your MetaDefender Cloud API key")
    ap.add_argument("file_path", help="Path to the file to sandbox-analyze")
    ap.add_argument(
        "--sandbox", default="windows10",
        choices=["windows10", "windows7", "linux"],
        help="Sandbox image to use (default: windows10).",
    )
    ap.add_argument(
        "--rule", default="",
        help=(
            "Optional MDC workflow rule. Valid values on Cloud are 'multiscan', "
            "'cdr', 'dlp', 'sanitize', 'unarchive', or combinations like "
            "'multiscan_sanitize_unarchive'. There is NO 'sandbox' rule - "
            "dynamic analysis is controlled solely by the 'sandbox' header. "
            "Leave empty to omit."
        ),
    )
    ap.add_argument(
        "--dump", action="store_true",
        help="Print the full /v4/file JSON response for debugging.",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.file_path):
        print(f"Error: file not found: {args.file_path}", file=sys.stderr)
        return 1

    rule = args.rule.strip() or None

    try:
        # 1) Upload with the sandbox header set.
        data_id = analyze_file(args.api_key, args.file_path, args.sandbox, rule)

        # 2) Wait for the file-level scan, then extract the sandbox_id.
        file_result = fetch_file_result(args.api_key, data_id)

        if args.dump:
            print("\n----- FULL /v4/file RESPONSE -----")
            print(json.dumps(file_result, indent=2))
            print("----- END RESPONSE -----\n")

        sandbox_id, where, system = find_sandbox_id(file_result)
        if not sandbox_id:
            diagnose_missing_sandbox(file_result)
            return 1

        print(f"[+] Found sandbox_id at '{where}' = {sandbox_id}")
        if system:
            print(f"    sandbox system = {system}")

        # 3) Poll the sandbox endpoint until the dynamic analysis is done.
        report = fetch_sandbox_report(args.api_key, sandbox_id)

        print("\n===== SANDBOX REPORT =====")
        print(json.dumps(report, indent=2))

        # 4) Download the full behavioural report via full_report.json.
        full_report_url = (report.get("full_report") or {}).get("json")
        if not full_report_url:
            raise RuntimeError("Sandbox response did not include full_report.json URL")

        print(f"\n[+] Downloading full report from {full_report_url}")
        headers = {"apikey": args.api_key}
        resp = requests.get(full_report_url, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Full report download failed (HTTP {resp.status_code}): {resp.text}"
            )
        full_report = resp.json()

        # Save as Aether_result_<basename-without-extension>.json
        original_name = os.path.basename(args.file_path)
        name_no_ext, _ = os.path.splitext(original_name)
        output_filename = f"Aether_result_{name_no_ext}.json"
        with open(output_filename, "w", encoding="utf-8") as out:
            json.dump(full_report, out, indent=2)
        print(f"[+] Saved full report to: {output_filename}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
