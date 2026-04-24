"""
aether-url.py
=============

Detonate a URL in the OPSWAT MetaDefender Aether sandbox (MetaDefender
Cloud dynamic analysis) and save the full behavioral report.

Workflow
--------
1. POST /v4/sandbox                -> body {"url": "..."}, returns
                                      sandbox_id directly. No intermediate
                                      /v4/file/{data_id} polling needed.
2. GET  /v4/sandbox/{sandbox_id}   -> poll until dynamic analysis produces
                                      a verdict report.
3. GET  full_report.json URL       -> download the complete behavioral
                                      report and save it as
                                      ``Aether_result_<safe-url-name>.json``.

Usage
-----
    python aether-url.py <api_key> <url>
    python aether-url.py <api_key> <url> --dump

Notes
-----
* Sandbox analysis is a paid/entitled feature on most MetaDefender Cloud
  tiers. Free tiers typically get a small daily allowance.
* URL detonation is useful for phishing-page analysis, QR-code landing
  pages, and anything where static reputation alone is insufficient.
* Dynamic analysis typically takes 1-5 minutes.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* https://www.opswat.com/products/metadefender/aether

Author:    Chris Seiler
Copyright: (c) 2026 OPSWAT, Inc. All rights reserved.
"""

import argparse
import json
import re
import sys
import time
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL = "https://api.metadefender.com/v4"

SANDBOX_POLL_INTERVAL_SECONDS = 15
SANDBOX_POLL_TIMEOUT_SECONDS = 1800   # 30 minutes


def submit_url(api_key, url):
    """
    Submit a URL for sandbox analysis.

    Per the MDC v4 "Sandbox URL scan" documentation:
      POST /v4/sandbox
      Headers: apikey, Content-Type: application/json
      Body:    {"url": "..."}
      Response:{"status", "in_queue", "queue_priority", "sandbox_id"}
    """
    endpoint = f"{BASE_URL}/sandbox"
    headers = {
        "apikey": api_key,
        "Content-Type": "application/json",
    }
    body = {"url": url}

    print(f"[+] POST {endpoint}")
    print(f"    url: {url}")
    resp = requests.post(endpoint, headers=headers, json=body)

    if resp.status_code not in (200, 202):
        raise RuntimeError(f"Submit failed (HTTP {resp.status_code}): {resp.text}")

    data = resp.json()
    sandbox_id = data.get("sandbox_id")
    if not sandbox_id:
        raise RuntimeError(f"No sandbox_id in submit response: {data}")

    status = data.get("status")
    in_queue = data.get("in_queue")
    if status or in_queue is not None:
        print(f"    status: {status}, in_queue: {in_queue}")
    print(f"[+] Submit OK. sandbox_id = {sandbox_id}")
    return sandbox_id, data


def _sandbox_report_is_complete(report):
    """
    Decide whether a /v4/sandbox/{id} response is a FINISHED report.

    See aether-file.py for a full explanation - the short version is that
    a finished report contains verdict-shaped fields (``final_verdict``,
    ``scan_results``, ``full_report``, etc.) whereas an in-flight response
    contains only submission metadata.
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
            print("    sandbox report not ready yet (HTTP 202)")
        elif resp.status_code == 200:
            report = resp.json()
            if _sandbox_report_is_complete(report):
                return report
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


def url_to_filename(url):
    """
    Derive a filesystem-safe filename from a URL.

    Examples
    --------
    >>> url_to_filename("https://www.example.com/path/page?q=1")
    'www.example.com_path_page'
    """
    parsed = urlparse(url)
    host = parsed.netloc or "url"
    path = parsed.path.strip("/").replace("/", "_")
    base = f"{host}_{path}" if path else host
    # Strip anything that's not filename-safe on any of Windows/macOS/Linux.
    base = re.sub(r'[<>:"/\\|?*\s]+', "_", base).strip("_")
    return base or "url"


def main():
    """Command-line entry point."""
    ap = argparse.ArgumentParser(
        description="Detonate a URL in the MetaDefender Aether sandbox."
    )
    ap.add_argument("api_key", help="Your MetaDefender Cloud API key")
    ap.add_argument("url", help="The URL to analyze (e.g. https://example.com)")
    ap.add_argument(
        "--dump", action="store_true",
        help="Print the full submit response for debugging.",
    )
    args = ap.parse_args()

    try:
        # 1) Submit the URL - sandbox_id comes back directly.
        sandbox_id, submit_resp = submit_url(args.api_key, args.url)

        if args.dump:
            print("\n----- FULL SUBMIT RESPONSE -----")
            print(json.dumps(submit_resp, indent=2))
            print("----- END RESPONSE -----\n")

        # 2) Poll until the sandbox report is ready.
        report = fetch_sandbox_report(args.api_key, sandbox_id)

        print("\n===== SANDBOX REPORT =====")
        print(json.dumps(report, indent=2))

        # 3) Download the complete behavioural report via full_report.json.
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

        # Save as Aether_result_<safe-url-name>.json
        safe_name = url_to_filename(args.url)
        output_filename = f"Aether_result_{safe_name}.json"
        with open(output_filename, "w", encoding="utf-8") as out:
            json.dump(full_report, out, indent=2)
        print(f"[+] Saved full report to: {output_filename}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
