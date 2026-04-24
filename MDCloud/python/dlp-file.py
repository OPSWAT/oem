"""
dlp-file.py
===========

Scan a single file with OPSWAT MetaDefender Cloud Proactive DLP (Data Loss
Prevention). DLP detects sensitive content such as SSNs, credit-card
numbers, HIPAA/PII indicators, classification markings, and custom regex
patterns. It is a detection-only workflow - the file itself is not
modified and there is nothing to download afterwards.

Workflow
--------
1. POST /v4/file                         -> upload with header ``rule: dlp``
2. GET  /v4/file/{data_id}               -> poll until progress_percentage == 100
3. Summarize DLP findings from ``dlp_info`` in the result.

Usage
-----
    python dlp-file.py <api_key> <path_to_file>
    python dlp-file.py <api_key> <path_to_file> --dump

Notes
-----
* DLP verdicts are numeric in the API response:
  0 = no findings / allowed, 1 = sensitive data found, 2 = blocked.
* ``certainty`` indicates engine confidence in the match (Low/Medium/High).
* To run DLP alongside another workflow, combine rules, e.g.
  ``rule: multiscan,dlp``.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* https://www.opswat.com/technologies/data-loss-prevention

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
POLL_INTERVAL_SECONDS = 3
POLL_TIMEOUT_SECONDS = 300


def analyze_file_dlp(api_key: str, file_path: str) -> str:
    """
    Upload a file and request Proactive DLP only.

    The ``rule: dlp`` header selects the DLP workflow on MetaDefender Cloud.
    """
    url = f"{BASE_URL}/file"
    headers = {
        "apikey": api_key,
        "Content-Type": "application/octet-stream",
        "filename": os.path.basename(file_path),
        "rule": "dlp",
    }

    print(f"[+] Uploading '{file_path}' to {url} with rule='dlp' (Proactive DLP) ...")
    with open(file_path, "rb") as f:
        response = requests.post(url, headers=headers, data=f.read())

    if response.status_code != 200:
        raise RuntimeError(
            f"Upload failed (HTTP {response.status_code}): {response.text}"
        )

    data = response.json()
    data_id = data.get("data_id")
    if not data_id:
        raise RuntimeError(f"No data_id in response: {data}")

    print(f"[+] Upload successful. data_id = {data_id}")
    return data_id


def fetch_analysis_result(api_key: str, data_id: str) -> dict:
    """Poll /v4/file/{data_id} until the scan reaches 100% progress."""
    url = f"{BASE_URL}/file/{data_id}"
    headers = {"apikey": api_key}

    print(f"[+] Fetching analysis result from {url} ...")
    start = time.time()

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(
                f"Fetch failed (HTTP {response.status_code}): {response.text}"
            )

        result = response.json()
        progress = result.get("scan_results", {}).get("progress_percentage", 0)
        print(f"    progress: {progress}%")

        if progress >= 100:
            return result

        if time.time() - start > POLL_TIMEOUT_SECONDS:
            raise TimeoutError(
                f"Scan did not complete within {POLL_TIMEOUT_SECONDS} seconds."
            )

        time.sleep(POLL_INTERVAL_SECONDS)


def _format_hit_value(value):
    """
    Render a single entry in ``dlp_info.hits`` as a short, readable string.

    DLP hit values come in several shapes across MDC versions - plain ints,
    lists of match objects, or dicts with a ``count``/``hits``/``matches``
    sub-field. This helper normalises all of them into a one-line summary.
    """
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return f"{len(value)} match(es)"
    if isinstance(value, dict):
        # Try the most common count-bearing field names first.
        for key in ("count", "hits", "total", "matches"):
            if key in value and isinstance(value[key], int):
                return str(value[key])
        # Otherwise look for a nested list we can count.
        for k, v in value.items():
            if isinstance(v, list):
                return f"{len(v)} match(es) (via '{k}')"
        # Last resort: list the dict's keys so the user can investigate.
        return f"(keys: {', '.join(value.keys())})"
    return str(value)


def print_summary(result: dict) -> None:
    """Print a DLP-focused summary of the scan result."""
    file_info = result.get("file_info", {})
    process_info = result.get("process_info", {}) or {}
    dlp_info = result.get("dlp_info") or {}

    print("\n" + "=" * 60)
    print("PROACTIVE DLP SUMMARY")
    print("=" * 60)
    print(f"File name         : {file_info.get('display_name')}")
    print(f"File size         : {file_info.get('file_size')} bytes")
    print(f"SHA256            : {file_info.get('sha256')}")
    print(f"Processing result : {process_info.get('result')}")
    print(f"Blocked reason    : {process_info.get('blocked_reason') or '(none)'}")

    verdict = dlp_info.get("verdict")
    certainty = dlp_info.get("certainty")
    hits = dlp_info.get("hits") or {}

    # Translate numeric verdict to a label for readability.
    verdict_labels = {
        0: "No findings / Allowed",
        1: "Sensitive data found",
        2: "Blocked",
    }
    verdict_display = (
        f"{verdict} ({verdict_labels[verdict]})"
        if verdict in verdict_labels
        else str(verdict)
    )

    print(f"DLP verdict       : {verdict_display}")
    print(f"DLP certainty     : {certainty}")

    if hits:
        print("\nDLP hits by category:")
        for category, info in hits.items():
            print(f"  - {category}: {_format_hit_value(info)}")
            # If the hit contains nested match samples, show up to three.
            if isinstance(info, dict):
                for nested_key in ("hits", "matches"):
                    matches = info.get(nested_key)
                    if isinstance(matches, list) and matches:
                        print(f"      first {min(3, len(matches))} sample(s):")
                        for m in matches[:3]:
                            print(f"        {m}")
                        break
    else:
        print("\n(No DLP hits found - either the file contains no sensitive")
        print(" content, or the DLP engine didn't run. Use --dump to inspect")
        print(" the full response.)")

    print("=" * 60)


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="Run Proactive DLP on a file using MetaDefender Cloud API v4."
    )
    parser.add_argument("api_key", help="Your MetaDefender Cloud API key")
    parser.add_argument("file_path", help="Path to the file to scan with DLP")
    parser.add_argument(
        "--dump", action="store_true",
        help="Print the full JSON response in addition to the summary.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file_path):
        print(f"Error: file not found: {args.file_path}", file=sys.stderr)
        return 1

    try:
        data_id = analyze_file_dlp(args.api_key, args.file_path)
        result = fetch_analysis_result(args.api_key, data_id)
        print_summary(result)

        if args.dump:
            print("\nFULL RESULT (JSON):")
            print(json.dumps(result, indent=2))

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
