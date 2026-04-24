"""
multi-scan-file.py
==================

Scan a single file with the OPSWAT MetaDefender Cloud API v4 multi-scan
engine (anti-malware multiscanning across 20+ AV engines).

Workflow
--------
1. POST /v4/file               -> upload the file, receive a data_id
2. GET  /v4/file/{data_id}     -> poll until scan_results.progress_percentage == 100
3. Print a human-readable summary plus the full JSON response

Usage
-----
    python multi-scan-file.py <api_key> <path_to_file>

Example:
    python multi-scan-file.py 70aad1e... report.pdf

Notes
-----
* Results are cached by file hash. Uploading the same file twice may return
  the cached result almost instantly.
* The free-tier API key is rate-limited; heavy usage may produce HTTP 429.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* https://metadefender.opswat.com/account  (check your API quotas)

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
POLL_INTERVAL_SECONDS = 3       # how often to re-check the scan result
POLL_TIMEOUT_SECONDS = 300      # give up after 5 minutes


def analyze_file(api_key: str, file_path: str) -> str:
    """
    Upload a file to MetaDefender Cloud for analysis.

    Parameters
    ----------
    api_key : str
        MetaDefender Cloud API key.
    file_path : str
        Path to the file on disk.

    Returns
    -------
    str
        The ``data_id`` used to poll for scan results.
    """
    url = f"{BASE_URL}/file"
    headers = {
        "apikey": api_key,
        # The /v4/file endpoint accepts either "application/octet-stream" (raw
        # bytes in the body, preferred) or "multipart/form-data".
        "Content-Type": "application/octet-stream",
        # Tell the server the original filename. Optional but recommended.
        "filename": os.path.basename(file_path),
    }

    print(f"[+] Uploading '{file_path}' to {url} ...")
    with open(file_path, "rb") as f:
        # Read the bytes and send them in the request body. Passing f directly
        # causes `requests` to use chunked transfer encoding, which this
        # endpoint does not accept alongside application/octet-stream.
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
    """
    Poll MetaDefender Cloud until the scan for ``data_id`` is complete.

    Parameters
    ----------
    api_key : str
        MetaDefender Cloud API key.
    data_id : str
        Identifier returned by :func:`analyze_file`.

    Returns
    -------
    dict
        The full scan-result JSON once ``progress_percentage`` reaches 100.
    """
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
        scan_results = result.get("scan_results", {})
        progress = scan_results.get("progress_percentage", 0)
        print(f"    progress: {progress}%")

        if progress >= 100:
            return result

        if time.time() - start > POLL_TIMEOUT_SECONDS:
            raise TimeoutError(
                f"Scan did not complete within {POLL_TIMEOUT_SECONDS} seconds."
            )

        time.sleep(POLL_INTERVAL_SECONDS)


def print_summary(result: dict) -> None:
    """Print a concise human-readable summary followed by the full JSON."""
    scan_results = result.get("scan_results", {})
    file_info = result.get("file_info", {})

    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"File name       : {file_info.get('display_name')}")
    print(f"File size       : {file_info.get('file_size')} bytes")
    print(f"SHA256          : {file_info.get('sha256')}")
    print(f"Overall verdict : {scan_results.get('scan_all_result_a')}")
    print(f"Total engines   : {scan_results.get('total_avs')}")
    print(f"Engines flagged : {scan_results.get('total_detected_avs')}")
    print("=" * 60)

    print("\nFULL RESULT (JSON):")
    print(json.dumps(result, indent=2))


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="Scan a file with MetaDefender Cloud API v4 multi-scan."
    )
    parser.add_argument("api_key", help="Your MetaDefender Cloud API key")
    parser.add_argument("file_path", help="Path to the file to scan")
    args = parser.parse_args()

    if not os.path.isfile(args.file_path):
        print(f"Error: file not found: {args.file_path}", file=sys.stderr)
        return 1

    try:
        data_id = analyze_file(args.api_key, args.file_path)
        result = fetch_analysis_result(args.api_key, data_id)
        print_summary(result)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
