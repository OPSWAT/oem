"""
cdr-file.py
===========

Sanitize a single file with OPSWAT MetaDefender Cloud Deep CDR (Content
Disarm and Reconstruction). CDR rebuilds the file from scratch, stripping
out potentially malicious active content (macros, embedded scripts, OLE
objects, JavaScript in PDFs, etc.) while preserving usability.

Workflow
--------
1. POST /v4/file                         -> upload with header ``rule: cdr``
2. GET  /v4/file/{data_id}               -> poll until progress_percentage == 100
3. If CDR produced a clean file, download it from the pre-signed S3 URL
   returned under ``sanitized.file_path`` in the scan result.

Usage
-----
    python cdr-file.py <api_key> <path_to_file>
    python cdr-file.py <api_key> <path_to_file> --dump

Output
------
* If the file was sanitized, the clean version is saved as
  ``sanitized_<original_name>`` in the current directory.
* If the file was already clean (or the type isn't supported by CDR), no
  file is written and a message is printed.

Notes
-----
* The sanitized file is retained by OPSWAT for 24 hours only. Download it
  in the same run.
* CDR is billed separately from multi-scanning on most MetaDefender Cloud
  tiers.
* ``rule: cdr`` triggers Deep CDR on its own. To combine workflows, use a
  comma-separated value such as ``multiscan,cdr``.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* https://www.opswat.com/technologies/deep-cdr

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


def analyze_file_cdr(api_key: str, file_path: str) -> str:
    """
    Upload a file and request Deep CDR only.

    The ``rule: cdr`` header selects the Deep CDR workflow on MetaDefender
    Cloud. Other valid rule values include ``multiscan``, ``dlp``,
    ``sanitize``, ``unarchive``, and combinations such as
    ``multiscan_sanitize_unarchive``.

    Parameters
    ----------
    api_key : str
        MetaDefender Cloud API key.
    file_path : str
        Path to the file on disk.

    Returns
    -------
    str
        The ``data_id`` used to poll for the sanitization result.
    """
    url = f"{BASE_URL}/file"
    headers = {
        "apikey": api_key,
        "Content-Type": "application/octet-stream",
        "filename": os.path.basename(file_path),
        # Selects the Deep CDR workflow.
        "rule": "cdr",
    }

    print(f"[+] Uploading '{file_path}' to {url} with rule='cdr' (Deep CDR) ...")
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
    """
    Poll /v4/file/{data_id} until the CDR run reaches 100% progress.

    Returns the full scan-result JSON, which includes the ``sanitized``
    object with a pre-signed S3 URL for the reconstructed file (if one
    was produced).
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
        progress = result.get("scan_results", {}).get("progress_percentage", 0)
        print(f"    progress: {progress}%")

        if progress >= 100:
            return result

        if time.time() - start > POLL_TIMEOUT_SECONDS:
            raise TimeoutError(
                f"Scan did not complete within {POLL_TIMEOUT_SECONDS} seconds."
            )

        time.sleep(POLL_INTERVAL_SECONDS)


def print_summary(result: dict) -> None:
    """Print a CDR-focused summary of the scan result."""
    file_info = result.get("file_info", {})
    process_info = result.get("process_info", {})
    post_processing = process_info.get("post_processing", {}) or {}
    sanitized = result.get("sanitized", {}) or {}

    # sanitization_details may come back as a string or a dict in different
    # MDC versions; surface whichever we get.
    details = post_processing.get("sanitization_details")
    if isinstance(details, dict):
        details = details.get("description") or details

    print("\n" + "=" * 60)
    print("DEEP CDR SUMMARY")
    print("=" * 60)
    print(f"File name            : {file_info.get('display_name')}")
    print(f"File size            : {file_info.get('file_size')} bytes")
    print(f"SHA256               : {file_info.get('sha256')}")
    print(f"Processing result    : {process_info.get('result')}")
    print(f"Post-processing      : {post_processing.get('actions_ran')}")
    print(f"Sanitization result  : {details}")
    print(f"Converted to         : {post_processing.get('converted_to')}")
    print(f"Copy-move dest       : {post_processing.get('copy_move_destination')}")
    print(f"Sanitized download   : {sanitized.get('file_path')}")
    print(f"Sanitized reason     : {sanitized.get('reason')}")
    print("=" * 60)


def was_sanitized(result: dict) -> bool:
    """
    Return True if Deep CDR actually produced a sanitized version of the file.

    MDC reports CDR status in a few places depending on version. Any of the
    following signals counts as "sanitized":
      * ``process_info.post_processing.actions_ran`` contains "Sanitized"
      * ``process_info.result`` mentions "Sanitized"
      * ``sanitized.file_path`` is present (pre-signed URL to the clean file)
    """
    pi = result.get("process_info") or {}
    pp = pi.get("post_processing") or {}

    actions_ran = (pp.get("actions_ran") or "").lower()
    if "sanitized" in actions_ran:
        return True

    if "sanitized" in (pi.get("result") or "").lower():
        return True

    sanitized = result.get("sanitized") or {}
    if sanitized.get("file_path"):
        return True

    return False


def download_sanitized(api_key: str, result: dict, original_name: str) -> str:
    """
    Download the sanitized (CDR-reconstructed) file.

    The scan result already contains a pre-signed AWS S3 URL under
    ``sanitized.file_path``. There is no need to call the
    ``/v4/file/converted/{data_id}`` endpoint; we just GET the signed URL
    directly. The signed URL does not require the ``apikey`` header (and
    passing one can interfere with S3 signature verification).

    Saves the file as ``sanitized_<original_name>`` in the current directory.
    """
    sanitized = result.get("sanitized") or {}
    sanitized_url = sanitized.get("file_path")

    if not sanitized_url:
        raise RuntimeError(
            "No sanitized.file_path in the scan result - cannot download."
        )

    print(f"[+] GET {sanitized_url.split('?')[0]}  (sanitized file, signed URL)")
    file_response = requests.get(sanitized_url)
    if file_response.status_code != 200:
        raise RuntimeError(
            f"Sanitized download failed (HTTP {file_response.status_code}): "
            f"{file_response.text[:500]}"
        )

    output = f"sanitized_{original_name}"
    with open(output, "wb") as out:
        out.write(file_response.content)

    print(f"[+] Saved sanitized file to: {output}")
    return output


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="Run Deep CDR on a file using MetaDefender Cloud API v4."
    )
    parser.add_argument("api_key", help="Your MetaDefender Cloud API key")
    parser.add_argument("file_path", help="Path to the file to sanitize")
    parser.add_argument(
        "--dump", action="store_true",
        help="Print the full JSON response in addition to the summary.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file_path):
        print(f"Error: file not found: {args.file_path}", file=sys.stderr)
        return 1

    try:
        data_id = analyze_file_cdr(args.api_key, args.file_path)
        result = fetch_analysis_result(args.api_key, data_id)
        print_summary(result)

        if args.dump:
            print("\nFULL RESULT (JSON):")
            print(json.dumps(result, indent=2))

        if was_sanitized(result):
            print("\n[+] File was sanitized by Deep CDR - downloading clean version.")
            download_sanitized(
                args.api_key, result, os.path.basename(args.file_path)
            )
        else:
            print("\n[!] File was not sanitized - no clean version to download.")
            print("    (CDR may have passed it through unchanged, or the file type")
            print("     is not supported by Deep CDR.)")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
