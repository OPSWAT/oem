"""
aether-hash.py
==============

Retrieve the last sandbox (dynamic analysis) report for a file from
OPSWAT MetaDefender Cloud, identified by its hash. If you pass a file
path the script hashes it locally first; if you pass a hash directly,
it uses it as-is.

Workflow
--------
1. If the argument is a file, compute its SHA256 locally (chunked read,
   safe for large files).
2. GET /v4/hash/{sandbox_hash}/sandbox -> returns the most recent sandbox
   report metadata for that hash, or 404 if no sandbox run exists.
3. Optionally fetch the complete behavioural report via ``full_report.json``
   or ``store_at`` and save it to disk.

Usage
-----
    python aether-hash.py <api_key> <file_or_hash>
    python aether-hash.py <api_key> <file_or_hash> --dump
    python aether-hash.py <api_key> <file_or_hash> --fetch-full

Accepted hash formats: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex).

Notes
-----
* A 404 response means no sandbox report exists for that hash. The file
  may have been multiscanned in the past but never sandboxed - upload
  it fresh with ``aether-file.py`` to generate a report.
* The behavioural report can be several megabytes. ``--fetch-full`` saves
  it as ``Aether_result_<name>.json`` in the current directory.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* https://www.opswat.com/products/metadefender/aether

Author:    Chris Seiler
Copyright: (c) 2026 OPSWAT, Inc. All rights reserved.
"""

import argparse
import hashlib
import json
import os
import re
import sys

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL = "https://api.metadefender.com/v4"

# Hex-length -> algorithm, used to auto-detect raw hash inputs.
HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}


def compute_sha256(file_path):
    """
    Compute the SHA256 hash of a file using a streaming read.

    Reads in 1 MB chunks so the script stays memory-efficient on large
    files. Returns the lowercase hex digest.
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):   # 1 MB chunks
            h.update(chunk)
    return h.hexdigest()


def resolve_hash_or_file(arg):
    """
    Figure out whether ``arg`` is a file path or an already-computed hash.

    Returns
    -------
    (hash_value, display_name) : tuple[str, str]
        ``display_name`` is used when building output filenames - the
        original filename minus its extension, or the hash itself.
    """
    # If the argument resolves to a real file on disk, hash it.
    if os.path.isfile(arg):
        print(f"[+] Computing SHA256 of {arg} ...")
        digest = compute_sha256(arg)
        print(f"    SHA256 = {digest}")
        return digest, os.path.splitext(os.path.basename(arg))[0]

    # Otherwise, check if it looks like an MD5/SHA1/SHA256 hex string.
    stripped = arg.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) in HASH_LENGTHS:
        algo = HASH_LENGTHS[len(stripped)]
        print(f"[+] Treating argument as a {algo} hash")
        return stripped, stripped

    raise SystemExit(
        f"Error: '{arg}' is neither a readable file nor a valid MD5/SHA1/SHA256 hash."
    )


def lookup_hash(api_key, sandbox_hash):
    """
    GET /v4/hash/{sandbox_hash}/sandbox and return the parsed JSON.

    Raises RuntimeError with a clear message on 404 (no sandbox report
    exists for this hash) or any other non-200 status.
    """
    url = f"{BASE_URL}/hash/{sandbox_hash}/sandbox"
    headers = {"apikey": api_key}

    print(f"[+] GET {url}")
    resp = requests.get(url, headers=headers)

    if resp.status_code == 404:
        raise RuntimeError(
            f"No sandbox report found for hash {sandbox_hash}. "
            "The file may not have been scanned with sandbox analysis before."
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Lookup failed (HTTP {resp.status_code}): {resp.text}")

    return resp.json()


def print_summary(report):
    """Print a short human-readable summary of the sandbox verdict."""
    fv = report.get("final_verdict") or {}
    sr = report.get("scan_results") or {}

    print("\n" + "=" * 60)
    print("SANDBOX LOOKUP SUMMARY")
    print("=" * 60)
    print(f"MD5        : {report.get('md5')}")
    print(f"SHA1       : {report.get('sha1')}")
    print(f"SHA256     : {report.get('sha256')}")
    print(f"data_id    : {report.get('data_id')}")
    print(f"sandbox_id : {sr.get('sandbox_id')}")
    print(f"Verdict    : {fv.get('verdict')}")
    print(f"ThreatLevel: {fv.get('threatLevel')}")
    print(f"Confidence : {fv.get('confidence')}")
    print(f"Blocked    : {fv.get('blocked')}")
    print(f"Scan result: {sr.get('scan_all_result_a')}")
    print("=" * 60)


def main():
    """Command-line entry point."""
    ap = argparse.ArgumentParser(
        description=(
            "Retrieve a file's last MetaDefender Aether sandbox report "
            "using its hash."
        )
    )
    ap.add_argument("api_key", help="MetaDefender Cloud API key")
    ap.add_argument(
        "file_or_hash",
        help=(
            "Path to a file (will be SHA256-hashed), or a raw "
            "MD5/SHA1/SHA256 hash string"
        ),
    )
    ap.add_argument(
        "--dump", action="store_true",
        help="Print the full response JSON in addition to the summary",
    )
    ap.add_argument(
        "--fetch-full", action="store_true",
        help="Also download the full_report.json and save it to disk",
    )
    args = ap.parse_args()

    try:
        sandbox_hash, display_name = resolve_hash_or_file(args.file_or_hash)
        report = lookup_hash(args.api_key, sandbox_hash)
        print_summary(report)

        if args.dump:
            print("\n----- FULL RESPONSE -----")
            print(json.dumps(report, indent=2))
            print("----- END RESPONSE -----")

        if args.fetch_full:
            # Prefer full_report.json; fall back to the pre-signed store_at URL.
            full_report_url = (
                (report.get("full_report") or {}).get("json")
                or report.get("store_at")
                or (report.get("scan_results") or {}).get("store_at")
            )
            if not full_report_url:
                print(
                    "\n[!] No full_report.json or store_at URL in response; "
                    "nothing to download."
                )
            else:
                print(f"\n[+] Downloading full report from {full_report_url}")
                headers = {"apikey": args.api_key}
                r = requests.get(full_report_url, headers=headers)
                if r.status_code != 200:
                    raise RuntimeError(
                        f"Full report download failed "
                        f"(HTTP {r.status_code}): {r.text}"
                    )
                full_report = r.json()
                output_filename = f"Aether_result_{display_name}.json"
                with open(output_filename, "w", encoding="utf-8") as out:
                    json.dump(full_report, out, indent=2)
                print(f"[+] Saved full report to: {output_filename}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
