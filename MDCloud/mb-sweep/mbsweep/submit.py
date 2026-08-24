"""
Submitting files to MetaDefender Cloud.

One POST per workflow, because the rule header takes a
single workflow at a time. Nothing here waits for a result -
submissions return data_ids and the poller takes over.
"""

import json
import os

import requests

from .config import (
    EXPECTED_MALICIOUS, MB_API_URL, MB_SAMPLE_URL, MDC_BASE_URL,
)


# ---------------------------------------------------------------------------
# MetaDefender Cloud
# ---------------------------------------------------------------------------
def mdc_submit(api_key, file_path, sandbox=None, rule=None, archive_password=None):
    """POST /v4/file. Returns the data_id, or raises with a clear message."""
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

    with open(file_path, "rb") as f:
        resp = requests.post(f"{MDC_BASE_URL}/file", headers=headers, data=f.read())

    if resp.status_code == 429:
        raise RuntimeError(
            f"MetaDefender daily limit reached (HTTP 429; "
            f"{describe_api_error(resp)}). Sandbox runs are metered separately "
            f"from scans - see 'limit_sandbox' on GET /v4/apikey."
        )
    if resp.status_code != 200:
        raise RuntimeError(
            f"upload rejected (HTTP {resp.status_code}; "
            f"{describe_api_error(resp)})")

    try:
        body = resp.json()
    except ValueError:
        raise RuntimeError(
            f"upload returned HTTP 200 with a body that is not JSON: "
            f"{resp.text[:200]}")

    # A 200 can still carry an error object rather than a data_id.
    data_id = body.get("data_id")
    if not data_id:
        raise RuntimeError(f"no data_id in response ({describe_api_error(resp)})")
    return data_id


def describe_api_error(resp):
    """
    Render MetaDefender's own error code and messages.

    The API answers failures with {"error": {"code": 400020, "messages": [...]}}.
    Reporting that code beats dumping the raw body: the code is what a support
    ticket or the documentation is keyed on.
    """
    try:
        body = resp.json()
    except ValueError:
        return f"non-JSON body: {resp.text[:160]}"

    error = body.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        messages = error.get("messages") or []
        rendered = "; ".join(str(m) for m in messages) or "no message"
        return f"code {code}: {rendered}" if code else rendered

    return f"body: {json.dumps(body)[:160]}"


def blank_outcome(sample):
    """The per-sample result skeleton, so every row has every key."""
    outcome = dict(sample)
    outcome.update({
        "mb_url": MB_SAMPLE_URL + sample["sha256"],
        # MalwareBazaar has no GET download link - /download/<sha256>/
        # serves an HTML page, not the archive. Re-fetching is an
        # authenticated POST, so record the exact command instead of a
        # URL that would not work when pasted into a browser.
        "mb_download_cmd": (
            f'curl -X POST {MB_API_URL} -H "Auth-Key: $MB_AUTH_KEY" '
            f'-d "query=get_file&sha256_hash={sample["sha256"]}" '
            f'-o {sample["sha256"]}.zip'
        ),
        "data_id": None, "sandbox_id": None, "chain": [],
        "report_html": None, "report_json": None, "report_pdf": None,
        "expected": sample.get("expected", EXPECTED_MALICIOUS),
        "original_sha256": sample.get("original_sha256", ""),
        "mutation": sample.get("mutation", ""),
        "mdc_verdict": None, "mdc_threat_level": None, "chain_depth": 0,
        "av": None, "cdr": None,
        "signal_groups": [], "yara": [], "mdc_tags": [], "mitre": {},
        "iocs_by_type": {}, "ioc_count": None, "error": None,
    })
    return outcome


def submit_one(api_key, sample, file_path, want_av, want_cdr, archive_password):
    """
    Fire off every submission for one file and return the tracking record.

    Nothing is waited on here. The returned dict is the entry in the pending
    map: the sample (carrying its expectation), the data_ids just handed out,
    and the per-view progress flags the poller drives to completion.
    """
    entry = {
        "sample": sample,
        "outcome": blank_outcome(sample),
        "sandbox_data_id": None,
        "av_data_id": None,
        "cdr_data_id": None,
        "sandbox_id": None,
        "sandbox_done": not True,     # explicit: nothing resolved yet
        "av_done": not want_av,
        "cdr_done": not want_cdr,
        "stage": "submitting",
        "error": None,
    }

    try:
        entry["sandbox_data_id"] = mdc_submit(
            api_key, file_path, sandbox="windows10",
            archive_password=archive_password)
        entry["outcome"]["data_id"] = entry["sandbox_data_id"]
        entry["stage"] = "file scan"

        if want_av:
            entry["av_data_id"] = mdc_submit(
                api_key, file_path, rule="multiscan",
                archive_password=archive_password)
        if want_cdr:
            entry["cdr_data_id"] = mdc_submit(
                api_key, file_path, rule="cdr",
                archive_password=archive_password)
    except (RuntimeError, requests.RequestException) as exc:
        entry["error"] = str(exc)
        entry["stage"] = "submit failed"

    return entry
