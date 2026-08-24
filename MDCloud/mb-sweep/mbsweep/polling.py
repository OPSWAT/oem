"""
Polling the submitted batch to completion.

Everything is submitted first, then driven here. Each entry
runs a small state machine, because the three views finish at
very different speeds. Anything unresolved when the window
closes is an error, never a pass.
"""

import json
import time

import requests

from .config import (
    ARCHIVE_SAMPLE_TYPES, EXPECTED_MALICIOUS, NESTED_ARCHIVE_NOTE,
    verdict_rank,
)
from .reportfetch import (
    collect_av, collect_cdr, file_scan_finished,
    mdc_report_summary, mdc_walk_chain,
)
from .config import MDC_BASE_URL


def advance_entry(api_key, entry):
    """
    Move one pending entry as far forward as it will go this round.

    Each view is independent: the AV and CDR passes are ordinary scans that
    finish in seconds, while the sandbox has to reach 100% on the file scan,
    then produce a verdict, then have its report fetched. Returns True when
    everything asked for has resolved.
    """
    outcome = entry["outcome"]

    # ---- Sandbox: file scan -> sandbox verdict -> report.
    if not entry["sandbox_done"]:
        if entry["sandbox_id"] is None:
            payload = file_scan_finished(api_key, entry["sandbox_data_id"])
            if payload is not None:
                entry["sandbox_id"] = payload.get("sandbox_id")
                outcome["sandbox_id"] = entry["sandbox_id"]
                if not entry["sandbox_id"]:
                    outcome["error"] = ("no sandbox_id (entitlement or "
                                        "unsupported file type)")
                    entry["sandbox_done"] = True
                    entry["stage"] = "no sandbox"
                else:
                    entry["stage"] = "detonating"
                    # The AV view sometimes rides along on this response.
                    if (not entry["av_done"]
                            and ((payload.get("scan_results") or {})
                                 .get("total_avs") or 0) > 0):
                        outcome["av"] = collect_av(payload, api_key)
                        entry["av_done"] = True
        else:
            try:
                resp = requests.get(
                    f"{MDC_BASE_URL}/sandbox/{entry['sandbox_id']}",
                    headers={"apikey": api_key}, timeout=60)
                meta = resp.json() if resp.status_code == 200 else {}
            except (requests.RequestException, json.JSONDecodeError):
                meta = {}

            if meta.get("final_verdict") or meta.get("full_report"):
                report_urls = meta.get("full_report") or {}
                outcome["report_html"] = report_urls.get("html")
                outcome["report_json"] = report_urls.get("json")
                outcome["report_pdf"] = report_urls.get("pdf")

                chain = mdc_walk_chain(api_key, entry["sandbox_id"])
                if chain:
                    outcome["chain"] = chain
                    worst = min(chain, key=lambda n: verdict_rank(n["verdict"]))
                    outcome["mdc_verdict"] = worst["verdict"]
                    outcome["mdc_threat_level"] = worst["threat_level"]
                    outcome["chain_depth"] = max(n["depth"] for n in chain)

                    with_report = [n for n in chain if n["report_url"]]
                    if with_report:
                        deepest = max(with_report, key=lambda n: n["depth"])
                        outcome.update(
                            mdc_report_summary(api_key, deepest["report_url"]))
                else:
                    outcome["error"] = "empty report chain"
                entry["sandbox_done"] = True
                entry["stage"] = "done"

    # ---- AV multiscan.
    if not entry["av_done"] and entry["av_data_id"]:
        payload = file_scan_finished(api_key, entry["av_data_id"])
        if payload is not None:
            outcome["av"] = collect_av(payload, api_key)
            entry["av_done"] = True

    # ---- Deep CDR.
    if not entry["cdr_done"] and entry["cdr_data_id"]:
        payload = file_scan_finished(api_key, entry["cdr_data_id"])
        if payload is not None:
            outcome["cdr"] = collect_cdr(payload)
            entry["cdr_done"] = True

    return entry["sandbox_done"] and entry["av_done"] and entry["cdr_done"]


def describe_stall(api_key, entry):
    """
    Explain why a submission produced nothing, as far as the API will say.

    A bare "timed out" is not actionable. This pulls what the file endpoint
    knows - the type it decided on, whether the AV pass ran, any blocked
    reason - and adds the nested-archive explanation when it applies, which in
    testing accounted for every stalled sample.
    """
    sample = entry["sample"]
    notes = []

    file_type = (sample.get("file_type") or "").lower()
    if file_type in ARCHIVE_SAMPLE_TYPES:
        notes.append(f"{NESTED_ARCHIVE_NOTE} (.{file_type})")

    data_id = entry.get("sandbox_data_id")
    if data_id:
        try:
            resp = requests.get(f"{MDC_BASE_URL}/file/{data_id}",
                                headers={"apikey": api_key}, timeout=30)
            payload = resp.json() if resp.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            payload = {}

        scan_results = payload.get("scan_results") or {}
        process = payload.get("process_info") or {}
        file_info = payload.get("file_info") or {}

        detail = []
        if scan_results.get("scan_all_result_a"):
            detail.append(f"scan={scan_results['scan_all_result_a']}")
        if process.get("result"):
            detail.append(f"process={process['result']}")
        if process.get("blocked_reason"):
            detail.append(f"blocked={process['blocked_reason']}")
        if file_info.get("file_type_description"):
            detail.append(f"detected={file_info['file_type_description']}")
        if detail:
            notes.append(", ".join(detail))

    return "; ".join(notes)


def describe_av_line(av):
    """
    One line stating the AV verdict and the engine count, unambiguously.

    "Not scanned" and "scanned, nothing found" are different results and must
    not read the same - particularly on a known-malicious sample, where the
    second is a finding and the first is a gap in the measurement.
    """
    if not av:
        return "not requested"
    if not av.get("scanned"):
        return f"NOT SCANNED ({av.get('overall') or 'no result'}) - no engine verdict"

    detected = av.get("detected") or 0
    total = av.get("total") or 0
    verdict = av.get("overall") or "unknown"
    line = f"{verdict} - {detected} of {total} engine(s) detected it"

    if av.get("from_extracted"):
        # Say so, briefly: the numbers describe the file inside the archive,
        # not the container that was submitted. The full name is in the report.
        line += " [counts from the extracted file]"

    threats = sorted({e["threat"] for e in av.get("engines") or [] if e.get("threat")})
    if threats:
        shown = ", ".join(threats[:3])
        if len(threats) > 3:
            shown += f" +{len(threats) - 3}"
        line += f"  -> {shown}"
    return line


def describe_cdr_line(cdr):
    """One line stating what Deep CDR did, or why it did nothing."""
    if not cdr:
        return "not requested"
    if not cdr.get("ran"):
        return (f"NOT SANITIZED - "
                f"{cdr.get('sanitized_reason') or cdr.get('description') or 'no action'}")
    removed = sum((o.get("count") or 1) for o in cdr.get("objects") or []
                  if isinstance(o, dict))
    line = f"{cdr.get('actions_ran') or 'processed'}"
    if cdr.get("converted_to"):
        line += f" as {cdr['converted_to']}"
    line += f" - {removed} object(s) removed"
    classes = sorted({o.get("object_name") for o in cdr.get("objects") or []
                      if isinstance(o, dict) and o.get("object_name")})
    if classes:
        line += f" ({', '.join(classes[:3])})"
    if cdr.get("on_container"):
        line += " [acted on the submitted archive, not the file inside]"
    return line


def poll_for_results(api_key, pending, interval, window_minutes):
    """
    Poll every ``interval`` seconds until everything resolves or time is up.

    Anything still unresolved when the window closes is recorded as an error
    naming the stage it was stuck at - a sample with no result is a failed
    measurement, not a passing one, and must not be reported as clean.
    """
    deadline = time.time() + window_minutes * 60
    live = {key: entry for key, entry in pending.items() if not entry["error"]}

    print(f"\n[+] Polling every {interval}s for up to {window_minutes} "
          f"minutes ({len(live)} submission(s) in flight)")

    round_number = 0
    while live and time.time() < deadline:
        round_number += 1
        finished = []

        for key, entry in live.items():
            try:
                if advance_entry(api_key, entry):
                    finished.append(key)
            except (RuntimeError, requests.RequestException) as exc:
                entry["error"] = str(exc)
                entry["outcome"]["error"] = str(exc)
                finished.append(key)

        for key in finished:
            entry = live[key]
            sample = entry["sample"]
            outcome = entry["outcome"]
            verdict = outcome.get("mdc_verdict") or "ERROR"
            print(f"    [{round_number:>2}] {key[:16]}... {verdict:<17} "
                  f"{sample['file_type'] or '?':<6} "
                  f"({sample.get('expected', EXPECTED_MALICIOUS)})")
            # All three views, per sample, as each resolves - a sandbox verdict
            # on its own says nothing about what AV or CDR made of the file.
            print(f"         multi-scan: {describe_av_line(outcome.get('av'))}")
            print(f"         deep cdr  : {describe_cdr_line(outcome.get('cdr'))}")
            del live[key]

        if not live:
            break

        remaining = int(deadline - time.time())
        if remaining <= 0:
            break
        print(f"    [{round_number:>2}] {len(live)} still pending, "
              f"{remaining // 60}m{remaining % 60:02d}s left "
              f"({', '.join(sorted({e['stage'] for e in live.values()}))})")
        time.sleep(min(interval, max(1, remaining)))

    # Whatever is left never produced a result inside the window.
    for key, entry in live.items():
        message = (f"no result within {window_minutes} minutes "
                   f"(stalled at: {entry['stage']})")
        diagnosis = describe_stall(api_key, entry)
        if diagnosis:
            message += f" - {diagnosis}"
        entry["error"] = message
        entry["outcome"]["error"] = message
        entry["outcome"]["stall_diagnosis"] = diagnosis
        print(f"    ! {key[:16]}... {message}")

    return [entry["outcome"] for entry in pending.values()]
