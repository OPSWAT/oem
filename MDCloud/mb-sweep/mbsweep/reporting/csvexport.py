"""
The CSV export: one flat row per sample.

Identifiers, links and headline numbers only. Per-object
detail lives in the Markdown report and the raw JSON,
because it does not fit a single row.
"""

import csv

from ..config import CAUGHT_VERDICTS, EXPECTED_CLEAN, EXPECTED_MALICIOUS


def write_csv(path, results):
    """
    One row per sample - the machine-readable summary.

    Deliberately flat: identifiers, links and headline numbers only. The
    per-object detail (engine names, removed CDR objects, individual IOCs)
    lives in the Markdown report and the raw JSON, because it does not fit a
    single row.
    """
    columns = [
        "expected", "false_positive", "original_sha256", "mutation",
        "sha256", "md5", "sha1", "mb_url", "mb_download_cmd", "first_seen", "day", "file_type",
        "file_size", "mb_signature", "mb_tags", "data_id", "sandbox_id",
        "sandbox_report_html", "mdc_verdict", "mdc_threat_level", "caught",
        "chain_depth", "av_overall", "av_scanned", "av_detected", "av_total",
        "av_counts_from_extracted", "av_threats",
        "cdr_ran", "cdr_on_container", "cdr_actions", "cdr_objects_removed", "signal_groups",
        "yara_matches", "mitre_techniques", "mdc_tags", "ioc_count", "error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        for r in results:
            av = r.get("av") or {}
            cdr = r.get("cdr") or {}
            threats = sorted({e["threat"] for e in av.get("engines") or []
                              if e.get("threat")})
            removed = sum((o.get("count") or 1)
                          for o in cdr.get("objects") or []
                          if isinstance(o, dict))
            verdict_upper = (r.get("mdc_verdict") or "").upper()
            detected_av = (av.get("detected") or 0) > 0
            is_control = r.get("expected") == EXPECTED_CLEAN
            writer.writerow([
                r.get("expected", EXPECTED_MALICIOUS),
                "yes" if (is_control and (verdict_upper in CAUGHT_VERDICTS
                                          or detected_av)) else "no",
                r.get("original_sha256", ""), r.get("mutation", ""),
                r["sha256"], r.get("md5", ""), r.get("sha1", ""),
                r.get("mb_url", ""), r.get("mb_download_cmd", ""), r["first_seen"], r["day"],
                r["file_type"], r["file_size"], r["signature"],
                ";".join(r.get("tags") or []),
                r.get("data_id") or "", r.get("sandbox_id") or "",
                r.get("report_html") or "",
                r.get("mdc_verdict") or "",
                r.get("mdc_threat_level") if r.get("mdc_threat_level") is not None else "",
                "yes" if (r.get("mdc_verdict") or "").upper() in CAUGHT_VERDICTS else "no",
                r.get("chain_depth", 0),
                av.get("overall") or "",
                ("yes" if av.get("scanned") else "no") if av else "",
                av.get("detected") if av.get("detected") is not None else "",
                av.get("total") if av.get("total") is not None else "",
                av.get("from_extracted") or "",
                ";".join(threats),
                "yes" if cdr.get("ran") else "no",
                ("yes" if cdr.get("on_container") else "no") if cdr else "",
                cdr.get("actions_ran") or "", removed,
                len(r.get("signal_groups") or []),
                ";".join(y["rule"] for y in r.get("yara") or []),
                ";".join((r.get("mitre") or {}).keys()),
                ";".join(r.get("mdc_tags") or []),
                r.get("ioc_count") if r.get("ioc_count") is not None else "",
                r.get("error") or "",
            ])
