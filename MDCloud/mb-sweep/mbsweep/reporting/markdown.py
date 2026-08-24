"""
The Markdown report: summary table and per-sample dossiers.

The deliverable a product team reads. The summary table is
for scanning a whole run at once; the dossiers carry enough
detail to act on a finding without re-running anything.
"""

from collections import Counter, defaultdict

from .avstats import (
    detections_without_engine, engine_breakdown, sorted_engines,
)
from ..config import (
    CLEAN_CODES, DETECTED_CODES, SCAN_CODE_MEANINGS,
    CAUGHT_VERDICTS, EXPECTED_CLEAN, EXPECTED_MALICIOUS, IOCS_IN_REPORT,
    SIGNALS_IN_REPORT, VERDICT_ORDER, file_category, verdict_rank,
)


def describe_multiscan(row):
    """
    One cell describing the AV result: the verdict, then the engine count.

    Kept deliberately explicit about three distinct states, which a single
    number cannot express: engines ran and flagged it, engines ran and found
    nothing, or no AV verdict exists at all. On a known-malicious sample the
    middle case is a finding and the last is a gap in the measurement.
    """
    av = row.get("av")
    if not av:
        return "not requested"
    if not av.get("scanned"):
        return f"**NOT SCANNED**<br>{av.get('overall') or 'no engine verdict'}"

    overall = av.get("overall") or "unknown"
    detected = av.get("detected") or 0
    total = av.get("total") or 0
    cell = (f"**{overall}**<br>{detected} of {total} engine(s) detected it")

    if av.get("from_extracted"):
        # The container is clean by construction; these numbers are the
        # extracted file's, and saying so avoids a confusing mismatch.
        cell += "<br><sub>counts are for the extracted file</sub>"

    threats = sorted({e["threat"] for e in av.get("engines") or []
                      if e.get("threat")})
    if threats:
        shown = ", ".join(f"`{t}`" for t in threats[:2])
        if len(threats) > 2:
            shown += f" +{len(threats) - 2}"
        cell += f"<br>{shown}"
    return cell


def describe_cdr(row):
    """One cell describing what Deep CDR did."""
    cdr = row.get("cdr")
    if not cdr:
        return "not gathered"
    if not cdr.get("ran"):
        return cdr.get("sanitized_reason") or cdr.get("description") or "not sanitized"
    removed = sum((o.get("count") or 1) for o in cdr.get("objects") or []
                  if isinstance(o, dict))
    cell = f"**{cdr.get('actions_ran') or 'processed'}**"
    if cdr.get("converted_to"):
        cell += f" as {cdr['converted_to']}"
    cell += f"<br>{removed} object(s) removed"
    if cdr.get("objects"):
        classes = sorted({o.get("object_name") for o in cdr["objects"]
                          if isinstance(o, dict) and o.get("object_name")})
        if classes:
            cell += f" ({', '.join(classes[:3])})"
    if cdr.get("on_container"):
        cell += "<br><sub>on the submitted archive</sub>"
    return cell


def describe_sandbox(row):
    """One cell describing the sandbox verdict and what drove it."""
    verdict = row.get("mdc_verdict")
    if not verdict:
        return "no verdict"
    level = row.get("mdc_threat_level")
    cell = f"**{verdict}**"
    if level is not None:
        cell += f" ({level})"
    bits = []
    groups = row.get("signal_groups") or []
    if groups:
        bits.append(f"{len(groups)} signal group(s)")
    if row.get("yara"):
        bits.append(f"{len(row['yara'])} YARA")
    if row.get("ioc_count"):
        bits.append(f"{row['ioc_count']} IOC(s)")
    if bits:
        cell += "<br>" + ", ".join(bits)
    return cell


def build_results_summary(results):
    """
    One row per submitted file, with the three engine results side by side.

    The per-sample dossiers further down carry the full detail; this table is
    for scanning the whole run at once - which sample was caught by what, and
    where the three views disagree. Disagreement is the interesting signal: a
    sample the sandbox calls MALICIOUS while no AV engine fires is a very
    different finding from one both agree on.
    """
    lines = [
        "",
        "## Results summary",
        "",
        "One row per file. `Expected` is what the sample is supposed to be, so a "
        "detection on a `clean` row is a false positive and a quiet `malicious` "
        "row is a miss.",
        "",
        "| # | File | Expected | Multi-Scan | Deep CDR | Sandbox |",
        "|---|---|---|---|---|---|",
    ]

    ordered = sorted(
        results,
        key=lambda r: (r.get("expected") != EXPECTED_MALICIOUS,
                       verdict_rank(r.get("mdc_verdict"))),
    )

    for position, row in enumerate(ordered, start=1):
        name = row.get("file_name") or row["sha256"][:16]
        if len(name) > 34:
            name = name[:31] + "..."
        label = f"`{name}`<br>{row.get('signature') or '-'} / {row.get('file_type') or '?'}"

        if row.get("error"):
            # No result means no measurement: show the failure rather than
            # implying the engines returned something clean.
            lines.append(
                f"| {position} | {label} | {row.get('expected', '?')} | "
                f"- | - | **ERROR**<br>{row['error']} |"
            )
            continue

        lines.append(
            f"| {position} | {label} | {row.get('expected', '?')} | "
            f"{describe_multiscan(row)} | {describe_cdr(row)} | "
            f"{describe_sandbox(row)} |"
        )

    lines.append("")   # keep the next heading separated
    return lines


def build_engine_summary(results, malware, controls):
    """
    Per-engine results across the whole corpus, plus unattributed detections.

    The per-sample dossiers say which engines fired on one file; this says
    which engines are contributing across the run, and flags any engine that
    hit a known-clean control.
    """
    ok = [r for r in results if not r.get("error")]
    stats = engine_breakdown(ok)
    lines = []

    malware_scanned = len([r for r in malware if (r.get("av") or {}).get("scanned")])
    control_scanned = len([r for r in controls if (r.get("av") or {}).get("scanned")])

    if stats:
        lines += [
            "",
            "## AV engine results",
            "",
            f"Every engine that returned a verdict, across {malware_scanned} "
            f"malware sample(s) and {control_scanned} clean control(s). "
            f"`Detected` counts detections out of the samples the engine "
            f"actually examined - an engine that answered "
            f"`filetype not supported` did not look and miss, so it is "
            f"excluded from that denominator and counted under `Not scanned` "
            f"instead. `Controls` is hits on files known to be clean, where "
            f"anything above zero is a false positive.",
            "",
            "| Engine | Detected | Not scanned | Controls | Threat names |",
            "|---|---|---|---|---|",
        ]
        for name, entry in sorted_engines(stats):
            threats = sorted(entry["threats"])
            shown = ", ".join(f"`{t}`" for t in threats[:3])
            if len(threats) > 3:
                shown += f" +{len(threats) - 3}"
            control_cell = (f"**{entry['controls_flagged']}**/"
                            f"{entry['controls_scanned']}"
                            if entry["controls_flagged"]
                            else f"{entry['controls_flagged']}/"
                                 f"{entry['controls_scanned']}")
            if entry["malware_not_scanned"]:
                reasons = ", ".join(
                    f"{count}x {reason}"
                    for reason, count in entry["skip_reasons"].most_common(2))
                skipped_cell = f"{entry['malware_not_scanned']} ({reasons})"
            else:
                skipped_cell = "-"
            lines.append(
                f"| {name} | {entry['malware_detected']}/"
                f"{entry['malware_scanned']} | {skipped_cell} | "
                f"{control_cell} | {shown or '-'} |")

        silent = [n for n, e in stats.items()
                  if e["malware_detected"] == 0 and e["malware_scanned"] > 0]
        if silent and malware_scanned:
            lines += ["", f"Detected nothing in this corpus: "
                      f"{', '.join(f'`{n}`' for n in sorted(silent))}."]

    unattributed = detections_without_engine(ok)
    if unattributed:
        lines += [
            "",
            "## Detections with no engine attribution",
            "",
            f"**{len(unattributed)}** scan(s) returned a verdict implying a "
            f"detection while no engine reported a threat name. A detection "
            f"nobody owns cannot be acted on, so these are listed rather than "
            f"counted as either caught or clean. The usual cause is a verdict "
            f"aggregated from a file extracted out of the submission, where "
            f"the per-engine detail sits on the extracted file rather than on "
            f"what was submitted.",
            "",
            "| SHA256 | Type | Expected | Overall | Engines |",
            "|---|---|---|---|---|",
        ]
        for item in unattributed:
            row = item["row"]
            lines.append(
                f"| `{row['sha256'][:16]}...` | {row.get('file_type') or '?'} | "
                f"{row.get('expected', '?')} | {item['overall']} | "
                f"{item['detected']}/{item['total']} |")

    if lines:
        lines.append("")
    return lines


def build_sample_detail(index, r):
    """
    Render one sample as a full dossier: identifiers, links, and the AV, CDR
    and sandbox findings side by side.

    This is the part an engine team works from. A verdict alone says a sample
    was missed; the signals, engine names and removed objects say *where* to
    look.
    """
    verdict = r.get("mdc_verdict") or "ERROR"
    caught = "caught" if verdict.upper() in CAUGHT_VERDICTS else "NOT CAUGHT"
    out = [
        f"### {index}. {r['signature'] or '(unnamed family)'} - "
        f"{r['file_type'] or '?'} - {verdict} ({caught})",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| SHA256 | `{r['sha256']}` |",
    ]
    if r.get("md5"):
        out.append(f"| MD5 | `{r['md5']}` |")
    if r.get("sha1"):
        out.append(f"| SHA1 | `{r['sha1']}` |")
    out += [
        f"| File type / size | {r['file_type'] or '?'} / {r['file_size']:,} bytes |",
        f"| MalwareBazaar family | {r['signature'] or '(unnamed)'} |",
        f"| MalwareBazaar tags | {', '.join(r.get('tags') or []) or '-'} |",
        f"| First seen | {r['first_seen']} |",
        f"| Sample page | {r.get('mb_url') or '-'} |",
        f"| Re-download | `{r.get('mb_download_cmd') or '-'}` |",
        f"| MDC data_id | `{r.get('data_id') or '-'}` |",
        f"| Sandbox ID | `{r.get('sandbox_id') or '-'}` |",
    ]
    if r.get("report_html"):
        out.append(f"| Sandbox report (HTML) | [open report]({r['report_html']}) |")
    if r.get("report_json"):
        out.append(f"| Sandbox report (JSON) | [raw JSON]({r['report_json']}) |")

    threat_level = r.get("mdc_threat_level")
    level_note = f" (threat level {threat_level})" if threat_level is not None else ""
    out.append(f"| Verdict | **{verdict}**{level_note} |")
    out.append(f"| Report chain depth | {r.get('chain_depth', 0)} |")
    if r.get("error"):
        out.append(f"| Error | {r['error']} |")

    # ---- Report chain, when the archive produced child reports.
    chain = r.get("chain") or []
    if len(chain) > 1:
        out += [
            "",
            "**Report chain** - the container is inert, so the verdict comes "
            "from the deepest node.",
            "",
            "| Depth | Sandbox ID | SHA256 | Verdict |",
            "|---|---|---|---|",
        ]
        for node in sorted(chain, key=lambda n: n["depth"]):
            out.append(
                f"| {node['depth']} | `{node['sandbox_id']}` | "
                f"`{(node.get('sha256') or '-')[:32]}` | "
                f"{node.get('verdict') or '-'} |"
            )

    # ---- AV multiscan.
    av = r.get("av")
    out += ["", "**AV multiscan**", ""]
    if not av:
        out.append("Not requested for this run.")
    elif not av.get("scanned"):
        out.append(f"**No AV verdict** - the multiscan pass returned "
                   f"`{av.get('overall') or 'no result'}`, so no engine "
                   f"opinion exists for this file.")
    else:
        source = (" The counts below are for the file extracted from the "
                  f"submitted archive (`{av['from_extracted']}`), because the "
                  "encrypted container itself is clean by construction."
                  if av.get("from_extracted") else "")
        engines = av.get("engines") or []
        examined = [e for e in engines
                    if e.get("code") in CLEAN_CODES
                    or e.get("code") in DETECTED_CODES or e.get("threat")]
        unable = [e for e in engines if e not in examined]
        out.append(
            f"`{av.get('overall')}` - {av.get('detected') or 0} of "
            f"{len(examined) or av.get('total') or 0} engine(s) that examined "
            f"this file detected it.{source}"
        )
        if unable:
            # Naming these matters: they are not misses.
            grouped = Counter(SCAN_CODE_MEANINGS.get(e.get("code"),
                                                     f"code {e.get('code')}")
                              for e in unable)
            detail = "; ".join(f"{count} x {reason}"
                               for reason, count in grouped.most_common())
            out += ["", f"{len(unable)} engine(s) returned no opinion "
                    f"({detail}): "
                    + ", ".join(f"`{e['engine']}`" for e in unable) + "."]
        detections = [e for e in av.get("engines") or [] if e.get("threat")]
        if detections:
            out += ["", "| Engine | Threat name | Definitions |", "|---|---|---|"]
            for engine in detections:
                out.append(
                    f"| {engine['engine']} | `{engine['threat']}` | "
                    f"{engine['def_time']} |"
                )
            clean = len(av.get("engines") or []) - len(detections)
            if clean:
                out += ["", f"{clean} further engine(s) returned clean."]
        else:
            out += ["", "No engine flagged it. For a confirmed-malicious "
                    "sample, that is itself the finding."]

    # ---- Deep CDR.
    cdr = r.get("cdr")
    out += ["", "**Deep CDR**", ""]
    if not cdr:
        out.append("Not gathered for this run.")
    elif not cdr.get("ran"):
        reason = (cdr.get("sanitized_reason") or cdr.get("description")
                  or "no sanitization performed")
        out.append(f"Did not sanitize: {reason}.")
    else:
        summary = f"`{cdr.get('actions_ran')}`"
        if cdr.get("converted_to"):
            summary += f" - rebuilt as {cdr['converted_to']}"
        if cdr.get("description"):
            summary += f". {cdr['description']}"
        out.append(summary)

        if cdr.get("objects"):
            out += ["", "| Object | Action | Count | Location |",
                    "|---|---|---|---|"]
            for obj in cdr["objects"]:
                if not isinstance(obj, dict):
                    out.append(f"| {obj} | - | - | - |")
                    continue
                where = "; ".join((obj.get("object_metadata") or [])[:2]) or "-"
                out.append(
                    f"| {obj.get('object_name') or 'object'} | "
                    f"{obj.get('action') or '-'} | {obj.get('count') or 1} | "
                    f"`{where}` |"
                )
        if cdr.get("actions_failed"):
            out += ["", f"Actions failed: {cdr['actions_failed']}"]

    # ---- Sandbox behaviour.
    out += ["", "**Sandbox report**", ""]
    groups = r.get("signal_groups") or []
    if not groups and not r.get("yara") and not r.get("iocs_by_type"):
        out.append("No behavioural detail returned.")
    else:
        out.append(f"{len(groups)} signal group(s), "
                   f"{r.get('ioc_count') or 0} unique IOC(s).")
        if groups:
            out += ["", "Strongest signals:", ""]
            for group in groups[:SIGNALS_IN_REPORT]:
                out.append(
                    f"- `{group['peak_strength']:.2f}` {group['description']} "
                    f"({group['verdict']}, {group['signal_count']} signal(s))"
                )
            hidden = len(groups) - SIGNALS_IN_REPORT
            if hidden > 0:
                out.append(f"- ... {hidden} more group(s); see the JSON report")
        if r.get("yara"):
            out += ["", "YARA: " + ", ".join(
                f"`{y['rule']}` ({y['verdict']})" for y in r["yara"])]
        if r.get("mdc_tags"):
            out += ["", "Tags: " + ", ".join(f"`{t}`" for t in r["mdc_tags"])]
        if r.get("mitre"):
            out += ["", "MITRE ATT&CK: " + ", ".join(
                f"{tid} {name}" for tid, name in r["mitre"].items())]
        if r.get("iocs_by_type"):
            out += ["", "IOCs by type:", ""]
            for ioc_type, values in sorted(r["iocs_by_type"].items(),
                                           key=lambda kv: -len(kv[1])):
                shown = values[:IOCS_IN_REPORT]
                more = len(values) - len(shown)
                listed = ", ".join(f"`{v[:70]}`" for v in shown)
                tail = f" ... +{more} more" if more else ""
                out.append(f"- **{ioc_type}** ({len(values)}): {listed}{tail}")

    out.append("")
    return out


def build_report(results, stamp, per_day, malware_count, elapsed,
                 query_failures=None):
    """Render the run report as Markdown."""
    ok = [r for r in results if not r["error"]]
    failed = [r for r in results if r["error"]]

    # Split by what each sample was supposed to be: a detection on malware is a
    # success, the same detection on a clean control is a false positive.
    malware = [r for r in ok if r.get("expected") != EXPECTED_CLEAN]
    controls = [r for r in ok if r.get("expected") == EXPECTED_CLEAN]

    caught = [r for r in malware
              if (r["mdc_verdict"] or "").upper() in CAUGHT_VERDICTS]
    missed = [r for r in malware if r not in caught]
    false_positives = [r for r in controls
                       if (r["mdc_verdict"] or "").upper() in CAUGHT_VERDICTS
                       or ((r.get("av") or {}).get("detected") or 0) > 0]

    days = sorted({r["day"] for r in results if r["day"]})
    verdicts = Counter((r["mdc_verdict"] or "none").upper() for r in ok)
    families = Counter(r["signature"] or "(unnamed)" for r in results)

    lines = [
        f"# MalwareBazaar sweep - {stamp}",
        "",
        "Malware samples come from MalwareBazaar, which hosts only confirmed "
        "malware, so each is a known positive; clean controls are known "
        "negatives. Malware was submitted as an encrypted archive and opened "
        "server-side - nothing was extracted locally.",
        "",
        "## Run",
        "",
        "| | |",
        "|---|---|",
        f"| Samples submitted | {len(results)} |",
        f"| Analysed successfully | {len(ok)} |",
        f"| Failed / timed out | {len(failed)} |",
        f"| Days covered | {len(days)} ({days[-1] if days else '-'} back to "
        f"{days[0] if days else '-'}) |",
        f"| Families represented | {len(families)} |",
        f"| Sampling | up to {per_day}/day, cap {malware_count} malware |",
        f"| Wall clock | {elapsed // 60:.0f}m {elapsed % 60:.0f}s |",
        "",
    ]
    lines += build_results_summary(results)
    lines += build_engine_summary(results, malware, controls)
    lines += [
        "## Corpus composition",
        "",
        "A corpus of one file type tests one code path. This run's mix:",
        "",
        "| Category | Samples | File types |",
        "|---|---|---|",
    ]
    by_category = defaultdict(Counter)
    for r in results:
        by_category[file_category(r["file_type"])][r["file_type"]] += 1
    for name in ("document", "script", "archive", "binary", "other"):
        if name in by_category:
            types = by_category[name]
            lines.append(
                f"| {name} | {sum(types.values())} | "
                f"{', '.join(f'{t} ({c})' for t, c in types.most_common())} |"
            )
    lines += [
        "",
        "## Detection coverage",
        "",
        f"**{len(caught)} of {len(malware)}** known-malicious samples were "
        f"rated SUSPICIOUS or worse.",
        "",
        "| Verdict | Samples |",
        "|---|---|",
    ]
    for verdict in VERDICT_ORDER + ["NONE"]:
        if verdicts.get(verdict):
            lines.append(f"| {verdict} | {verdicts[verdict]} |")

    if controls:
        lines += [
            "",
            "## False positives (clean controls)",
            "",
            f"{len(controls)} known-clean file(s) were submitted as controls. "
            f"**{len(false_positives)}** produced a detection.",
            "",
        ]
        if false_positives:
            lines += [
                "A detection on a file that is definitively clean is a false "
                "positive, and on a signed operating-system binary that is a more "
                "damaging defect than a missed obscure sample.",
                "",
                "| File | Sandbox verdict | AV | Source |",
                "|---|---|---|---|",
            ]
            for r in false_positives:
                av = r.get("av") or {}
                ratio = (f"{av.get('detected') or 0}/{av.get('total') or 0}"
                         if av else "-")
                lines.append(
                    f"| `{r['file_name']}` | {r.get('mdc_verdict') or '-'} | "
                    f"{ratio} | {r.get('source') or '-'} |")
        else:
            lines.append("No false positives - every control came back clean.")

    if missed:
        lines += [
            "",
            "### Rated below SUSPICIOUS - worth reviewing",
            "",
            "These are known-malicious samples that the sandbox did not flag. "
            "For archive submissions, check whether the verdict came from the "
            "container rather than its contents.",
            "",
            "| SHA256 | Family | Type | First seen | Verdict | Chain depth |",
            "|---|---|---|---|---|---|",
        ]
        for r in missed:
            lines.append(
                f"| `{r['sha256'][:16]}...` | {r['signature'] or '-'} | "
                f"{r['file_type'] or '-'} | {r['day']} | "
                f"{r['mdc_verdict'] or 'none'} | {r['chain_depth']} |"
            )

    lines += [
        "",
        "## Per-sample detail",
        "",
        "One section per sample: identifiers, links, and the AV, Deep CDR "
        "and sandbox findings. Sandbox report links carry their own access "
        "token and need no API key, so treat this file as shareable-but-"
        "sensitive.",
        "",
    ]
    for position, r in enumerate(
            sorted(results, key=lambda x: verdict_rank(x.get("mdc_verdict"))),
            start=1):
        lines += build_sample_detail(position, r)

    
    if failed:
        lines += ["", "## Failures", "",
                  "| SHA256 | Family | Type | Sandbox ID | Error |",
                  "|---|---|---|---|---|"]
        for r in failed:
            lines.append(
                f"| `{r['sha256'][:16]}...` | {r['signature'] or '-'} | "
                f"{r['file_type'] or '-'} | `{r.get('sandbox_id') or '-'}` | "
                f"{r['error']} |")

    if query_failures:
        lines += [
            "",
            "## Data-source gaps",
            "",
            "These MalwareBazaar queries could not be served, so the "
            "candidate pool was narrower than requested. Each was retried "
            "and, for families, re-attempted as a tag query before being "
            "given up on. This limits coverage but does not invalidate the "
            "results above.",
            "",
            "| Query | Last error |",
            "|---|---|",
        ]
        for label, error in query_failures:
            lines.append(f"| {label} | {error} |")

    lines += ["", "## Families sampled", "",
              ", ".join(f"{name} ({count})"
                        for name, count in families.most_common()), ""]
    return "\n".join(lines)
