"""
The terminal summary printed when a run finishes.

Short by design - the Markdown report carries the detail.
"""

from collections import Counter

from ..config import CAUGHT_VERDICTS, EXPECTED_CLEAN
from .avstats import (
    detections_without_engine, engine_breakdown, sorted_engines,
)


def print_console_summary(results, elapsed, query_failures=None):
    """Short summary for the terminal; the Markdown file has the detail."""
    ok = [r for r in results if not r["error"]]
    malware = [r for r in ok if r.get("expected") != EXPECTED_CLEAN]
    controls = [r for r in ok if r.get("expected") == EXPECTED_CLEAN]
    caught = [r for r in malware
              if (r["mdc_verdict"] or "").upper() in CAUGHT_VERDICTS]
    false_positives = [r for r in controls
                       if (r["mdc_verdict"] or "").upper() in CAUGHT_VERDICTS
                       or ((r.get("av") or {}).get("detected") or 0) > 0]
    days = sorted({r["day"] for r in results if r["day"]})

    print("\n" + "=" * 70)
    print(" SWEEP COMPLETE")
    print("=" * 70)
    print(f" Submitted      : {len(results)}")
    print(f" Analysed       : {len(ok)}   (failed: {len(results) - len(ok)})")
    print(f" Days covered   : {len(days)}")
    if malware:
        print(f" Rated >= SUSPICIOUS : {len(caught)} of {len(malware)} malware")
    if controls:
        print(f" False positives     : {len(false_positives)} of "
              f"{len(controls)} clean control(s)")
        for r in false_positives:
            av = r.get("av") or {}
            print(f"   ! {r['file_name']} -> {r.get('mdc_verdict')} "
                  f"(AV {av.get('detected') or 0}/{av.get('total') or 0})")
    for verdict, count in Counter(
        (r["mdc_verdict"] or "ERROR").upper() for r in results
    ).most_common():
        print(f"   {verdict:<18} {count}")

    # AV coverage, alongside the sandbox verdicts. 'Infected' means at least one
    # engine flagged the sample; for a corpus of known-bad files the count that came
    # back clean is the number worth watching.
    # Malware only: "no engine detection" is a finding on a known-bad sample and
    # simply the correct answer on a clean control.
    with_av = [r for r in malware if r.get("av")]
    if with_av:
        infected = [r for r in with_av
                    if (r["av"].get("detected") or 0) > 0]
        clean = len(with_av) - len(infected)
        hits = [r["av"].get("detected") or 0 for r in infected]
        print(f" AV infected    : {len(infected)} of {len(with_av)} "
              f"(engines flagging: min {min(hits) if hits else 0}, "
              f"max {max(hits) if hits else 0})")
        unscanned = [r for r in with_av if not r["av"].get("scanned")]
        if clean - len(unscanned) > 0:
            print(f" AV clean       : {clean - len(unscanned)}  <-- known-"
                  f"malicious, engines ran, nothing detected")
        if unscanned:
            print(f" AV not scanned : {len(unscanned)}  <-- no engine verdict "
                  f"at all (not a detection result)")
    if controls:
        control_av = [r for r in controls if r.get("av")]
        flagged = [r for r in control_av
                   if (r["av"].get("detected") or 0) > 0]
        if control_av:
            print(f" AV on controls : {len(flagged)} of {len(control_av)} "
                  f"clean file(s) flagged by an engine")

    with_cdr = [r for r in malware if r.get("cdr")]
    if with_cdr:
        sanitized = [r for r in with_cdr if r["cdr"].get("ran")]
        print(f" CDR sanitized  : {len(sanitized)} of {len(with_cdr)}")
    # Per-engine results across the corpus. On a set of known-bad files this is
    # the table that says which engines are contributing.
    stats = engine_breakdown(ok)
    if stats:
        malware_total = len([r for r in malware if (r.get("av") or {}).get("scanned")])
        control_total = len([r for r in controls if (r.get("av") or {}).get("scanned")])
        print(f"\nEngine results ({malware_total} malware, "
              f"{control_total} clean control(s) scanned):")
        print(f"   {'ENGINE':<26} {'DETECTED':>9} {'NOT SCANNED':>12}   "
              f"{'CONTROLS':>9}")
        for name, entry in sorted_engines(stats):
            # Denominator is what the engine actually examined. An engine that
            # returned "filetype not supported" did not look and miss.
            caught = f"{entry['malware_detected']}/{entry['malware_scanned']}"
            skipped = entry["malware_not_scanned"]
            skipped_cell = str(skipped) if skipped else "-"
            flagged = f"{entry['controls_flagged']}/{entry['controls_scanned']}"
            notes = []
            if entry["controls_flagged"]:
                notes.append("flagged clean file(s)")
            if skipped:
                reason = entry["skip_reasons"].most_common(1)[0][0]
                notes.append(reason)
            marker = f"  <-- {'; '.join(notes)}" if notes else ""
            print(f"   {name[:26]:<26} {caught:>9} {skipped_cell:>12}   "
                  f"{flagged:>9}{marker}")

    unattributed = detections_without_engine(ok)
    if unattributed:
        print(f"\nDetections with no engine attribution: {len(unattributed)}")
        print("   (verdict implies a detection but no engine reported a threat)")
        for item in unattributed:
            row = item["row"]
            print(f"   ! {row['sha256'][:16]}... {row.get('file_type') or '?':<5} "
                  f"{item['overall']} - {item['detected']}/{item['total']} engines")

    print(f"\nElapsed        : {elapsed // 60:.0f}m {elapsed % 60:.0f}s")
    if query_failures:
        print(f" Source gaps    : {len(query_failures)} query/queries "
              f"unavailable - see the report")
