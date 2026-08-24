"""
Cross-sample AV statistics.

Two questions a per-sample view cannot answer:

* **Which engines are actually earning their place?** A run-level count per
  engine shows who caught what across the whole corpus, and - just as usefully -
  which engines flagged the known-clean controls.
* **Which scans claim a detection nobody owns?** MetaDefender can return an
  overall verdict of Infected while no engine row carries a threat name. That
  happens legitimately (the verdict is aggregated from an extracted file whose
  detail was not fetched) and illegitimately (a caller reading the wrong level
  of an archive response). Either way it is worth listing rather than hiding,
  because a detection with no engine behind it cannot be acted on.

Shared by the console summary and the Markdown report so both agree.
"""

from collections import Counter

from ..config import (
    CLEAN_CODES, DETECTED_CODES, EXPECTED_CLEAN, SCAN_CODE_MEANINGS,
)

# Overall verdict words that imply at least one engine found something.
DETECTION_WORDS = ("infected", "suspicious", "blocked")


def engine_breakdown(results):
    """
    Per-engine counts across the run.

    Returns ``{engine: {...}}`` covering malware detections and, separately,
    hits on the known-clean controls - an engine that flags controls is a
    false-positive source and belongs in the same table, not a footnote.
    Only rows where the AV pass actually ran are counted, so a missing scan
    never depresses an engine's apparent hit rate.
    """
    stats = {}

    for row in results:
        av = row.get("av") or {}
        if not av.get("scanned"):
            continue

        is_control = row.get("expected") == EXPECTED_CLEAN
        for engine in av.get("engines") or []:
            name = engine.get("engine")
            if not name:
                continue
            entry = stats.setdefault(name, {
                "malware_scanned": 0, "malware_detected": 0,
                "malware_not_scanned": 0,
                "controls_scanned": 0, "controls_flagged": 0,
                "controls_not_scanned": 0,
                "skip_reasons": Counter(), "threats": set(),
            })
            code = engine.get("code")
            detected = code in DETECTED_CODES or bool(engine.get("threat"))
            examined = detected or code in CLEAN_CODES

            if is_control:
                if examined:
                    entry["controls_scanned"] += 1
                else:
                    entry["controls_not_scanned"] += 1
                if detected:
                    entry["controls_flagged"] += 1
                    entry["threats"].add(engine.get("threat") or "unnamed")
            else:
                if examined:
                    entry["malware_scanned"] += 1
                else:
                    # The engine produced no opinion, so it must not count in
                    # the denominator as though it had looked and missed.
                    entry["malware_not_scanned"] += 1
                    entry["skip_reasons"][
                        SCAN_CODE_MEANINGS.get(code, f"code {code}")] += 1
                if detected:
                    entry["malware_detected"] += 1
                    entry["threats"].add(engine.get("threat") or "unnamed")

    return stats


def sorted_engines(stats):
    """Engines ordered by malware detections, then by name."""
    return sorted(stats.items(),
                  key=lambda kv: (-kv[1]["malware_detected"], kv[0].lower()))


def detections_without_engine(results):
    """
    Rows whose AV result implies a detection that no engine reported.

    Two shapes count: an overall verdict containing Infected/Suspicious/Blocked
    with no engine carrying a threat name, or a non-zero detected count with no
    engine names to back it. Both mean the same thing operationally - something
    decided the file was bad and there is no engine attribution for it.
    """
    unattributed = []

    for row in results:
        av = row.get("av") or {}
        if not av.get("scanned"):
            continue

        overall = (av.get("overall") or "").lower()
        implies_detection = any(word in overall for word in DETECTION_WORDS)
        detected = av.get("detected") or 0
        named = [e for e in av.get("engines") or [] if e.get("threat")]

        if (implies_detection or detected > 0) and not named:
            unattributed.append({
                "row": row,
                "overall": av.get("overall"),
                "detected": detected,
                "total": av.get("total"),
                "from_extracted": av.get("from_extracted") or "",
            })

    return unattributed
