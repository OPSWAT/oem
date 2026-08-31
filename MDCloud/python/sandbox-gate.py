"""
sandbox-gate.py
===============

Pre-filter files with a local content-detection pass before spending a
MetaDefender Aether sandbox run on them.

Why gate at all
---------------
A sandbox detonation costs 1-5 minutes of wall clock and one metered run per
file. Most files in real traffic carry nothing that *could* execute: a PNG, a
CSV, a plain-text log. Detonating those buys nothing. The gate answers one
question per file - "does this file carry a capability that warrants further
processing?" - in single-digit milliseconds, locally, and only the files that
say yes are submitted.

The gate is `cdscan`, from the content-detect project. It reports capabilities
(macros, script, auto-execution hooks, external references, embedded content,
encryption), never a risk score, and its quick mode runs the same checks as its
full mode but stops at the first finding - so a clean quick result means the same
thing as a clean full result. That property is what makes it usable as a gate.

The decision, and which way it fails
------------------------------------
    needs_further_processing  ->  SUBMIT      something was found
    indeterminate             ->  SUBMIT      the file could not be parsed
    clean                     ->  WITHHOLD    nothing found, and the scan finished

`indeterminate` submitting is the whole safety property. It means "the scanner
could not look", which is not the same as "there is nothing to see", and a gate
that treated the two alike would let every unparseable file bypass the sandbox
silently. There is no flag to turn that off.

Workflow
--------
1. For each file, run the gate and record the decision and the time it took.
2. Submit only the files that need further processing, via ``POST /v4/file``
   with a ``sandbox`` header - the same call ``aether-file.py`` makes.
3. Report throughput, how many files were kept off the service, and - when
   ground-truth labels are supplied - whether anything was withheld that should
   not have been.

Usage
-----
    python sandbox-gate.py --dry-run <path>...
    python sandbox-gate.py <api_key> <path>... --sandbox windows10
    python sandbox-gate.py --dry-run <dir> --recurse --csv gate.csv
    python sandbox-gate.py --dry-run <dir> --expect-manifest manifest.json

Flags
-----
--dry-run           Gate and measure, submit nothing. No API key needed.
--cdscan            Path to the cdscan executable. Auto-discovered otherwise.
--mode              quick (default) or full. Quick is the gate; full is for
                    understanding a decision after the fact.
--recurse           Descend into subdirectories.
--sandbox           Sandbox image for submitted files: windows10 (default),
                    windows7, linux.
--archivepwd        Password passed to MetaDefender for submitted archives.
--expect-manifest   A JSON manifest of ground-truth labels, in the shape
                    mb-sweep writes. Turns the run into a measurement: anything
                    labelled malicious and withheld is reported as a false
                    negative.
--csv               Write one row per file.
--limit             Stop after N files, for a quick look at a large corpus.
--archive-password  Password to open encrypted archive members, so their content
                    is scanned rather than only reported as locked. Nothing is
                    written to disk. With a password supplied, `encrypted_container`
                    stops counting as a reason to submit - the members behind it
                    were read - while a decryption *failure* still marks the scan
                    incomplete and submits.
--max-stream-mb     Largest single stream the scanner reads (default 10). A longer
                    stream is read up to the ceiling and reported indeterminate
                    rather than clean, because the tail was never examined.
--min-severity      Ignore findings below this severity: info (the default,
                    ignoring nothing), low, medium, high. This is the knob that
                    trades sandbox runs against coverage - raising it withholds
                    more files, and every file it withholds is one the scanner
                    did find something in. It never affects `indeterminate`.

Notes
-----
* Nothing here decrypts or extracts anything. Files are handed to the gate as
  paths, or as bytes on standard input; a password-protected archive is
  submitted, not opened.
* A password-protected archive can never be filtered out. Its content is
  unreadable by construction, so the gate reports encryption and the file is
  submitted. That is correct, and it means a corpus of encrypted archives sees
  no benefit from gating at all.
* Sandbox analysis is metered. Check ``limit_sandbox`` on ``GET /v4/apikey``
  before pointing this at a large corpus without --dry-run.

References
----------
* https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4
* content-detect: ../../POC-IDEAS/content-detect

Author:    Chris Seiler
Copyright: (c) 2026 OPSWAT, Inc. All rights reserved.
"""

import argparse
import csv
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

try:
    import requests
except ImportError:                                   # pragma: no cover
    requests = None


BASE_URL = "https://api.metadefender.com/v4"

# What one avoided detonation is worth. The sandbox sample documents 1-5 minutes
# per file; the low end is used so the saving is never overstated.
SANDBOX_SECONDS_PER_FILE = 60

# Verdicts the gate can return. Anything not in this set is treated as a submit,
# because an unrecognised verdict is a reason to be careful, not a reason to
# withhold.
SUBMIT_VERDICTS = {"needs_further_processing", "indeterminate"}
WITHHOLD_VERDICTS = {"clean"}

# Severity order, lowest first. The gate can be told to ignore findings below a
# floor, which trades sandbox runs for coverage.
SEVERITY_ORDER = ["info", "low", "medium", "high"]


# ---------------------------------------------------------------------------
# Finding the gate
# ---------------------------------------------------------------------------
def find_cdscan(explicit):
    """Locate the cdscan executable, or exit with a usable message."""
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        sys.exit(f"--cdscan {explicit} is not a file")

    found = shutil.which("cdscan")
    if found:
        return found

    # The usual layout on a developer machine: this repo and content-detect
    # checked out side by side.
    here = os.path.dirname(os.path.abspath(__file__))
    repos = os.path.abspath(os.path.join(here, "..", "..", ".."))
    candidates = [
        os.path.join(repos, "POC-IDEAS", "content-detect", "target", "release", "cdscan.exe"),
        os.path.join(repos, "POC-IDEAS", "content-detect", "target", "release", "cdscan"),
        os.path.join(repos, "POC-IDEAS", "content-detect", "target", "debug", "cdscan.exe"),
        os.path.join(repos, "POC-IDEAS", "content-detect", "target", "debug", "cdscan"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    sys.exit(
        "could not find cdscan. Build it with `cargo build --release` in "
        "content-detect, or pass --cdscan <path>."
    )


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
class GateResult:
    """One file's gate decision, with the timings behind it."""

    def __init__(self, path, verdict, capabilities, notes, wall_ms, engine_ms,
                 error=None, ignored=None, signer=None):
        self.path = path
        self.verdict = verdict
        self.capabilities = capabilities
        self.notes = notes
        self.wall_ms = wall_ms
        self.engine_ms = engine_ms
        self.error = error
        # Capabilities found but below the severity floor. Kept so the report can
        # say what was set aside rather than dropping it silently.
        self.ignored = ignored or []
        # The signing identity the scanner attached, when the file is a signed
        # executable. Recorded per file so a later distrust entry can be applied
        # retroactively: one query over the CSV by spki finds everything that
        # passed under a stolen key. See docs/trust.md in content-detect.
        self.signer = signer or {}

    @property
    def submit(self):
        """True when this file must go to the sandbox."""
        return self.verdict not in WITHHOLD_VERDICTS and self.verdict != "trusted_bypass"

    @property
    def reason(self):
        if self.error:
            return f"gate failed: {self.error}"
        if self.verdict == "indeterminate":
            return "could not be parsed conclusively"
        if not self.capabilities:
            if self.ignored:
                return "only below the floor: " + ", ".join(self.ignored)
            return "no capability found, scan completed"
        return ", ".join(self.capabilities)


def run_gate(cdscan, path, mode, stdin_bytes=None, stdin_name=None, floor="info",
             archive_password=None, max_stream_mb=None):
    """
    Gate one file and time it.

    Two clocks, because they answer different questions. `wall_ms` is what this
    harness experiences, process launch included, and is what a shell-script
    integration would see. `engine_ms` is what the scanner itself spent, and is
    what an in-process integration - linking the library rather than spawning a
    binary - would see. On small files the difference is most of the number, so
    reporting only one of them would misrepresent the cost either way.
    """
    command = [cdscan, "--json", "--mode", mode]
    if archive_password:
        command += ["--archive-password", archive_password]
    if max_stream_mb:
        command += ["--max-stream-mb", str(max_stream_mb)]
    if stdin_bytes is None:
        command.append(path)
    else:
        command += ["--stdin", "--stdin-name", stdin_name or os.path.basename(path)]

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            input=stdin_bytes,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        wall = (time.perf_counter() - started) * 1000.0
        return GateResult(path, "indeterminate", [], [], wall, 0.0, error=str(exc))
    wall = (time.perf_counter() - started) * 1000.0

    text = completed.stdout.decode("utf-8", errors="replace").strip()
    if not text:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        return GateResult(path, "indeterminate", [], [], wall, 0.0,
                          error=detail or f"no output, exit {completed.returncode}")

    try:
        # --json emits one object per file; a gate call has exactly one.
        report = json.loads(text.splitlines()[0])
    except (ValueError, IndexError) as exc:
        return GateResult(path, "indeterminate", [], [], wall, 0.0, error=f"bad JSON: {exc}")

    # A severity floor is a policy the consumer sets, which is the division this
    # scanner is built around: it reports what a file carries, and what counts as
    # worth a detonation is not its call. `url` on a PDF is the case that matters
    # in practice, since almost every real document has one.
    threshold = SEVERITY_ORDER.index(floor) if floor in SEVERITY_ORDER else 0
    capabilities, ignored = [], []
    for finding in report.get("findings", []):
        capability = finding.get("capability")
        if not capability:
            continue

        # With a password in hand, "this archive was encrypted" stops being a
        # coverage gap and becomes a fact about the container. It is not a reason
        # to detonate: the members behind it were decrypted and scanned, and
        # whatever they carry is reported on its own account. When decryption
        # fails the scanner marks the scan incomplete instead, which arrives as
        # `indeterminate` and submits — so nothing rests on this being right.
        if archive_password and capability == "encrypted_container":
            if capability not in ignored:
                ignored.append(capability)
            continue
        severity = finding.get("severity", "high")
        rank = (SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER
                else len(SEVERITY_ORDER))
        target = capabilities if rank >= threshold else ignored
        if capability not in target:
            target.append(capability)

    verdict = report.get("verdict", "indeterminate")

    # Everything found was below the floor, so by this policy there is nothing to
    # act on. `indeterminate` is never downgraded this way: the floor filters
    # findings, and "could not look" is not a finding.
    if verdict == "needs_further_processing" and not capabilities:
        verdict = "clean"

    return GateResult(
        path,
        verdict,
        capabilities,
        report.get("notes", []),
        wall,
        float(report.get("elapsed_ms", 0)),
        ignored=ignored,
        signer=report.get("signer"),
    )


# ---------------------------------------------------------------------------
# Trust policy
# ---------------------------------------------------------------------------
# Publisher trust levels, weakest first, for the --trust-min-level comparison.
TRUST_LEVELS = ["provisional", "standard", "high"]


def trust_bypass_reason(result, args, eligible_counter):
    """
    The one place trust can turn a submit into a skip, and the rules that
    bound it. Returns a reason string when the file may skip the sandbox,
    None otherwise.

    Hard rules, not configurable, in order:

      1. The signature must be VERIFIED. Stage 1 scanners report claims
         (verified: false), and a claim is forgeable - a certificate chain can
         be copied out of a signed file into malware. So with today's engine
         this function never returns a reason, whatever the flags say: the
         policy surface exists ahead of the capability, not behind it.
      2. A distrusted identity never skips, whatever else matches.
      3. Trust only excuses BEING an executable. Any finding beyond
         executable_file - a capability, an indicator, anything - forces the
         sandbox regardless of who signed the file.
      4. An indeterminate scan never skips: "could not look" is not "clean".

    Then the knobs: --trust-bypass must be on, the publisher's level must meet
    --trust-min-level, the key must be active, and 1 in --trust-sample
    eligible files detonates anyway - the only control that reaches inside a
    stolen key's pre-disclosure window. docs/trust.md has the full argument.
    """
    if not args.trust_bypass:
        return None
    signer = result.signer
    if not signer or not signer.get("verified"):
        return None                                   # rule 1: claims never grant
    if signer.get("distrusted"):
        return None                                   # rule 2
    if result.verdict != "needs_further_processing":
        return None                                   # rule 4 (clean/indeterminate)
    if set(result.capabilities) - {"executable_file"}:
        return None                                   # rule 3
    level = signer.get("publisher_trust")
    if level not in TRUST_LEVELS:
        return None
    if TRUST_LEVELS.index(level) < TRUST_LEVELS.index(args.trust_min_level):
        return None
    if signer.get("key_status") != "active":
        return None

    eligible_counter[0] += 1
    if args.trust_sample > 0 and eligible_counter[0] % args.trust_sample == 0:
        return None                                   # the sampled detonation
    return "TRUSTED_BYPASS: %s (%s), key active, signature verified" % (
        signer.get("publisher"), level)


# ---------------------------------------------------------------------------
# MetaDefender Cloud
# ---------------------------------------------------------------------------
def submit(api_key, path, sandbox, archive_password):
    """POST /v4/file with a sandbox header. Returns (data_id, error)."""
    if requests is None:
        return None, "the requests library is not installed"

    headers = {
        "apikey": api_key,
        "Content-Type": "application/octet-stream",
        "filename": os.path.basename(path),
        "sandbox": sandbox,
    }
    if archive_password:
        headers["archivepwd"] = archive_password

    try:
        with open(path, "rb") as handle:
            payload = handle.read()
    except OSError as exc:
        return None, f"could not read locally: {exc}"

    try:
        response = requests.post(
            f"{BASE_URL}/file", headers=headers, data=payload, timeout=120)
    except requests.RequestException as exc:
        return None, str(exc)

    if response.status_code >= 400:
        return None, f"HTTP {response.status_code}: {response.text[:200]}"

    try:
        return response.json().get("data_id"), None
    except ValueError:
        return None, "response was not JSON"


# ---------------------------------------------------------------------------
# Targets and labels
# ---------------------------------------------------------------------------
def expand(paths, recurse):
    """Every readable file under the given paths, in a stable order."""
    files = []
    for path in paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            if recurse:
                for root, _, names in os.walk(path):
                    files += [os.path.join(root, n) for n in sorted(names)]
            else:
                files += [os.path.join(path, n) for n in sorted(os.listdir(path))
                          if os.path.isfile(os.path.join(path, n))]
        else:
            print(f"  skipped, not found: {path}")
    return files


def load_labels(manifest_path):
    """
    Ground-truth labels keyed by every name a sample might have on disk.

    Reads the manifest mb-sweep writes. Malware lands as <sha256>.zip; clean
    controls keep their own name, so both are indexed.
    """
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)

    labels = {}
    for sample in manifest.get("samples", []):
        expected = sample.get("expected")
        if not expected:
            continue
        record = {"expected": expected, "file_type": sample.get("file_type") or "?"}
        for key in (sample.get("sha256"), sample.get("file_name")):
            if key:
                labels[key] = record
                labels[f"{key}.zip"] = record
    return labels


def label_for(labels, path):
    """The label for a file on disk, matched by name or by name without .zip."""
    name = os.path.basename(path)
    return labels.get(name) or labels.get(os.path.splitext(name)[0])


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def measure_batched(cdscan, paths, mode, archive_password=None, max_stream_mb=None):
    """
    The same files through one process, to separate the gate's cost from the
    integration's.

    Spawning a binary per file costs tens of milliseconds of process launch on
    every file, which on small inputs is the entire measurement. That number is
    real for a shell-script integration and badly misleading as a statement about
    the detection itself, so both are reported and this is where the second one
    comes from. Returns (wall_ms, engine_ms, files) or None.
    """
    if not paths:
        return None
    # Chunked, because a few hundred paths on one command line exceeds what
    # Windows accepts and the measurement would silently come back empty.
    chunk_size = 40
    wall = 0.0
    engine = 0.0
    files = 0
    for start in range(0, len(paths), chunk_size):
        command = [cdscan, "--json", "--mode", mode]
        if archive_password:
            command += ["--archive-password", archive_password]
        if max_stream_mb:
            command += ["--max-stream-mb", str(max_stream_mb)]
        command += list(paths[start:start + chunk_size])
        began = time.perf_counter()
        try:
            completed = subprocess.run(command, capture_output=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired):
            return None
        wall += (time.perf_counter() - began) * 1000.0

        for line in completed.stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                engine += float(json.loads(line).get("elapsed_ms", 0))
                files += 1
            except ValueError:
                continue
    return (wall, engine, files) if files else None


def report_throughput(results, batched=None):
    walls = [r.wall_ms for r in results]
    engines = [r.engine_ms for r in results]
    submitted = [r for r in results if r.submit]
    withheld = [r for r in results if not r.submit]

    print()
    print("=" * 72)
    print("GATE RESULT")
    print("=" * 72)
    print(f"  files gated                 {len(results)}")
    print(f"  submitted to the sandbox    {len(submitted)}")
    print(f"  prevented from going        {len(withheld)}")
    if results:
        print(f"  filtered out                {100.0 * len(withheld) / len(results):.1f}%")

    print()
    print("  Time per file, gate only")
    print(f"    wall clock   mean {statistics.mean(walls):7.2f} ms   "
          f"median {statistics.median(walls):7.2f} ms   "
          f"p95 {percentile(walls, 0.95):7.2f} ms" if walls else "    no files")
    if walls:
        print(f"    in engine    mean {statistics.mean(engines):7.2f} ms   "
              f"median {statistics.median(engines):7.2f} ms   "
              f"p95 {percentile(engines, 0.95):7.2f} ms")
        print(f"    total wall clock for the batch: {sum(walls) / 1000.0:.2f} s")
        print("    wall clock is one process launch per file, which on small files")
        print("    is most of the number; in-engine is the detection itself.")

    if batched:
        batch_wall, batch_engine, batch_files = batched
        print()
        print("  Time per file, one process for the whole batch")
        print(f"    wall clock   {batch_wall / batch_files:7.2f} ms per file "
              f"({batch_wall / 1000.0:.2f} s for {batch_files} files)")
        print(f"    in engine    {batch_engine / batch_files:7.2f} ms per file "
              f"({batch_engine:.0f} ms total)")
        print("    This is the number to plan capacity against: one process, or a")
        print("    linked library, amortises the launch away.")

    bypassed = [r for r in results if r.verdict == "trusted_bypass"]
    if bypassed:
        print()
        print(f"  Trusted bypasses              {len(bypassed)}")
        print("    Provenance TRUSTED_BYPASS, not CLEAN: these files were not")
        print("    analysed to completion, they were skipped on signer reputation.")
        print("    The CSV records spki and certificate for retroactive re-triage.")

    if withheld:
        saved = len(withheld) * SANDBOX_SECONDS_PER_FILE
        print()
        print(f"  Sandbox runs avoided          {len(withheld)}")
        print(f"  Detonation time avoided       {saved / 60.0:.1f} min "
              f"(at {SANDBOX_SECONDS_PER_FILE}s per file, the low end of the "
              f"documented 1-5 min)")

    return submitted, withheld


def report_accuracy(results, labels):
    """
    The measurement that matters: was anything withheld that should have gone?

    A file labelled malicious and withheld is a false negative - the sandbox
    never saw a file that needed detonating, and the gate is the reason. A file
    labelled clean and submitted is only a missed saving: it costs a run, it does
    not miss a threat. The two are not symmetric and are not reported as if they
    were.
    """
    labelled = [(r, label_for(labels, r.path)) for r in results]
    labelled = [(r, lab) for r, lab in labelled if lab]
    if not labelled:
        print()
        print("  no files matched a label in the manifest; accuracy not measured")
        return []

    false_negatives = [(r, lab) for r, lab in labelled
                       if lab["expected"] == "malicious" and not r.submit]
    true_submits = [(r, lab) for r, lab in labelled
                    if lab["expected"] == "malicious" and r.submit]
    correct_withholds = [(r, lab) for r, lab in labelled
                         if lab["expected"] == "clean" and not r.submit]
    missed_savings = [(r, lab) for r, lab in labelled
                      if lab["expected"] == "clean" and r.submit]

    print()
    print("=" * 72)
    print("ACCURACY, AGAINST GROUND TRUTH")
    print("=" * 72)
    print(f"  labelled files gated        {len(labelled)}")
    print()
    print("  Known-malicious")
    print(f"    submitted (correct)       {len(true_submits)}")
    print(f"    WITHHELD (false negative) {len(false_negatives)}")
    print()
    print("  Known-clean")
    print(f"    withheld (a saving)       {len(correct_withholds)}")
    print(f"    submitted (missed saving) {len(missed_savings)}")

    if false_negatives:
        print()
        print("  FALSE NEGATIVES - these needed the sandbox and did not reach it:")
        for result, label in false_negatives:
            print(f"    {os.path.basename(result.path)[:44]:<46} "
                  f"{label['file_type']:<6} {result.reason}")
        print()
        print("  A false negative here is a gate defect, not a tuning question:")
        print("  the file was withheld on the strength of a clean result.")
    else:
        print()
        print("  No false negatives: every known-malicious file was submitted.")

    return false_negatives


def write_csv(path, results, labels):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "file", "decision", "verdict", "capabilities", "expected",
            "file_type", "wall_ms", "engine_ms", "reason",
            "signer_publisher", "signer_trust", "signer_verified",
            "signer_spki_sha256", "signer_cert_sha256", "signer_distrusted",
        ])
        for result in results:
            label = label_for(labels, result.path) if labels else None
            signer = result.signer
            writer.writerow([
                os.path.basename(result.path),
                "submit" if result.submit else "withhold",
                result.verdict,
                ";".join(result.capabilities),
                (label or {}).get("expected", ""),
                (label or {}).get("file_type", ""),
                f"{result.wall_ms:.2f}",
                f"{result.engine_ms:.2f}",
                result.reason,
                signer.get("publisher", ""),
                signer.get("publisher_trust", ""),
                signer.get("verified", ""),
                signer.get("spki_sha256", ""),
                signer.get("cert_sha256", ""),
                signer.get("distrusted", ""),
            ])
    print(f"\n  per-file rows written to {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Gate files with content-detect before sandboxing them.")
    parser.add_argument("api_key", nargs="?",
                        help="MetaDefender Cloud API key; omit with --dry-run")
    parser.add_argument("paths", nargs="+", help="files or directories to gate")
    parser.add_argument("--dry-run", action="store_true",
                        help="gate and measure, submit nothing")
    parser.add_argument("--cdscan", help="path to the cdscan executable")
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--recurse", action="store_true")
    parser.add_argument("--sandbox", default="windows10",
                        choices=["windows10", "windows7", "linux"])
    parser.add_argument("--archivepwd", help="archive password passed to MetaDefender")
    parser.add_argument("--expect-manifest", help="ground-truth labels, mb-sweep shape")
    parser.add_argument("--csv", help="write one row per file")
    parser.add_argument("--limit", type=int, help="stop after N files")
    parser.add_argument("--archive-password",
                        help="password to open encrypted archive members, so their "
                             "content can be scanned instead of only reported as locked")
    parser.add_argument("--max-stream-mb", type=int, default=10,
                        help="largest single stream the scanner reads, in MB "
                             "(default: 10; a longer stream is reported "
                             "indeterminate, not clean)")
    parser.add_argument("--trust-bypass", action="store_true",
                        help="allow a VERIFIED signature from a trusted publisher to "
                             "skip the sandbox for files whose only finding is being "
                             "an executable. Off by default. Inert against a Stage 1 "
                             "scanner, which never reports verified signatures - see "
                             "docs/trust.md for the hole this knob opens and its bounds")
    parser.add_argument("--trust-min-level", choices=TRUST_LEVELS, default="high",
                        help="minimum publisher trust level for bypass eligibility "
                             "(default: high)")
    parser.add_argument("--trust-sample", type=int, default=8,
                        help="1 in N bypass-eligible files is detonated anyway, the "
                             "only control that works inside a stolen key's "
                             "pre-disclosure window (default: 8; 1 disables bypass)")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="info",
                        help="ignore findings below this severity (default: info, "
                             "which ignores nothing)")
    args = parser.parse_args()

    # The API key is positional and optional, which means a dry run's first path
    # can be swallowed by it. Give it back rather than silently skipping a file.
    api_key = args.api_key
    paths = list(args.paths)
    if args.dry_run and api_key and (os.path.exists(api_key) or os.sep in api_key):
        paths.insert(0, api_key)
        api_key = None
    if not args.dry_run and not api_key:
        parser.error("an API key is required unless --dry-run is given")

    cdscan = find_cdscan(args.cdscan)
    labels = load_labels(args.expect_manifest) if args.expect_manifest else {}

    targets = expand(paths, args.recurse)
    if args.limit:
        targets = targets[:args.limit]
    if not targets:
        sys.exit("no files to gate")

    print(f"gate     : {cdscan}")
    print(f"mode     : {args.mode}")
    print(f"stream   : {args.max_stream_mb} MB ceiling")
    if args.archive_password:
        print("password : supplied, encrypted members will be opened and scanned")
    print(f"floor    : {args.min_severity}"
          + ("" if args.min_severity == "info" else "  (findings below this are ignored)"))
    print(f"files    : {len(targets)}")
    if labels:
        print(f"labels   : {args.expect_manifest}")
    print(f"submit   : {'no (dry run)' if args.dry_run else args.sandbox}")
    print()

    results = []
    eligible_counter = [0]
    for index, path in enumerate(targets, 1):
        result = run_gate(cdscan, path, args.mode, floor=args.min_severity,
                          archive_password=args.archive_password,
                          max_stream_mb=args.max_stream_mb)

        # Trust is consulted only after the scan, and only to reconsider a
        # submit. TRUSTED_BYPASS is provenance, never CLEAN: the CSV records
        # which it was, so the two can never be conflated downstream.
        if result.submit:
            bypass = trust_bypass_reason(result, args, eligible_counter)
            if bypass:
                result.verdict = "trusted_bypass"
                result.capabilities = [bypass]
        results.append(result)

        decision = "SUBMIT  " if result.submit else "withhold"
        print(f"  [{index:>4}/{len(targets)}] {decision} "
              f"{os.path.basename(path)[:44]:<46} "
              f"{result.wall_ms:6.1f} ms  {result.reason[:40]}")

        if result.submit and not args.dry_run:
            data_id, error = submit(api_key, path, args.sandbox, args.archivepwd)
            if error:
                print(f"           submit failed: {error}")
            else:
                print(f"           submitted, data_id {data_id}")

    batched = measure_batched(cdscan, targets, args.mode,
                              archive_password=args.archive_password,
                              max_stream_mb=args.max_stream_mb)
    submitted, _ = report_throughput(results, batched)
    false_negatives = report_accuracy(results, labels) if labels else []

    if args.csv:
        write_csv(args.csv, results, labels)

    if not args.dry_run:
        print()
        print(f"  {len(submitted)} files submitted. Poll them with aether-file.py, "
              f"or use mb-sweep for a batch.")

    # A false negative is a defect worth failing a build over; everything else
    # here is information.
    return 1 if false_negatives else 0


if __name__ == "__main__":
    sys.exit(main())
