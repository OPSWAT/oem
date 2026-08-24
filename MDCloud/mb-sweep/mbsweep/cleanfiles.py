"""
Known-clean controls: discovery and hash mutation.

A corpus of only malware measures recall and nothing about
false positives. This module sources files that are
definitively clean - signed system binaries and
vendor-shipped documents - and gives each a unique hash so
the service cannot answer from cache or reputation.
"""

import hashlib
import os
import shutil
import zipfile
from collections import Counter, defaultdict

from .config import (
    CLEAN_DOC_EXTENSIONS, CLEAN_DOC_MAX_DEPTH,
    CLEAN_DOC_SKIP_DIRS, EXPECTED_CLEAN, TEXT_BASED_TYPES,
    ZIP_BASED_TYPES,
)


# ---------------------------------------------------------------------------
# Sample selection
# ---------------------------------------------------------------------------
def collect_clean_samples(clean_dir, clean_pe_count, max_bytes):
    """
    Gather known-clean files to submit alongside the malware.

    A corpus of nothing but malware measures recall and says nothing about
    false positives - and a false positive on a signed operating-system binary
    is a far more damaging product defect than a missed obscure sample. Mixing
    in files that are definitively clean turns the sweep into a two-sided
    measurement.

    Two sources:

    * ``--clean-dir`` - every regular file in a directory you nominate. Use
      this for a curated goodware set (vendor installers, your own builds).
    * ``--clean-pe-count`` - N signed binaries sampled from the Windows system
      directory. Nothing is downloaded, and their provenance is not in doubt.

    Returned records mirror the MalwareBazaar shape so the rest of the
    pipeline needs no special cases, with ``expected`` set to "clean".
    """
    samples = []

    if clean_dir:
        if not os.path.isdir(clean_dir):
            raise SystemExit(f"--clean-dir is not a directory: {clean_dir}")
        names = sorted(os.listdir(clean_dir))
        for name in names:
            path = os.path.join(clean_dir, name)
            if not os.path.isfile(path):
                continue
            samples.append(clean_record(path, "clean-dir"))

    if clean_pe_count > 0:
        system_dir = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        if not os.path.isdir(system_dir):
            print(f"[!] {system_dir} not found - skipping system clean files "
                  f"(this source is Windows-only).")
        else:
            # Deterministic pick: sort by name and take a stride through the
            # list, so the same machine contributes the same set every run and
            # results stay comparable between sweeps.
            candidates = []
            for name in sorted(os.listdir(system_dir)):
                if not name.lower().endswith((".exe", ".dll")):
                    continue
                path = os.path.join(system_dir, name)
                try:
                    if not os.path.isfile(path):
                        continue
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size == 0 or (max_bytes and size > max_bytes):
                    continue
                candidates.append(path)

            if candidates:
                stride = max(1, len(candidates) // clean_pe_count)
                picked = candidates[::stride][:clean_pe_count]
                for path in picked:
                    samples.append(clean_record(path, "system32"))

    for sample in samples:
        if not sample["sha256"]:
            samples = [s for s in samples if s["sha256"]]
            break

    print(f"[+] {len(samples)} known-clean file(s) added to the corpus")
    return samples


def clean_record(path, source):
    """Build a candidate record for a local clean file."""
    digest = ""
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        size = os.path.getsize(path)
    except OSError as exc:
        print(f"    ! cannot read {path}: {exc}")
        size = 0

    name = os.path.basename(path)
    return {
        "sha256": digest,
        "md5": "",
        "sha1": "",
        "file_name": name,
        "file_type": os.path.splitext(name)[1].lstrip(".").lower(),
        "file_size": size,
        "signature": "(known clean)",
        "first_seen": "",
        "day": "",
        "tags": [],
        "reporter": source,
        "source": source,
        "expected": EXPECTED_CLEAN,
        # Submitted as-is: a clean file is not a password-protected archive.
        "local_path": path,
    }


def find_clean_documents(max_bytes):
    """
    Locate vendor-shipped documents on this machine, grouped by extension.

    These are real files signed off by Microsoft, Dell, Adobe and friends -
    preferable to synthesising documents, which risks measuring the sandbox's
    opinion of a hand-rolled file rather than of a genuine one.
    """
    roots = []
    for env_name, subdir in (("SystemRoot", "System32"),
                             ("ProgramFiles", ""),
                             ("ProgramFiles(x86)", ""),
                             ("ProgramData", "")):
        base = os.environ.get(env_name)
        if base:
            candidate = os.path.join(base, subdir) if subdir else base
            if os.path.isdir(candidate):
                roots.append(candidate)

    wanted = set(CLEAN_DOC_EXTENSIONS)
    by_extension = defaultdict(list)

    for root in roots:
        root_depth = root.rstrip(os.sep).count(os.sep)
        for current, dirnames, filenames in os.walk(root, topdown=True):
            if current.count(os.sep) - root_depth >= CLEAN_DOC_MAX_DEPTH:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames
                           if d.lower() not in CLEAN_DOC_SKIP_DIRS]

            for name in filenames:
                extension = os.path.splitext(name)[1].lower()
                if extension not in wanted:
                    continue
                path = os.path.join(current, name)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size < 2048 or (max_bytes and size > max_bytes):
                    continue
                by_extension[extension].append(path)

    for paths in by_extension.values():
        paths.sort()
    return by_extension


def collect_clean_documents(count, max_bytes):
    """
    Return up to ``count`` clean productivity files, spread across types.

    Selection goes round-robin over the extensions rather than taking the
    first N paths, because Windows ships dozens of copies of the same
    licence RTF - a naive pick would submit ten of those and call it document
    coverage. Content hashes de-duplicate the copies.
    """
    by_extension = find_clean_documents(max_bytes)
    if not by_extension:
        print("[!] No vendor-shipped documents found for clean controls.")
        return []

    ordered_types = [e for e in CLEAN_DOC_EXTENSIONS if e in by_extension]
    samples, seen_digests = [], set()
    cursor = {extension: 0 for extension in ordered_types}

    while len(samples) < count:
        progressed = False
        for extension in ordered_types:
            if len(samples) >= count:
                break
            paths = by_extension[extension]
            while cursor[extension] < len(paths):
                path = paths[cursor[extension]]
                cursor[extension] += 1
                record = clean_record(path, "shipped-document")
                if not record["sha256"] or record["sha256"] in seen_digests:
                    continue
                seen_digests.add(record["sha256"])
                samples.append(record)
                progressed = True
                break
        if not progressed:
            break   # every extension exhausted

    types = Counter(s["file_type"] for s in samples)
    print(f"[+] {len(samples)} clean document(s): {dict(types)}")
    return samples


def mutate_clean_file(source_path, dest_dir, run_stamp):
    """
    Copy a clean control and alter it just enough to change its hash.

    Why bother: MetaDefender caches results by hash, and a stock Microsoft
    binary or Office template is very likely already known - possibly
    reputation-allowlisted. Submitting it unchanged can return a cached or
    reputation-derived "clean" without the analysis engines doing any real
    work, which is precisely the thing a false-positive test needs to measure.
    A unique hash forces a genuine analysis.

    The mutation is format-aware, because *how* you change the bytes matters:

    * ZIP-based Office formats get an archive comment. Readers ignore it and
      every part stays byte-identical, so the document is untouched.
    * Text formats get a trailing blank line, which no parser objects to.
    * PDF gets a trailing ``%`` comment after ``%%EOF``; trailing bytes are
      tolerated and the page tree is not touched.
    * Anything else - PE binaries, OLE documents (.doc/.xls/.ppt) - gets bytes
      appended as an overlay. See the caveat returned alongside.

    Returns ``(path, note)`` where note describes the mutation, or
    ``(source_path, None)`` if it could not be applied.
    """
    extension = os.path.splitext(source_path)[1].lower()
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, os.path.basename(source_path))

    try:
        shutil.copy2(source_path, dest_path)
    except OSError as exc:
        print(f"    ! could not copy control {source_path}: {exc}")
        return source_path, None

    marker = f"clean-control {run_stamp}".encode("ascii", "replace")

    try:
        if extension in ZIP_BASED_TYPES:
            # An archive comment lives in the end-of-central-directory record.
            # Entries are rewritten byte-for-byte, so the document content is
            # untouched and every Office reader ignores the comment.
            with zipfile.ZipFile(dest_path, "a") as archive:
                archive.comment = marker
            return dest_path, "zip archive comment"

        if extension == ".pdf":
            with open(dest_path, "ab") as handle:
                handle.write(b"\n%% " + marker + b"\n")
            return dest_path, "trailing PDF comment"

        if extension in TEXT_BASED_TYPES:
            with open(dest_path, "ab") as handle:
                handle.write(b"\r\n")
            return dest_path, "trailing blank line"

        # Fallback: append to the overlay. This is the honest but imperfect
        # case - on a signed PE it invalidates the Authenticode signature, and
        # some engines treat "appended overlay" or "broken signature" as
        # suspicious in itself. A detection here may be a reaction to the
        # mutation rather than a true false positive, so it is called out in
        # the report.
        with open(dest_path, "ab") as handle:
            handle.write(b"\x00" + marker)
        return dest_path, "appended overlay (invalidates any signature)"

    except (OSError, zipfile.BadZipFile) as exc:
        print(f"    ! could not mutate control {dest_path}: {exc}")
        return dest_path, None


def apply_clean_mutation(sample, dest_dir, run_stamp):
    """
    Mutate one clean control in place within its sample record.

    Keeps the original hash for traceability and re-points the record at the
    mutated copy, so the rest of the pipeline submits and reports the file
    that was actually analysed.
    """
    original_path = sample["local_path"]
    original_digest = sample["sha256"]

    path, note = mutate_clean_file(original_path, dest_dir, run_stamp)
    if not note:
        return sample

    updated = clean_record(path, sample.get("source") or "clean")
    sample["local_path"] = path
    sample["sha256"] = updated["sha256"]
    sample["file_size"] = updated["file_size"]
    sample["original_sha256"] = original_digest
    sample["mutation"] = note
    return sample
