"""
Run bookkeeping: dated folders, manifests and cross-run state.

A run is an artefact on disk, not just console output. This
owns its layout so a sweep can be re-run later against the
same corpus, and so coverage accumulates across runs.
"""

import json
import os

from .downloads import prepare_quarantine, warn_if_paths_too_long


def run_directory(out_dir, allow_synced, stamp_day):
    """
    Create ``<out-dir>/<YYYY-MM-DD>/`` and return the paths for this run.

    Everything a run produces lands under one dated folder - the sealed
    samples, the manifest, and the three report files - so a day's test is a
    self-contained artefact that can be re-submitted later with --from-dir.
    """
    run_dir = os.path.join(out_dir, stamp_day)
    samples_dir = os.path.join(run_dir, "samples")
    warn_if_paths_too_long(samples_dir)
    prepare_quarantine(samples_dir, allow_synced)
    return run_dir, samples_dir


def write_manifest(path, selected, run_stamp):
    """
    Record the MalwareBazaar metadata for everything downloaded.

    Without this a retained folder is just anonymous ZIPs: the family,
    file type and first-seen date all come from the API, not the file. The
    manifest is what makes --from-dir able to rebuild a full report.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"run": run_stamp, "samples": selected}, f, indent=1)


def read_manifest(directory):
    """Load a previous run's manifest and pair each entry with its archive."""
    manifest_path = os.path.join(directory, "manifest.json")
    samples_dir = os.path.join(directory, "samples")
    if not os.path.isfile(manifest_path):
        raise SystemExit(
            f"No manifest.json in {directory}. --from-dir expects a folder "
            f"produced by an earlier run."
        )
    with open(manifest_path, encoding="utf-8") as f:
        entries = json.load(f).get("samples") or []

    paired, missing = [], 0
    for entry in entries:
        archive = os.path.join(samples_dir, f"{entry['sha256']}.zip")
        if os.path.isfile(archive):
            # Attach the path to the record itself: the submission loop can
            # substitute samples, so positional pairing would not survive.
            entry["local_archive"] = archive
            paired.append((entry, archive))
        else:
            missing += 1
    if missing:
        print(f"[!] {missing} archive(s) named in the manifest are gone - "
              f"a previous run used --delete-after.")
    return paired


def load_state(path):
    """Return the set of sha256 values already submitted by earlier runs."""
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, encoding="utf-8") as f:
            return set(json.load(f).get("submitted") or [])
    except (json.JSONDecodeError, OSError):
        print(f"[!] Could not read state file {path}; treating as empty.")
        return set()


def save_state(path, submitted):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"submitted": sorted(submitted),
                   "count": len(submitted)}, f, indent=1)
