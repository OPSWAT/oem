"""
Download and quarantine utilities.

Where downloaded files land and how that directory is
guarded. Kept apart from the MalwareBazaar client because
these rules apply to anything written to disk, whatever the
source.
"""

import os

from .config import SYNCED_DIR_MARKERS, WARNING_TEXT


def warn_if_paths_too_long(samples_dir):
    """
    Warn when sample paths would exceed the Windows 260-character limit.

    Archives are named <64-char sha256>.zip, so a deep --out-dir pushes
    the total past MAX_PATH. The failure mode is a FileNotFoundError on a
    directory that demonstrably exists, which is thoroughly confusing, so
    it is worth predicting rather than discovering.
    """
    longest = len(os.path.abspath(samples_dir)) + 69
    if os.name == "nt" and longest > 259:
        print(f"[!] Sample paths would reach ~{longest} characters, past "
              f"the Windows 260-character limit. Downloads would fail "
              f"with a misleading file-not-found error. Use a shorter "
              f"--out-dir, for example C:\\mb-sweeps.")
        return False
    return True


def prepare_quarantine(path, allow_synced):
    """
    Create the download directory and mark it as dangerous.

    Refuses a path that looks like a syncing cloud folder, because malware
    landing there gets replicated to corporate storage.
    """
    lowered = os.path.abspath(path).lower()
    for marker in SYNCED_DIR_MARKERS:
        if marker in lowered:
            if not allow_synced:
                raise SystemExit(
                    f"Refusing to download malware into what looks like a "
                    f"synced cloud folder ('{marker}' in the path). Choose a "
                    f"local directory, or pass --allow-synced-dir if you are "
                    f"certain it is not syncing."
                )
            print(f"[!] '{marker}' in the download path - syncing malware to "
                  f"cloud storage is a real risk. Proceeding as instructed.")

    os.makedirs(path, exist_ok=True)
    # Keep the corpus out of git, and leave a note for whoever finds it.
    with open(os.path.join(path, ".gitignore"), "w", encoding="utf-8") as f:
        f.write("# Live malware - never commit.\n*\n")
    with open(os.path.join(path, "WARNING.txt"), "w", encoding="utf-8") as f:
        f.write(WARNING_TEXT)
    return path
