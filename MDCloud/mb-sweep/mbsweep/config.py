"""
Configuration: endpoints, catalogues and shared vocabulary.

Everything the other modules agree on - API endpoints, the
default query catalogues, verdict ordering, and the timing
budgets. No behaviour lives here beyond file_category() and
verdict_rank(), which are pure lookups over these tables.
"""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"


MDC_BASE_URL = "https://api.metadefender.com/v4"


# Every MalwareBazaar sample ships in a ZIP with this password. It is a
# published convention, not a secret - it exists so AV cannot intercept the
# archive in transit.
ARCHIVE_PASSWORD = "infected"


# Public sample page, for provenance in the report.
MB_SAMPLE_URL = "https://bazaar.abuse.ch/sample/"


# Families queried by default. Deliberately mixed - stealers, RATs, loaders,
# botnets, ransomware, and a Linux family - so the corpus is not all one
# shape. Override with --signatures.
DEFAULT_SIGNATURES = [
    "AsyncRAT", "Vidar", "RedLineStealer", "Formbook", "LummaStealer",
    "njrat", "Remcos", "AgentTesla", "Mirai", "SnakeKeylogger",
    "Amadey", "Stealc",
]


# Tags queried by default. Deliberately weighted away from PE files:
# real-world intrusions arrive as documents, scripts and container formats,
# and those exercise entirely different sandbox paths than a raw binary.
# Every tag here was verified to return data, with the date span observed.
DEFAULT_TAGS = [
    # Office / productivity documents
    "docx", "doc", "xlsx", "xls", "rtf", "ppt", "pptx", "pdf", "one", "xll",
    # Scripts and shortcuts - the usual delivery wrappers
    "lnk", "js", "vbs", "ps1", "hta",
    # Container formats used to smuggle payloads past mail filters
    "iso", "zip", "rar", "7z",
    # Binaries, for contrast
    "exe", "dll", "msi", "apk", "elf",
]


# File types grouped for the corpus-composition report. A sweep that is 90%
# PE is not broad coverage, however many families it spans.
FILE_CATEGORIES = {
    "document": {"doc", "docx", "xls", "xlsx", "xlsm", "rtf", "ppt", "pptx",
                 "pdf", "one", "xll", "pub", "odt"},
    "script": {"js", "jse", "vbs", "vbe", "ps1", "hta", "bat", "cmd", "sh",
               "py", "jar", "wsf", "lnk"},
    "archive": {"zip", "rar", "7z", "iso", "img", "gz", "tar", "cab", "ace",
                "arj", "vhd"},
    "binary": {"exe", "dll", "sys", "msi", "elf", "apk", "dmg", "macho",
               "pesys", "pedll"},
}


def file_category(file_type):
    """Bucket a MalwareBazaar file_type for the composition report."""
    ftype = (file_type or "").lower()
    for name, members in FILE_CATEGORIES.items():
        if ftype in members:
            return name
    return "other"


# Query concurrency. These are independent network calls; the ceiling is
# politeness to abuse.ch rather than local capacity.
MB_QUERY_WORKERS = 8


# MalwareBazaar answers with sporadic 502s that clear on a retry.
MB_QUERY_ATTEMPTS = 3


MB_RETRY_BACKOFF_SECONDS = 4.0


# A healthy tag query returns in about 4 seconds; a failing one sat for 30s
# before answering 502 in testing. A generous timeout therefore only buys
# waiting time for queries that were never going to succeed. Family queries
# return up to ~2 MB and legitimately need longer, so they get their own
# budget.
MB_QUERY_TIMEOUT_SECONDS = 45


MB_DISCOVERY_TIMEOUT_SECONDS = 12


# Attempts for the broad discovery sweep. One tag out of two dozen failing
# costs almost nothing in coverage, whereas retrying it three times with
# backoff cost roughly 100 seconds - the entire discovery phase.
MB_DISCOVERY_ATTEMPTS = 1


# Polling for the MDC file scan and sandbox run.
FILE_POLL_INTERVAL_SECONDS = 3


FILE_POLL_TIMEOUT_SECONDS = 300


SANDBOX_POLL_INTERVAL_SECONDS = 15


SANDBOX_POLL_TIMEOUT_SECONDS = 900        # 15 min per sample; 50 samples max


# Verdicts, most severe first. Used to pick the worst verdict in an archive
# chain and to order the report.
VERDICT_ORDER = [
    "MALICIOUS", "LIKELY_MALICIOUS", "SUSPICIOUS",
    "UNKNOWN", "INFORMATIONAL", "NO_THREAT", "BENIGN",
]


# A sample is "caught" if MetaDefender put it at or above this severity.
CAUGHT_VERDICTS = {"MALICIOUS", "LIKELY_MALICIOUS", "SUSPICIOUS"}


# What a sample is supposed to be. MalwareBazaar only hosts confirmed malware, so
# everything from it is a known positive; clean files are known negatives, and a
# detection on one is a false positive.
EXPECTED_MALICIOUS = "malicious"


EXPECTED_CLEAN = "clean"


# Detail caps in the Markdown report. The raw JSON always has everything.
SIGNALS_IN_REPORT = 8


IOCS_IN_REPORT = 8


# Directory names that suggest a syncing cloud client. Downloading malware
# into one of these uploads it to corporate storage.
SYNCED_DIR_MARKERS = [
    "onedrive", "dropbox", "google drive", "googledrive",
    "icloud", "box sync", "sharepoint", "nextcloud",
]


WARNING_TEXT = """\
QUARANTINE - LIVE MALWARE
=========================

Every .zip in this directory is a confirmed-malicious sample downloaded from
abuse.ch MalwareBazaar by malwarebazaar-sweep.py.

They are encrypted with the password "infected" and MUST NOT be extracted on
a normal workstation. They were uploaded to MetaDefender Cloud in encrypted
form; nothing here has been opened locally.

Do not: extract, execute, rename to a runnable extension, copy to a network
share, or let a backup/sync client touch this directory.

To dispose of them, delete the whole directory.
"""


# Document types worth covering as clean controls. Office and PDF exercise the
# CDR and document-sandbox paths, which a PE never touches - and which is where
# a false positive is most likely, since "contains active content" heuristics
# fire on structure rather than code.
CLEAN_DOC_EXTENSIONS = [
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".rtf", ".pptx", ".ppt", ".csv",
]


# Where vendor-shipped documents actually live on Windows. WinSxS is excluded
# deliberately: it is enormous and holds nothing but duplicates of these files.
CLEAN_DOC_SKIP_DIRS = {"winsxs", "servicing", "installer", "assembly",
                       "driverstore", "$recycle.bin", "windowsapps"}


# Bound the walk - Program Files is deep, and everything useful is near the top.
CLEAN_DOC_MAX_DEPTH = 5


# Formats whose container tolerates a cosmetic edit that changes the file hash
# without altering what the file *is*.
ZIP_BASED_TYPES = {".docx", ".xlsx", ".pptx", ".zip"}


TEXT_BASED_TYPES = {".rtf", ".csv", ".txt", ".xml", ".html", ".htm"}


# ---------------------------------------------------------------------------
# State, quarantine directory, reporting
# ---------------------------------------------------------------------------
# Result polling. Everything is submitted first, then polled together, so the
# service analyses the whole batch in parallel instead of one file at a time.
POLL_INTERVAL_SECONDS = 60


POLL_WINDOW_MINUTES = 15


def verdict_rank(verdict):
    """Index into VERDICT_ORDER - lower is more severe."""
    v = (verdict or "").upper()
    return VERDICT_ORDER.index(v) if v in VERDICT_ORDER else len(VERDICT_ORDER)


# MalwareBazaar file types that are themselves containers. Every sample arrives
# inside an "infected"-encrypted zip, so when the sample is *also* an archive
# the sandbox has to unpack a second container it has no password for. Observed
# behaviour is a job that never completes rather than an error: 3 of 4 such
# samples produced no verdict, no report and no child reports even hours later,
# while every non-archive type in the same runs resolved normally.
ARCHIVE_SAMPLE_TYPES = {
    "zip", "rar", "7z", "gz", "tar", "cab", "iso", "arj", "ace", "xz", "bz2",
    "z", "lzh", "img",
}

NESTED_ARCHIVE_NOTE = (
    "sample is itself an archive inside the encrypted container, so the "
    "sandbox must open a second archive it has no password for"
)


# Per-engine scan_result_i codes, from the MetaDefender documentation. Only 0,
# 1 and 2 are an engine opinion about the file; the rest mean the engine did
# not produce one. Counting a "filetype not supported" as a clean scan makes an
# engine look like it examined the file and missed - which is a materially
# different statement.
SCAN_CODE_MEANINGS = {
    0: "no threats found",
    1: "infected",
    2: "suspicious",
    3: "failed to scan",
    4: "cleaned",
    5: "unknown",
    6: "quarantined",
    7: "skipped clean",
    8: "skipped infected (blocklisted type)",
    9: "exceeded archive depth",
    10: "not scanned (engine skipped it)",
    11: "aborted",
    12: "encrypted",
    13: "exceeded archive size",
    14: "exceeded archive file count",
    15: "password protected",
    16: "exceeded archive timeout",
    23: "filetype not supported",
    253: "not scanned (rate limit exceeded)",
}

# The engine looked and reached a conclusion.
DETECTED_CODES = {1, 2}
CLEAN_CODES = {0, 4, 7}
