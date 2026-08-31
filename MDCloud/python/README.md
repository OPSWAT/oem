# MetaDefender Cloud API v4 — Python Samples

A collection of standalone Python scripts demonstrating common workflows on the [OPSWAT MetaDefender Cloud API v4](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4). Each script targets a single feature (multi-scan, sandbox, CDR, DLP, hash lookup) and is designed to be easy to read, copy, and adapt.

Runs on **Windows, macOS, and Linux** — no platform-specific dependencies.

## Prerequisites

- Python 3.8 or later (Windows, macOS, or Linux)
- A MetaDefender Cloud API key — get one free at [metadefender.opswat.com](https://metadefender.opswat.com/account)
- The `requests` library:

```
pip install requests
```

## Scripts

| Script | Feature | Endpoint(s) | What it does |
|---|---|---|---|
| `multi-scan-file.py` | Multi-scanning | `POST /v4/file`, `GET /v4/file/{data_id}` | Uploads a file and reports the multi-engine AV verdict. |
| `cdr-file.py` | Deep CDR | `POST /v4/file` with `rule: cdr` | Sanitizes a file and downloads the reconstructed clean version. |
| `dlp-file.py` | Proactive DLP | `POST /v4/file` with `rule: dlp` | Scans a file for sensitive content (SSNs, credit card numbers, PII). |
| `aether-file.py` | Sandbox (file) | `POST /v4/file` + `GET /v4/sandbox/{id}` | Detonates a file in the MetaDefender Aether sandbox and saves the full behavioral report. |
| `aether-url.py` | Sandbox (URL) | `POST /v4/sandbox` + `GET /v4/sandbox/{id}` | Detonates a URL in the sandbox and saves the full behavioral report. |
| `aether-hash.py` | Sandbox lookup | `GET /v4/hash/{hash}/sandbox` | Retrieves the last sandbox report for a file by its MD5/SHA1/SHA256. Hashes the file locally if given a path. |
| [`../mb-sweep/`](../mb-sweep/) | Detection-coverage harness | MalwareBazaar API + `POST /v4/file` (`sandbox` + `archivepwd`) | Its own self-contained folder, so it can be zipped and shared on its own. Builds a corpus of live malware from abuse.ch and reports how MetaDefender rated a set of known-bad files. |
| `sandbox-gate.py` | Pre-filter before sandboxing | local `cdscan` + `POST /v4/file` | Runs a local content-detection pass over each file and submits only the ones that carry something worth detonating. Reports throughput, how many files were kept off the service, and — given ground-truth labels — whether anything was withheld that should not have been. `--dry-run` measures without submitting. With `--trusted-hashes` (an NSRL-derived DB from `tools/trust/nsrl-import.py`) it adds a TRUSTED_KNOWN_FILE fast path requiring both a known hash and a verified Authenticode signature. |
| `aether-ioc.py` | Sandbox IOCs, multiscan, CDR | `POST /v4/file` + `GET /v4/sandbox/{id}`, or `GET /v4/hash/{hash}/sandbox`; plus `rule: multiscan` / `rule: cdr` or `GET /v4/hash/{hash}` | Detonates a file, then prints the IOCs the sandbox collected along with the signals behind the verdict, YARA hits, tags and MITRE techniques — optionally with AV and Deep CDR results in their own sections. Each section names the endpoint behind it. Exports the IOCs to CSV. |

## Common concepts

All scripts share the same authentication and polling patterns.

**Authentication.** Every request sends `apikey: <your key>` as an HTTP header.

**Workflow selection.** The MetaDefender Cloud API uses a `rule` header on `POST /v4/file` to pick which workflow to run. Valid values on Cloud are `multiscan`, `cdr`, `dlp`, `sanitize`, and `unarchive` — **one per submission**. Combination forms such as `multiscan_sanitize_unarchive` are rejected with HTTP 400, so gathering two workflows' results takes two submissions. (Server-side profile names like `multiscan_sanitize` do appear in cached results, but they are not accepted as `rule` values.) Note that sandbox analysis is **not** a rule — it is controlled by a separate `sandbox` header.

**Asynchronous scans.** File scans return a `data_id` immediately; the actual analysis happens asynchronously. Clients poll `GET /v4/file/{data_id}` and watch `scan_results.progress_percentage` until it reaches 100. Sandbox runs work the same way via `GET /v4/sandbox/{sandbox_id}`, but completion is signaled by the presence of verdict fields like `final_verdict`, `scan_results`, or `full_report` rather than a progress counter.

**Caching.** MetaDefender Cloud caches results by file hash. If a previously-scanned hash is uploaded again, you may receive the cached result rather than a fresh scan.

## Usage

Every script accepts the API key as its first positional argument. Full usage with `-h` / `--help` on any individual script.

### Multi-scan

```
python multi-scan-file.py <api_key> <file>
```

Returns the AV verdict (engines queried, engines that flagged the file, overall result).

### Deep CDR

```
python cdr-file.py <api_key> <file>
python cdr-file.py <api_key> <file> --dump
```

Sanitizes the file. If CDR produces a cleaned version, the script downloads it to `sanitized_<original_name>` in the current directory. The sanitized file is retained by OPSWAT for 24 hours only — grab it in the same run.

### Proactive DLP

```
python dlp-file.py <api_key> <file>
python dlp-file.py <api_key> <file> --dump
```

Reports sensitive-data findings (SSNs, credit card numbers, regex matches, etc.). Detection-only — DLP does not modify the file.

### Sandbox — file

```
python aether-file.py <api_key> <file>
python aether-file.py <api_key> <file> --sandbox linux
python aether-file.py <api_key> <file> --dump
```

Submits a file for dynamic analysis. Waits for the sandbox run to finish (typically 1–5 minutes), then downloads the full behavioral report and saves it as `Aether_result_<basename>.json`.

### Sandbox — URL

```
python aether-url.py <api_key> <url>
```

Submits a URL for dynamic analysis. Saves the full behavioral report as `Aether_result_<safe-url-name>.json`.

### Hash lookup

```
python aether-hash.py <api_key> <file>                   # hashes the file, looks it up
python aether-hash.py <api_key> <sha256_hash>            # uses the hash directly
python aether-hash.py <api_key> <file> --fetch-full      # also downloads the full report
```

Retrieves the last sandbox report for a file without needing to re-scan it. If a file path is provided, the script computes its SHA256 locally before looking it up.

### Sandbox — IOC report

```
python aether-ioc.py <api_key> <file>                    # detonate, then report
python aether-ioc.py <api_key> <sha256_hash>             # read an existing report
python aether-ioc.py <api_key> <file> --multiscan --cdr  # add AV + CDR sections
python aether-ioc.py <api_key> <file> --archive-password infected
python aether-ioc.py <api_key> <file> --detail signals   # show example signals
python aether-ioc.py <api_key> <file> --all-iocs --csv   # full IOC list + CSV export
```

Submits a file for dynamic analysis exactly as `aether-file.py` does, then parses the report instead of just saving it, and prints:

- the **final verdict** with its threat level and confidence;
- the **signal groups** behind that verdict, bucketed by strength — the strongest bucket is what pushed the file over the line;
- **YARA rule hits** with their individual verdicts;
- the sandbox's **tags** (`packed`, `anti-debug`, `overlay`, …);
- **MITRE ATT&CK techniques** mapped from the observed behaviour patterns;
- every **IOC** the sandbox collected — domains, URLs, IPs, MD5/SHA1/SHA256, registry paths, UUIDs, e-mail addresses, crypto wallets — de-duplicated, grouped by type, and sorted with the most severe verdict first. Indicators the sandbox flagged as interesting are marked with `*`.

Every section of the output names the endpoint that produced it, so you can see which call yields which data.

#### Multiscan and Deep CDR sections

`--multiscan` and `--cdr` add two further sections. They are separate MDC workflows selected by the `rule` header, and only one rule is accepted per submission — so for a **file** target each flag costs one extra submission:

| Flag | Calls | Reads |
|---|---|---|
| `--multiscan` | `POST /v4/file` with `rule: multiscan`, then `GET /v4/file/{data_id}` | `scan_results.scan_details` (per-engine verdict, threat name, definition date), `total_avs`, `total_detected_avs` |
| `--cdr` | `POST /v4/file` with `rule: cdr`, then `GET /v4/file/{data_id}` | `process_info.post_processing` (`actions_ran`, `converted_to`, `sanitization_details`) and `sanitized` (`result`, `reason`, `file_path`) |

For a **hash** target both sections come from a single `GET /v4/hash/{hash}` — no upload, and nothing charged against the sandbox quota. Note that endpoint is distinct from `GET /v4/hash/{hash}/sandbox`: the former returns the cached multiscan/CDR view, the latter the dynamic-analysis report.

The CDR section reports **what was detected and removed**, not just that the file was cleaned. Each entry in `process_info.post_processing.sanitization_details.details[]` describes one class of active content:

| Field | Shown as | Example |
|---|---|---|
| `object_name` | the class of content | `JavaScript`, `TXT file` |
| `action` + `count` | what CDR did, to how many | `removed x5` |
| `object_metadata` | where it sat in the document | `/Catalog /OpenAction /JavaScript` |
| `object_details` | the removed content itself | `app.alert('one');` |
| `object_sha256` | a digest per removed object | `49227a8d1776…` |

For example, submitting a PDF carrying five JavaScript actions and an embedded file:

```
 Detected and sanitized: 6 object(s) across 2 class(es)
   - JavaScript: removed x5
       location : /Catalog /OpenAction /JavaScript
       location : /Catalog /Names /JavaScript /Names /JavaScript
       ... 2 more location(s)
       content  : app.alert('one');
       content  : var a=1+1;
       ... 2 more object(s) (use --detail all)
       sha256   : 49227a8d177686d78d12028cdd76be265f2d4e3296ae30769d7ffd5abb08e988
   - TXT file: sanitized
```

That is the audit trail for a sanitization — useful when you have to prove *which* active content was stripped from a document. Each list is capped at three entries per class; `--detail all` prints every one. When CDR rebuilds a file but finds no active content, the section says so explicitly rather than showing an empty list.

Note that what gets removed depends on the workflow's CDR configuration — in the default Cloud `cdr` workflow, embedded JavaScript is removed while a plain URI link annotation is left in place.

The sanitized file is a pre-signed URL retained for 24 hours only. This sample reports that it exists; use `cdr-file.py` to download it.

#### Encrypted archives

`--archive-password` sends the `archivepwd` header so the service opens a password-protected archive server-side — useful for samples distributed with the `infected` convention, since nothing is ever extracted on the submitting host. Archives produce a **parent report with child reports**: the parent's `reports.next_level[]` lists the extracted items, and the content-bearing report is often several levels down.

Passing a hash instead of a file path reads the last existing report via `GET /v4/hash/{hash}/sandbox`. That uploads nothing and does not consume a sandbox run, which makes it the cheap way to re-render a report you have already paid for.

#### Reading the report JSON yourself

The document behind `full_report.json` carries two views of the same run, and it is worth knowing which one you want:

| View | Style | Contents |
|---|---|---|
| `overview_report` | flattened, `snake_case` | `final_verdict`, `signal_groups[]`, `yara_matches[]`, `tags[]`, `iocs[][]`. This is what `aether-ioc.py` renders. |
| `full_report` | complete, `camelCase` | `allSignalGroups[]`, `allTags[]`, `iocs{}` keyed by type, `yaraMatches[]` with matched strings and offsets, `summary.behaviorPatterns[]` with the MITRE mappings. |

Two gotchas worth knowing before you write your own parser:

- **`full_report` is a JSON string, not an object.** It needs a second `json.loads()` pass.
- **`overview_report.iocs` is a list *of lists*** — one inner list per analysed sub-file — so the same domain routinely appears more than once and needs de-duplicating.

There is no dedicated IOC endpoint on MetaDefender Cloud — the indicators are a field inside the report document, reached through the URLs in `full_report`. Those URLs carry a long token in the path and are served **without** the `apikey` header, so treat each one as a bearer credential for that report: don't log them or paste them into tickets.

### MalwareBazaar detection-coverage sweep

Moved to its own folder so it can be shared on its own: [`../mb-sweep/`](../mb-sweep/). It builds a date-spread corpus of live malware from abuse.ch, runs each sample through the sandbox, AV multiscan and Deep CDR, and reports how MetaDefender rated a set of known-bad files.

## Flags (where supported)

- `--dump` — prints the full JSON response from the API in addition to the summary. Useful for debugging or discovering fields that the summary doesn't surface.
- `--fetch-full` (`aether-hash.py` only) — downloads the complete behavioral report from the `full_report.json` / `store_at` URL.
- `--sandbox` (`aether-file.py`, `aether-ioc.py`) — selects the sandbox image (`windows10`, `windows7`, `linux`). Defaults to `windows10`.
- `--detail` (`aether-ioc.py` only) — signal verbosity: `summary` (one line per behaviour, the default), `signals` (a few examples each), or `all`. A real sample emits hundreds of signals.
- `--multiscan` (`aether-ioc.py`) — adds the multi-engine AV section.
- `--cdr` (`aether-ioc.py` only) — adds the Deep CDR section.
- `--archive-password` (`aether-ioc.py` only) — sends `archivepwd` so the service opens an encrypted archive server-side; nothing is extracted locally.
- `--all-iocs` (`aether-ioc.py` only) — prints every IOC instead of the first 10 per type.
- `--min-strength N` (`aether-ioc.py` only) — hides signals weaker than N (0.0–1.0).
- `--csv [PATH]` (`aether-ioc.py` only) — writes the collected IOCs to CSV for import into a SIEM or threat-intel platform.
- `--save-report` (`aether-ioc.py` only) — also saves the raw report JSON.
- `--no-color` (`aether-ioc.py` only) — disables ANSI color, which is also disabled automatically when stdout is redirected.

## Output

Scripts that save files to disk do so in the current working directory:

- `sanitized_<original_name>` — the CDR-reconstructed clean file
- `Aether_result_<n>.json` — the full sandbox behavioral report
- `iocs_<n>.csv` — the IOCs collected by the sandbox (`type`, `type_display_name`, `indicator`, `verdict`, `is_interesting`)

## Rate limits and entitlements

Each API key has separate daily limits for multi-scanning, Deep CDR, DLP, sandbox runs, and hash lookups. Check your current limits on the [account page](https://metadefender.opswat.com/account).

**Sandbox analysis is a paid/entitled feature on most tiers.** If you submit a file with the `sandbox` header and the response comes back without a `sandbox_id`, your key likely doesn't have a sandbox entitlement. `aether-file.py` includes a diagnostic routine that prints likely causes when this happens.

## Troubleshooting

**HTTP 400 "Invalid Content-Type"** — the file endpoint requires either `application/octet-stream` (binary upload) or `multipart/form-data`. These samples use `application/octet-stream`.

**HTTP 400 "Header is not valid. 'rule' can't be 'X'"** — `rule` accepts exactly one workflow name (`multiscan`, `cdr`, `dlp`, `sanitize`, `unarchive`). Underscore-joined combinations are not accepted, and there is no `rule: sandbox`.

**HTTP 429** — daily rate limit hit. Wait for the reset (24 hours from your first request of the day) or upgrade your plan.

**Empty `sandbox` object in file scan response** — your API key does not have a sandbox entitlement, the file type isn't supported by the sandbox, or your daily sandbox quota is exhausted.

**HTTP 404 on hash lookup** — no sandbox report exists for that hash. Submit the file fresh via `aether-file.py` to generate one.

## References

- [MetaDefender Cloud API v4 documentation](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4)
- [Rate limits and pricing](https://metadefender.opswat.com/licensing)
- [Supported file types for sandbox](https://www.opswat.com/docs/filescan/datasheet/supported-file-types)

## Integrating MetaDefender into your product?

If you're building file security into a commercial product or service, OPSWAT offers OEM licensing for MetaDefender Cloud and a broader OEM SDK covering advanced threat detection, vulnerability assessment, and endpoint security. Reach out to **oem@opswat.com** to discuss integration, licensing, and commercial terms.

For more on OPSWAT OEM solutions, see [OEM SDK — Advanced Threat Detection & Endpoint Security](https://www.opswat.com/products/oem).

## Author

Chris Seiler

## License

Copyright (c) 2026 OPSWAT, Inc. All rights reserved.

These samples are provided as-is for demonstration and integration reference purposes.
