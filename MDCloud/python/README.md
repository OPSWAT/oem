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

## Common concepts

All scripts share the same authentication and polling patterns.

**Authentication.** Every request sends `apikey: <your key>` as an HTTP header.

**Workflow selection.** The MetaDefender Cloud API uses a `rule` header on `POST /v4/file` to pick which workflow to run. Valid values on Cloud are `multiscan`, `cdr`, `dlp`, `sanitize`, `unarchive`, or combinations like `multiscan_sanitize_unarchive`. Note that sandbox analysis is **not** a rule — it is controlled by a separate `sandbox` header.

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

## Flags (where supported)

- `--dump` — prints the full JSON response from the API in addition to the summary. Useful for debugging or discovering fields that the summary doesn't surface.
- `--fetch-full` (`aether-hash.py` only) — downloads the complete behavioral report from the `full_report.json` / `store_at` URL.
- `--sandbox` (`aether-file.py` only) — selects the sandbox image (`windows10`, `windows7`, `linux`). Defaults to `windows10`.

## Output

Scripts that save files to disk do so in the current working directory:

- `sanitized_<original_name>` — the CDR-reconstructed clean file
- `Aether_result_<n>.json` — the full sandbox behavioral report

## Rate limits and entitlements

Each API key has separate daily limits for multi-scanning, Deep CDR, DLP, sandbox runs, and hash lookups. Check your current limits on the [account page](https://metadefender.opswat.com/account).

**Sandbox analysis is a paid/entitled feature on most tiers.** If you submit a file with the `sandbox` header and the response comes back without a `sandbox_id`, your key likely doesn't have a sandbox entitlement. `aether-file.py` includes a diagnostic routine that prints likely causes when this happens.

## Troubleshooting

**HTTP 400 "Invalid Content-Type"** — the file endpoint requires either `application/octet-stream` (binary upload) or `multipart/form-data`. These samples use `application/octet-stream`.

**HTTP 400 "Header is not valid. 'rule' can't be 'X'"** — `rule` only accepts workflow names (`multiscan`, `cdr`, `dlp`, `sanitize`, `unarchive`, or combinations). There is no `rule: sandbox`.

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
