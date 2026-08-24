# MalwareBazaar detection-coverage sweep

A standalone harness that builds a date-spread corpus of live malware from
[abuse.ch MalwareBazaar](https://bazaar.abuse.ch/api/), runs every sample through
[OPSWAT MetaDefender Cloud](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4)
— sandbox, AV multiscan and Deep CDR — and reports how MetaDefender rated a set of files that
are already known to be malicious.

Because MalwareBazaar only hosts confirmed malware, **every sample is a known positive**. The
valuable output is therefore inverted: not "what did we catch" but the list of samples that came
back below `SUSPICIOUS`, with enough per-file detail for an engine team to act on.

Runs on Windows, macOS and Linux. One file, one dependency.

## Contents

```
malwarebazaar-sweep.py      command line: argument parsing and orchestration
mbsweep/
├── config.py               endpoints, catalogues, verdict order, timing budgets
├── malwarebazaar.py        abuse.ch queries, candidate pool, day-spread selection
├── downloads.py            where files land, and how that directory is guarded
├── cleanfiles.py           known-clean controls, and mutating them to a unique hash
├── runstore.py             dated run folders, manifests, cross-run state
├── submit.py               POSTing files to MetaDefender Cloud
├── reportfetch.py          reading scan payloads and sandbox reports back
├── polling.py              driving the submitted batch to completion
└── reporting/
    ├── markdown.py         the report: summary table and per-sample dossiers
    ├── csvexport.py        one flat row per sample, for trending
    └── console.py          the terminal summary
├── settings.py             the config file: parsing, validation, precedence
mb-sweep.conf.sample        documented template - copy this, distribute this
mb-sweep.conf               your live config, with keys (gitignored)
requirements.txt            the single runtime dependency (requests)
README.md                   this document
```

The split follows the shape of a run: discover candidates, get files onto disk, submit,
poll, report. Two boundaries are deliberate — `downloads.py` holds rules that apply to
anything written to disk whatever its source, so a second sample source needs no new
quarantine logic; and `reporting/` never talks to an API, so output can be reshaped
without touching collection.

Everything is standard library plus `requests`. Run the entry script from anywhere:
Python puts its directory on the path, so `mbsweep` imports without installation.

## Prerequisites

- Python 3.8 or later
- A **MetaDefender Cloud API key** — free tier at [metadefender.opswat.com](https://metadefender.opswat.com/account). Check `limit_sandbox` on `GET /v4/apikey`: the free allowance is small (5/day at the time of writing), and each sample costs one sandbox run.
- A **MalwareBazaar Auth-Key** — from your [abuse.ch account](https://bazaar.abuse.ch/account/). Every MalwareBazaar API call, metadata included, now requires it.
- `pip install -r requirements.txt`

## Configuration file

Settings live in `mb-sweep.conf` beside the script, so a routine run is one command with no
arguments:

```
python malwarebazaar-sweep.py
```

Copy `mb-sweep.conf.sample` to `mb-sweep.conf` and fill in the two keys. Every setting is
documented in the sample; the file is found automatically, next to the script or in the working
directory, and `--config PATH` points at a different one.

**Precedence is defaults, then the file, then the command line** — so anything in the file can be
overridden for a one-off without editing it:

```
python malwarebazaar-sweep.py --malware-count 20 --dry-run
```

Every run states what the config contributed, with the keys deliberately not echoed:

```
[+] Config: C:\...\mb-sweep.conf (2 key(s); 16 setting(s): clean_docs, clean_pe_count, ...)
```

The file is **validated rather than best-effort**, because a setting that is silently ignored
looks exactly like a setting that did not work:

| Mistake | Result |
|---|---|
| `malware_kount = 5` | `unknown setting 'malware_kount'. Valid settings are: ...` |
| `malware_count = five` | `setting 'malware_count' expects int, got 'five'` |
| missing `[sweep]` header | `has no [sweep] section - see mb-sweep.conf.sample` |
| `--config nope.conf` | `Config file not found: nope.conf` |

A blank value means "leave the default alone", so settings can be commented out or emptied
without special-casing.

`mb-sweep.conf` holds live API keys. The `.gitignore` beside it excludes the file, and the
shareable zip contains only the `.sample` — so distributing the tool never distributes the keys.
The MetaDefender key may still be given as the first positional argument, and `MB_AUTH_KEY` is
still read from the environment, for cases where a config file is not wanted.

## Quick start

Always dry-run first. It selects samples and prints the plan without downloading or submitting
anything, so it costs no quota:

```
python malwarebazaar-sweep.py --dry-run
```

Then the real run:

```
python malwarebazaar-sweep.py
```

Both read `mb-sweep.conf` for the keys and the corpus sizes. Without a config file, pass the
MetaDefender key as the first argument and the abuse.ch key with `--mb-key`.

On Windows keep `--out-dir` shallow. Archives are named `<64-char sha256>.zip`, and a deep root
pushes paths past the 260-character limit — which surfaces as a file-not-found error on a
directory that plainly exists. The script predicts this and warns.

## Safety model

This tool downloads live malware. Two properties keep that manageable:

1. **Nothing is ever extracted or executed locally.** MalwareBazaar serves each sample as a ZIP
   encrypted with the password `infected`. The script uploads that archive *still encrypted* and
   sets the `archivepwd` header so MetaDefender opens it server-side. Detonation happens in
   OPSWAT's sandbox, never on the machine running the sweep.
2. **The download directory is treated as quarantine.** The script writes a `.gitignore` and a
   `WARNING.txt` into it, and refuses a path that looks like a synced cloud folder (OneDrive,
   Dropbox, SharePoint, …) unless you pass `--allow-synced-dir`.

Those archives are real malware, merely locked. Prune old dated folders when you are done with
them, and do not let a backup client index the directory.

```
python malwarebazaar-sweep.py <mdc_api_key> --dry-run          # plan only, no downloads
python malwarebazaar-sweep.py <mdc_api_key>                    # 3/day, stop at 50
python malwarebazaar-sweep.py <mdc_api_key> --per-day 5 --malware-count 100
python malwarebazaar-sweep.py <mdc_api_key> --from-dir mb-sweeps/2026-08-20
python malwarebazaar-sweep.py <mdc_api_key> --file-types docx,xlsx,pdf,lnk
```

Builds a corpus of confirmed-malicious samples from [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/api/), runs each through MetaDefender Cloud, and reports the results. Because MalwareBazaar only hosts real malware, every sample is a **known positive** — so the interesting output is the list of samples that came back below `SUSPICIOUS`.

Requires a MalwareBazaar Auth-Key in `MB_AUTH_KEY` (or `--mb-key`) in addition to your MetaDefender key.

**Samples are never extracted locally.** MalwareBazaar serves each sample as a ZIP encrypted with the password `infected`; the script uploads that encrypted archive with the `archivepwd` header and lets the service open it server-side. Decrypted malware never exists on the machine running the sweep, and nothing is executed there — detonation happens in OPSWAT's sandbox.

The download directory is still a quarantine area holding live (if locked) malware. The script writes a `.gitignore` and a `WARNING.txt` into it, refuses a path that looks cloud-synced unless you pass `--allow-synced-dir`, and supports `--delete-after` to remove each archive once submitted — recommended for scheduled runs.

## The results summary

The report opens with one row per submitted file, putting the three engine results side by side:

| # | File | Expected | Multi-Scan | Deep CDR | Sandbox |
|---|---|---|---|---|---|
| 1 | `njrat.exe` njrat / exe | malicious | **Infected** - 4 of 12 engines `Malware/Win.VMProtect` +2 | Unsupported file type | **MALICIOUS** (1.0) 12 signal groups, 3 YARA, 19 IOCs |
| 2 | `invoice.docm` AgentTesla / docx | malicious | **No Threat Detected** - 0 of 12 engines | **Sanitized** as pdf, 3 objects removed (JavaScript) | **SUSPICIOUS** (0.5) |
| 3 | `PROTTPLN.DOC` (known clean) / doc | clean | **No Threat Detected** - 0 of 12 engines | **Sanitized**, 0 objects removed | **NO_THREAT** (0.25) |
| 4 | `mirai.elf` Mirai / elf | malicious | - | - | **ERROR** no result within 15 minutes |

Multi-Scan gives the verdict *and* the engine hit count, with the distinct threat names beneath —
`Infected - 4 of 12 engines` says considerably more than `Infected` alone. Rows sort malware
first, most severe verdict at the top, with clean controls after.

Where the three columns **disagree** is the interesting part. Row 2 above is the case worth
chasing: the sandbox called it suspicious and CDR stripped active content out of it, yet not one
AV engine fired. Row 4 shows a timeout rendered as an explicit error rather than as three quiet
cells that could be mistaken for a clean result.

The per-sample dossiers further down still carry the full detail — every engine detection, every
removed CDR object with its document location, the signal groups, MITRE techniques and IOCs.

## Reading the AV and CDR columns

Malware always arrives inside an `infected`-encrypted archive, and that changes what the AV and
CDR results describe. Both are now stated explicitly rather than left to inference.

**AV on an archive reports two different levels.** The container itself is clean by construction,
so the top level says `scan_all_result_a: "Infected"` (aggregated from what was extracted) while
`total_detected_avs` is 0 and every engine row is empty. Reading only the top level produces the
contradiction *"Infected - 0 of 12 engines"*. The real numbers live on the extracted child, in
`extracted_files.files_in_archive[]`, where `detected_by` is the engine count; the threat names
come from that child's own scan:

```
multi-scan: Infected - 4 of 12 engine(s) detected it [counts from the extracted file]
            -> Trojan ( 006dd1e91 ), Trojan/Win.Generic, W32/ABTrojan.ORGD-3846 +1
```

**Three AV states are kept distinct**, because a single number cannot express them and only one is
a detection result:

| State | Rendered | Meaning on a known-bad sample |
|---|---|---|
| engines ran, flagged it | `Infected - 4 of 12 engine(s) detected it` | caught |
| engines ran, found nothing | `No Threat Detected - 0 of 12 engine(s) detected it` | a **finding** |
| no AV verdict at all | `NOT SCANNED` | a gap in the measurement, not a result |

The console summary separates the last two as well — `AV clean` versus `AV not scanned` — so a
missing verdict is never counted as a clean one.

**CDR on an archive acted on the container.** `Sanitized as zip - 0 object(s) removed` against a
malware sample means the zip was rebuilt, not that the payload inside is free of active content.
That is now said outright:

```
deep cdr  : Sanitized as zip - 0 object(s) removed [acted on the submitted archive, not the file inside]
```

Clean controls are submitted as plain files, so their AV and CDR numbers need no such caveat — and
the difference is visible: clean PEs come back `NOT SANITIZED - File is not sanitizable` because a
PE never enters CDR, while clean documents report `Sanitized as pdf`. That contrast is the reason
to run both `clean_pe_count` and `clean_docs`.

Every sample now prints all three views as it resolves, not just the sandbox verdict.

## AV engine results across the run

The summary lists **every engine that returned a verdict**, with what it caught across the corpus
and — in the same table — what it flagged among the known-clean controls:

```
Engine results (5 malware, 3 clean control(s) scanned):
   ENGINE                       MALWARE    CONTROLS
   Varist                           4/5         0/3
   Xvirus Anti-Malware              3/5         0/3
   OPSWAT Predictive Alin AI        1/5         0/3
   AhnLab                           0/5         0/3
   ...
```

```
   ENGINE                      DETECTED  NOT SCANNED    CONTROLS
   Varist                           4/5            -         0/3
   SentinelOne                      0/2            3         0/3  <-- filetype not supported
   RocketCyber                      0/0            5         0/2  <-- filetype not supported
```

**The denominator is what the engine actually examined.** Per-engine results carry a
`scan_result_i` code, and only `0` (no threats found), `1` (infected) and `2` (suspicious) are an
engine opinion about the file. `23` means *filetype not supported*, `3` failed to scan, `10` the
engine skipped it. An engine that answered "filetype not supported" did not look and miss, so
counting it as a clean scan would misrepresent it — those land in `Not scanned` with the reason
attached.

The difference is not cosmetic. In the run above, RocketCyber shows `0/0 detected, 5 not scanned`:
it never examined a single sample in that corpus. Reported as `0/5` it would look like an engine
that missed five malware samples.

`Controls` is hits on files known to be clean, where anything above zero is a false positive — and
a non-zero control count is marked inline rather than left to be spotted in a column of
similar-looking numbers. The report adds the threat names each engine reported, and names the
engines that examined files and detected nothing.

Per-sample dossiers say the same thing in the singular:

```
`Infected` - 1 of 10 engine(s) that examined this file detected it.
2 engine(s) returned no opinion (2 x filetype not supported): `RocketCyber`, `SentinelOne`.
```

## Detections with no engine attribution

A separate section lists scans whose verdict implies a detection while **no engine reported a
threat name**:

```
Detections with no engine attribution: 1
   (verdict implies a detection but no engine reported a threat)
   ! aaaaaaaaaaaaaaaa... zip   Infected - 0/12 engines
```

A detection nobody owns cannot be acted on, so these are listed rather than counted as either
caught or clean. The usual cause is an archive submission: the verdict is aggregated from an
extracted file while the per-engine detail sits on that child rather than on what was submitted.
That is exactly the trap described above — this section exists so it can never hide again.

## Clean controls (false-positive testing)

A corpus of nothing but malware measures **recall** and says nothing about **false positives** —
and a detection on a signed operating-system binary is a more damaging product defect than a
missed obscure sample. Two flags mix in files that are known-good:

```
--malware-count 5                # 5 malware samples from MalwareBazaar
--clean-pe-count 5               # 5 clean PE binaries from %SystemRoot%\System32
--clean-docs 5                   # 5 clean productivity documents
--clean-dir C:\goodware          # every file in a folder you curate
```

Use **both** `--clean-pe-count` and `--clean-docs`: the same "not all PE" argument that applies to
the malware corpus applies to the controls. A document goes through Deep CDR and the document
sandbox — code paths a PE never touches, and where a false positive is most likely, because
"contains active content" heuristics fire on structure rather than on code. In testing, clean
PEs came back `not sanitizable` from CDR while clean documents came back `Sanitized`, which is
the difference in coverage made visible.

`--clean-docs` finds **real vendor-shipped documents** rather than synthesising any — measuring
the sandbox's opinion of a hand-rolled file would tell you about the file, not the product. On a
typical Windows machine with Office installed it locates seven types in a few seconds:

```
[+] 8 clean document(s): {'pdf': 2, 'doc': 1, 'xlsx': 1, 'xls': 1, 'rtf': 1, 'ppt': 1, 'csv': 1}
  doc     19,968  C:\Program Files\Microsoft Office\root\Office16\1033\PROTTPLN.DOC
  xlsx     5,760  C:\Program Files\Microsoft Office\root\vfs\Windows\SHELLNEW\EXCEL12.XLSX
  rtf      3,669  C:\Program Files (x86)\Microsoft SDKs\...\Eula.rtf
```

Selection is round-robin across extensions, because Windows ships dozens of identical copies of
the same licence RTF and a naive pick would submit ten of those and call it document coverage.
Content hashes de-duplicate the copies. `WinSxS` is skipped — it is enormous and holds nothing
but more duplicates.

Controls are submitted as plain files (no `archivepwd` — they are not encrypted archives), are
never deleted by `--delete-after`, and are deliberately **not** recorded in the state file, so
they are re-tested on every run. That includes `--from-dir` re-runs, which is how a
false-positive regression surfaces after an engine or workflow change.

The system-directory pick is deterministic — sorted, then strided — so the same machine
contributes the same control set each run and results stay comparable.

### Controls are mutated so their hash is unique

MetaDefender caches results by hash, and a stock system file is very likely already known —
possibly reputation-allowlisted. Submitting one unchanged can return a cached or
reputation-derived "clean" without the analysis engines doing real work, which defeats the
purpose of a false-positive test. So each control is **copied and cosmetically modified** before
submission, giving it a hash the service has never seen. `--no-mutate-clean` turns this off.

Originals are never touched — the mutated copy lands in `<run>/samples/clean/`. The mutation is
format-aware, because how you change the bytes matters:

| Format | Mutation | Effect on the file |
|---|---|---|
| `.docx` `.xlsx` `.pptx` | ZIP archive comment | every part byte-identical; readers ignore the comment |
| `.pdf` | trailing `%` comment after `%%EOF` | header and page tree untouched |
| `.rtf` `.csv` `.txt` `.xml` | trailing blank line | no parser objects |
| everything else (PE, `.doc`/`.xls`/`.ppt`) | bytes appended as an overlay | **invalidates any Authenticode signature** |

That last row is the honest caveat: on a signed binary an appended overlay breaks the signature,
and some engines treat a broken signature or an unexpected overlay as suspicious in itself. A
detection on such a control may be a reaction to the mutation rather than a true false positive.
The CSV records `mutation` and `original_sha256` for every control so you can tell the two apart,
and the console prints both hashes:

```
    clean control (26118 bytes (local, clean)) [appended overlay (invalidates any signature)]
      submitted as 092d4007c9abdc39... (was ec6c0605b54b77a1...)
```

Verified on this machine: the mutations changed every hash while keeping the formats valid — the
XLSX remained a 9-part archive passing `testzip()`, the PDF kept its `%PDF` header and `%%EOF`.
Worth noting what mutation revealed: an **unmodified** system DLL came back `BENIGN`
(threat level -1), while the **same DLL mutated** came back `NO_THREAT` (0.25). The unmodified
submission was getting a shortcut answer; the mutated one got a real analysis. That is precisely
why this is on by default. Neither was a false positive.

Reporting keeps the two populations apart. Detection coverage counts only known-malicious
samples; controls get their own section:

```
 Rated >= SUSPICIOUS : 4 of 5 malware
 False positives     : 1 of 10 clean control(s)
   ! notepad.exe -> SUSPICIOUS (AV 0/12)
 AV on controls : 0 of 10 clean file(s) flagged by an engine
```

A control counts as a false positive if the sandbox rated it `SUSPICIOUS` or worse **or** any AV
engine flagged it. The CSV gains `expected` and `false_positive` columns so both populations can
be trended separately.

Worth knowing before you interpret the results: in testing on this machine, `notepad.exe` came
back `SUSPICIOUS` (threat level 0.50) from the sandbox while `calc.exe` came back `NO_THREAT`.
Both are signed Microsoft binaries. That is exactly the kind of finding this mode exists to
surface.

## How a run executes: submit everything, then poll

Submissions are not waited on one at a time. Every file is submitted first — the sandbox pass
plus the AV and CDR passes — and each `data_id` is recorded in a map keyed by the hash actually
submitted, together with that sample's expectation (`malicious` or `clean`). Only then does a
single poller drive the whole batch to completion.

This matters because a detonation takes minutes and the service is happy to work on the batch in
parallel. Waiting per file serialises the slowest part of the run; submitting first collapses it.
A four-file batch that took 1m26s sequentially finished in **45s**, and the gap widens with
sample count.

```
[+] 4 of 4 submission(s) accepted; nothing has been waited on yet

[+] Polling every 60s for up to 15 minutes (4 submission(s) in flight)
    [ 1] 4 still pending, 14m52s left (detonating)
    [ 2] a6fb4abdf5adba5c... SUSPICIOUS        pdf    (malicious)
    [ 2] d651dbf82ffcb853... NO_THREAT         pdf    (clean)
```

Each pending entry runs its own small state machine, because the views finish at different
speeds: AV and CDR are ordinary scans that return in seconds, while the sandbox has to reach 100%
on the file scan, then produce a verdict, then have its report fetched. The poller reports which
stages the batch is sitting in (`file scan`, `detonating`, …).

`--poll-interval` (default 60 seconds) and `--poll-window` (default 15 minutes) control the
cadence and the deadline.

### Anything without a result is an error

When the window closes, every unresolved submission is recorded as a failure naming the stage it
stalled at:

```
    ! a6fb4abdf5adba5c... no result within 15 minutes (stalled at: file scan)
```

Those rows appear in the report's **Failures** table with their sandbox ID, and are excluded from
both the detection-coverage and false-positive counts. A sample with no result is a failed
measurement, not a passing one — counting a timeout as "clean" would understate misses on the
malware side and hide false positives on the control side.

## Watching a run

Each sample reports all three views as it completes, so a problem is visible without waiting for
the report:

```
[4/5] 622ad8a0eb9290c6...  njrat  exe  first seen 2026-08-19
    downloaded sealed archive (28103 bytes)
    verdict: MALICIOUS (threat level 1, chain depth 1, 10 IOCs)
    AV: Infected - 4 of 12 engine(s) found a threat [Malware/Win.VMProtect, W64/ABTrojan.RSWD-6924, Win/malicious_93 (+1 more)]
    CDR: Sanitized (1 object(s) removed)
```

`AV:` gives the multiscan outcome (`Infected` / `No Threat Detected`), how many of the engines
flagged the sample, and up to three distinct threat names. On a corpus of confirmed malware,
`No Threat Detected` is the line worth stopping on.

The closing summary aggregates the same figures:

```
 Rated >= SUSPICIOUS : 4 of 5
 AV infected    : 3 of 5 (engines flagging: min 2, max 9)
 AV clean       : 2  <-- known-malicious but no engine detection
 CDR sanitized  : 1 of 5
```

## Run folders and repeatability

Every run writes to `<out-dir>/<YYYY-MM-DD>/`, defaulting to `mb-sweeps/`:

```
mb-sweeps/
├── mb-sweep-state.json            hashes already submitted, across all runs
└── 2026-08-20/
    ├── manifest.json              MalwareBazaar metadata for each sample
    ├── samples/                   the sealed archives, retained
    │   ├── .gitignore             so they can never be committed
    │   ├── WARNING.txt
    │   └── <sha256>.zip
    ├── mb-sweep-<stamp>.md        the report
    ├── mb-sweep-<stamp>.csv
    └── mb-sweep-<stamp>.json
```

Archives are **kept** by default so a run can be repeated against the identical corpus:

```
python malwarebazaar-sweep.py <mdc_api_key> --from-dir mb-sweeps/2026-08-20
```

That re-submits the retained archives and never contacts MalwareBazaar, which makes it the way to re-test after a workflow or engine change and compare like with like. The manifest is what makes it work — family, file type and first-seen date come from the API, not from the file, so without it a retained folder is just anonymous ZIPs.

`--delete-after` still exists but breaks repeatability; prefer pruning old dated folders. On Windows, keep `--out-dir` shallow: archives are named `<64-char sha256>.zip`, and a deep root pushes paths past the 260-character limit, which surfaces as a file-not-found error on a directory that plainly exists. The script predicts this and warns instead.

## Not just PE files

Real intrusions arrive as documents, shortcuts and container formats, and those exercise different sandbox paths than a raw binary — so the default tag list is deliberately weighted away from executables. All of these were verified to return data, with the date span each covers:

| Category | Tags | Span observed |
|---|---|---|
| Documents | `docx` `doc` `xlsx` `xls` `rtf` `ppt` `pptx` `pdf` `one` `xll` | 18–38 days |
| Scripts / shortcuts | `lnk` `js` `vbs` `ps1` `hta` | 1–28 days |
| Containers | `iso` `zip` `rar` `7z` | 7–33 days |
| Binaries | `exe` `dll` `msi` `apk` `elf` | varies |

Selection spreads three ways — **least-represented file-type category first**, then least-used family, then smallest file. A twelve-sample dry run came out at three each of document, script, archive and binary, across eleven distinct file types. The report opens with a "Corpus composition" table so a PE-heavy run is obvious at a glance, and `--file-types docx,xlsx,pdf` narrows to a specific format when you want to test one.

## How day coverage is built

MalwareBazaar's API has no date query, so coverage is assembled from what it does offer:

| Query | Reach | Used for |
|---|---|---|
| `get_siginfo&signature=<family>&limit=1000` | ~5 months | the main source of historical spread |
| `get_taginfo&tag=<tag>&limit=100` | ~2 weeks | variety beyond named families |
| `get_recent&selector=100` | current day only | discovering which families are active now |
| `get_file_type` | — | returns HTTP 502 at every limit tested; unused |

Discovery is ordered cheapest-first and runs concurrently. Tag queries (100 rows, ~2 weeks of
history, about 4 seconds each) go first; if they already hold enough candidates for the requested
`--malware-count`, the family queries — 1000 rows each and months of history — are skipped
entirely. A five-sample run never needs them.

Two measurements drove this. A healthy tag query returns in ~4s, but the `exe` tag sat for 30
seconds before answering 502 — and retrying it three times with backoff cost roughly 100 seconds,
which was the entire discovery phase. So the broad sweep now runs single-attempt with a 12-second
timeout (losing one tag out of two dozen barely dents coverage, while retrying it dominated the
clock), and the deeper family queries keep a longer budget because they legitimately return ~2 MB.
Net effect on a five-sample run: **118s to 25s**. `--query-workers` tunes the concurrency.

Results from all queries are pooled and de-duplicated by SHA256, grouped by `first_seen` date, then sampled `--per-day` at a time from the newest day backwards until `--malware-count`. Within a day, the least-represented family wins, so one prolific family cannot dominate; ties break toward the smaller file, and `--max-size` (default 32 MB) skips outliers that would only slow the run.

Submitted hashes are recorded in `--state`, so running this on a schedule keeps widening coverage rather than re-scanning the same samples. `--forget` resets it.

## What each sample is tested with

Every sample gets three MetaDefender passes — the `rule` header accepts only one workflow per submission, so each is its own upload of the same sealed archive:

| Pass | Header | Yields |
|---|---|---|
| Sandbox | `sandbox: windows10` | verdict, signal groups, YARA hits, tags, MITRE techniques, IOCs |
| AV multiscan | `rule: multiscan` | per-engine verdicts with threat names and definition dates |
| Deep CDR | `rule: cdr` | what was detected and removed, per object, with document locations |

Three submissions per sample: one against `limit_sandbox`, two against `limit_analysis`. `--no-av` and `--no-cdr` drop the extra passes.

## The per-sample dossier

The report devotes a section to each sample, so a finding can be acted on without re-running anything:

```
## 1. TestStandIn - pdf - SUSPICIOUS (caught)

| SHA256 | `a6fb4abd...` |
| Sample page | https://bazaar.abuse.ch/sample/<sha256> |
| MDC data_id | `YTI2MDgyMUlV...` |
| Sandbox ID | `6a88833bef4585e92a2ef608` |
| Sandbox report (HTML) | [open report](https://api.metadefender.com/...) |
| Verdict | **SUSPICIOUS** (threat level 0.5) |

**AV multiscan**
`No Threat Detected` - 0 of 12 engines flagged this sample.
No engine flagged it. For a confirmed-malicious sample, that is itself the finding.

**Deep CDR**
`Sanitized` - rebuilt as pdf.
| Object | Action | Count | Location |
| JavaScript | removed | 1 | `/Catalog /OpenAction /JavaScript` |

**Sandbox report**
10 signal group(s), 4 unique IOC(s).
- `0.50` Phishing PDF layout (single page, single clickable URL, very low semantic content)
- `0.25` PDF contains embedded JavaScript
YARA: `pdf_warning_openaction` (NO_THREAT), `suspicious_javascript_object` (NO_THREAT)
Tags: `javascript`, `macros`, `masquerade`, `phishing`
MITRE ATT&CK: T1036.008 Masquerade File Type, T1566 Phishing
IOCs by type:
- **Domain** (1): `example.com`
- **IP** (1): `172.66.147.243`
```

The HTML link comes from `full_report.html` and carries its own access token — it opens in a browser with **no API key**, which is what makes the report shareable with an engine team. Treat the file accordingly: each link is effectively a bearer credential for that one report.

Where an archive produced child reports, the dossier also prints the chain with a sandbox ID per node, so you can tell whether a low verdict came from the inert container or from the extracted content.

## Reading the report

Each run writes `mb-sweep-<stamp>.{md,csv,json}`. The Markdown report leads with a detection-coverage table and then a **"Rated below SUSPICIOUS"** table — the samples worth investigating. Note the `chain_depth` column: archives produce a parent report for the container plus children for the extracted content, and the container is inert, so the sweep reports the **most severe verdict anywhere in the chain** rather than the parent's. A missed detection with a shallow chain may mean extraction failed rather than that detection did.

## Nested archives: the one failure mode to know about

Every sample arrives inside an `infected`-encrypted zip. When the sample is **itself an archive**
(`zip`, `rar`, `7z`, ...), the sandbox has to open a second container it has no password for — and
it reports that as *silence*, not as an error: no verdict, no report, no child reports, and the
file endpoint says only `scan_all_result_a: "Not Scanned"`.

Measured across three runs of 15 samples: **3 of 4 archive samples never returned a verdict**,
while every non-archive type resolved normally. Queried hours later the three were still empty, so
a longer `--poll-window` does not help. A plain benign zip, by contrast, detonated in 15 seconds —
so this is nested-encrypted-archive handling, not a missing format.

The documented detonation targets are PE (`.exe .dll .com .cpl .ocx .drv .sys .efi .msi .msp`),
ELF, macOS binaries and `.pdf`, so an inner `.rar` has no detonation path in any case.

Two consequences for a run:

* Such samples are therefore **excluded by default**, and selection backfills with other types
  so the corpus stays the size you asked for. The exclusion is reported rather than silent:

```
[+] 381 nested-archive candidate(s) excluded (--include-nested-archives to keep them)
```

  `--include-nested-archives` puts them back — one of the four did resolve, so the door is left
  open — and then warns that the run may be spent for nothing.
* When one does stall, the report now says why rather than just "timed out":

```
! 941ad06660c3a0da... no result within 15 minutes (stalled at: detonating) - sample is
  itself an archive inside the encrypted container, so the sandbox must open a second
  archive it has no password for (.rar); scan=Not Scanned
```

A heads-up is printed before anything is submitted, so the cost is visible up front:

```
[!] 2 sample(s) are archives inside the encrypted container (rar, zip). The sandbox has no
    password for the inner archive and such samples often never return a verdict - use
    --skip-nested-archives to leave them out.
```

Worth raising with the engine team: a job that cannot complete should fail rather than hang.

## Troubleshooting

**`HTTP 502` from MalwareBazaar.** Common and usually transient — abuse.ch drops whole query
classes for minutes at a time. Every query is retried, and a failing family query is re-attempted
as a tag query before the family is dropped. Anything still unavailable is listed in the report
under "Data-source gaps", so a narrower corpus is never silent. `get_file_type` has never worked
in any session and is not used.

**A rejected submission** now reports MetaDefender's own error code rather than a dumped body,
which is what documentation and support tickets are keyed on:

```
upload rejected (HTTP 400; code 400020: Header is not valid. 'rule' can't be 'multiscan_sanitize')
upload rejected (HTTP 401; code 401000: Unauthorized)
```

**`HTTP 429` from MetaDefender.** The daily sandbox allowance is exhausted. It is metered
separately from ordinary scans — see `limit_sandbox` on `GET /v4/apikey`. The run stops cleanly
and the report is still written.

**`401 Unauthorized` from MalwareBazaar.** Missing or invalid Auth-Key. Note that even metadata
queries require one.

**A sample shows `NO_THREAT` with a shallow chain depth.** Check whether the archive extraction
failed rather than assuming detection did. Archives produce a parent report for the inert
container plus children for the content; the sweep reports the most severe verdict anywhere in
the chain and prints the chain per sample.

## References

- [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- [MetaDefender Cloud API v4](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4)
- The wider MetaDefender Cloud Python samples live in [`../python/`](../python/) — in particular
  `aether-ioc.py` for a deep single-file report and `cdr-file.py` for downloading a sanitized copy.

## Author

Chris Seiler

## License

Copyright (c) 2026 OPSWAT, Inc. All rights reserved.

Provided as-is for demonstration and integration reference purposes.
