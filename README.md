\# OPSWAT OEM Integration Samples



Reference integrations, sample code, and starter projects for building on top of OPSWAT technologies — \[MetaDefender Cloud](https://www.opswat.com/products/metadefender/cloud), \[MetaDefender Core](https://www.opswat.com/products/metadefender/core), \[MetaDefender Aether](https://www.opswat.com/products/metadefender/aether) (Sandbox), Deep CDR, Proactive DLP, and more.



This repository is maintained by OPSWAT as a learning and starting point for OEM partners and integrators. The samples are intentionally small, focused, and easy to copy into your own projects.



\## Repository layout



```

oem/

├── MDCloud/

│   └── python/         # MetaDefender Cloud API v4 — Python samples

└── MetaDefender/       # MetaDefender Core / on-prem integration samples

```



| Folder | Contents | Target audience |

|---|---|---|

| \[`MDCloud/python`](./MDCloud/python) | Standalone Python scripts for MetaDefender Cloud API v4: multi-scan, Deep CDR, Proactive DLP, Aether sandbox (file and URL), hash-based sandbox lookup. | Developers integrating cloud-based file/URL security into SaaS, web apps, or back-end services. |

| \[`MetaDefender`](./MetaDefender) | Samples targeting on-premises MetaDefender Core (primarily C#). | Developers embedding MetaDefender Core into desktop or server applications, custom engines, or air-gapped environments. |



Each subfolder has its own README with setup instructions and per-sample documentation.



\## Choosing the right product



| If you need… | Use | Deployment |

|---|---|---|

| A hosted API for scanning files, URLs, hashes | \*\*MetaDefender Cloud\*\* | SaaS (`api.metadefender.com`) |

| On-prem multi-scanning, CDR, DLP, vulnerability assessment | \*\*MetaDefender Core\*\* | Self-hosted (Windows, Linux, Docker, K8s) |

| Dynamic analysis / sandbox detonation in the cloud | \*\*MetaDefender Aether\*\* (via MDC) | SaaS, included in Cloud API |

| Adaptive sandbox on-prem | \*\*MetaDefender Aether / Sandbox\*\* | Self-hosted |



\## Getting started



1\. \*\*Pick the product\*\* that matches your deployment model (SaaS vs on-prem).

2\. \*\*Get an API key or license.\*\* Free MetaDefender Cloud keys are available at \[metadefender.opswat.com](https://metadefender.opswat.com/account). Core licenses come through your OPSWAT sales contact.

3\. \*\*Open the relevant subfolder\*\* and follow its README. Every sample runs on Windows, macOS, and Linux unless otherwise noted.



\## Documentation



\- \[MetaDefender Cloud API v4 reference](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4)

\- \[MetaDefender Core documentation](https://docs.opswat.com/mdcore/metadefender-core)

\- \[MetaDefender Aether / Sandbox documentation](https://www.opswat.com/docs/filescan)

\- \[All OPSWAT product documentation](https://docs.opswat.com/)



\## Contributing



Bug fixes and sample improvements are welcome via pull request. Please read the \[Code of Conduct](./CODE\_OF\_CONDUCT.md) and \[Contributing guide](./CONTRIBUTING.md) before submitting. For substantial new samples, open an issue first to discuss scope and fit.



\## Support



These samples are provided as reference material and are \*\*not a supported product\*\*. For production use of OPSWAT technologies, please engage OPSWAT Support through your standard channel, or reach out to the OEM team (see below) for commercial support options.



If you find a bug in a sample, please \[open an issue](https://github.com/OPSWAT/oem/issues).



\## Building on OPSWAT technologies?



If you're embedding file security, threat detection, or endpoint compliance into a commercial product or service, OPSWAT offers OEM licensing for MetaDefender Cloud, MetaDefender Core, and the broader OEM SDK — covering advanced threat detection, vulnerability assessment, and endpoint security.



Contact \*\*oem@opswat.com\*\* to discuss integration, licensing, and commercial terms.



For an overview of the OEM program, see \[OEM SDK — Advanced Threat Detection \& Endpoint Security](https://www.opswat.com/products/oem).



\## License



Copyright (c) 2026 OPSWAT, Inc. All rights reserved.



These samples are provided as-is for demonstration and integration reference purposes. See individual subfolders for any license notes specific to that sample.

