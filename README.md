\# IOC Enrichment Script



A Python script that automates a routine SOC triage task: checking Indicators of Compromise (IOCs) against VirusTotal. Give it a list of IP addresses, domains, and file hashes, and it returns a CSV with detection counts and a verdict for each one.



\## Why this project



During alert triage, analysts often have to look up many IPs, domains, and hashes by hand. This script does the lookups automatically so the results can be reviewed in one table.



\## Features



\- Accepts IPs, domains, and file hashes (MD5, SHA-1, SHA-256) in one input file

\- Detects the IOC type automatically

\- Accepts defanged IOCs (for example `evil\[.]com` or `hxxp://...`)

\- Waits between requests to stay within the VirusTotal free-tier limit (4 lookups per minute)

\- Retries after a pause if the rate limit is hit

\- Writes results to a CSV file and prints a summary in the terminal



\## Requirements



\- Python 3.8 or newer

\- A free \[VirusTotal](https://www.virustotal.com) account and API key

\- The `requests` library



\## Setup



```bash

pip install requests

```



Set your API key as an environment variable. The key is never stored in the code or in this repo.



\*\*Windows (PowerShell):\*\*

```powershell

$env:VT\_API\_KEY="your\_api\_key\_here"

```



\*\*Linux / macOS:\*\*

```bash

export VT\_API\_KEY="your\_api\_key\_here"

```



\## Usage



```bash

python scripts/ioc\_enrich.py data/iocs.txt results/results.csv

```



The input file takes one IOC per line. Lines starting with `#` are ignored.



```text

\# Example input

8.8.8.8

example.com

275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

```



\## Verdict logic



| Verdict | Condition |

|---|---|

| MALICIOUS | 3 or more engines flag the IOC as malicious |

| SUSPICIOUS | 1 or 2 engines flag it as malicious, or at least 1 flags it as suspicious |

| CLEAN | No engine flags it |

| NOT FOUND | VirusTotal has no record of the IOC |



These thresholds are a simple starting point. A real triage decision should also consider context such as the source of the alert and how old the IOC is.



\## Example output



| IOC | Type | Malicious | Suspicious | Harmless | Undetected | Verdict |

|---|---|---|---|---|---|---|

| 8.8.8.8 | ip | 0 | 0 | 53 | 38 | CLEAN |

| example.com | domain | 0 | 0 | 61 | 30 | CLEAN |

| 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | hash | 66 | 0 | 0 | 2 | MALICIOUS |



The hash in the last row is the standard EICAR antivirus test file. It is harmless and is used here to confirm that detection works.



\## Project structure



```text

ioc-enrichment/

├── scripts/

│   └── ioc\_enrich.py     # main script

├── data/

│   └── iocs.txt          # sample input

├── results/

│   └── results.csv       # sample output

├── .gitignore

└── README.md

```



\## Limitations



\- Uses only VirusTotal, so results depend on one source

\- Free-tier rate limits make large lists slow (about 16 seconds per IOC)

\- Verdicts are based on detection counts only, with no scoring by context



\## Future improvements



\- Add AbuseIPDB lookups for IP reputation and abuse confidence scores

\- Add a caching step so repeated IOCs are not looked up twice

\- Include the VirusTotal link for each IOC in the CSV

\- Map findings to MITRE ATT\&CK techniques where possible



\## Security note



Never commit API keys. This project reads the key from the `VT\_API\_KEY` environment variable only.

