"""
IOC enrichment script
Reads a list of IPs, domains and file hashes, looks each one up on VirusTotal,
and writes a verdict table to a CSV file.

Usage:
    export VT_API_KEY="your_key_here"      (Windows PowerShell: $env:VT_API_KEY="your_key_here")
    python ioc_enrich.py iocs.txt results.csv
"""

import csv
import os
import re
import sys
import time

import requests

API_KEY = os.environ.get("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
DELAY_SECONDS = 16  # free tier allows 4 lookups per minute


def clean(ioc):
    """Un-defang IOCs, e.g. evil[.]com -> evil.com, hxxp -> http."""
    return ioc.strip().replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")


def ioc_type(ioc):
    """Work out whether the IOC is an IP, a hash or a domain."""
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        return "hash"
    return "domain"


def endpoint(ioc, kind):
    if kind == "ip":
        return f"{BASE_URL}/ip_addresses/{ioc}"
    if kind == "hash":
        return f"{BASE_URL}/files/{ioc}"
    return f"{BASE_URL}/domains/{ioc}"


def lookup(ioc, kind):
    """Ask VirusTotal about one IOC. Returns a dict of detection counts."""
    response = requests.get(
        endpoint(ioc, kind), headers={"x-apikey": API_KEY}, timeout=30
    )

    if response.status_code == 404:
        return {"verdict": "NOT FOUND"}
    if response.status_code == 429:
        print("  Rate limit hit, waiting 60 seconds...")
        time.sleep(60)
        return lookup(ioc, kind)
    response.raise_for_status()

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 3:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "verdict": verdict,
    }


def main():
    if not API_KEY:
        sys.exit("Set the VT_API_KEY environment variable first.")
    if len(sys.argv) != 3:
        sys.exit("Usage: python ioc_enrich.py <input_file> <output_csv>")

    input_file, output_file = sys.argv[1], sys.argv[2]

    with open(input_file) as f:
        iocs = [clean(line) for line in f if line.strip() and not line.startswith("#")]

    columns = ["ioc", "type", "malicious", "suspicious", "harmless", "undetected", "verdict"]
    rows = []

    for i, ioc in enumerate(iocs, start=1):
        kind = ioc_type(ioc)
        print(f"[{i}/{len(iocs)}] {ioc} ({kind})")
        try:
            result = lookup(ioc, kind)
        except requests.RequestException as error:
            result = {"verdict": f"ERROR: {error}"}
        rows.append({"ioc": ioc, "type": kind, **result})
        if i < len(iocs):
            time.sleep(DELAY_SECONDS)

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDone. Results saved to {output_file}")
    for row in rows:
        print(f"{row['ioc']:<70} {row['verdict']}")


if __name__ == "__main__":
    main()
