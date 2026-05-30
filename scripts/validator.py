import json
import os
import time
import random
import requests
import re
import urllib3

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INPUT_FILE = os.getenv("INPUT_FILE", "all_discovered_vulnerabilities.jsonl")
OUTPUT_FILE = "validated_bounty_leads.txt"

# Enhanced Regex Patterns for Sensitive Data
REGEX_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Webhook": r"https://hooks.slack.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Generic Secret": r"(?i)(key|secret|password|auth|token|access)[-|_]*[=|\:][-|_]*['|\"]?([A-Za-z0-9]{12,})['|\"]?"
}

SECRET_KEYWORDS = ["aws_secret", "db_password", "database_url", "private_key", "S3_BUCKET", "connectionstring"]

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
}

if not os.path.exists(INPUT_FILE) or os.path.getsize(INPUT_FILE) == 0:
    print(f"[-] Input file '{INPUT_FILE}' not found or empty. No leads to validate.")
    with open(OUTPUT_FILE, "w") as f:
        f.write("No validated leads found during this run.")
    exit(0)

print("[+] Python Browser Validation Engine Active. Verifying leads...")
validated_count = 0

with open(INPUT_FILE, "r") as infile, open(OUTPUT_FILE, "w") as outfile:
    for line in infile:
        if not line.strip():
            continue
        try:
            data = json.loads(line.strip())
            target_url = data.get("matched-at") or data.get("host")
            vuln_id = data.get("template-id")
            severity = data.get("info", {}).get("severity", "unknown")

            if not target_url:
                continue

            if not target_url.startswith(("http://", "https://")):
                target_url = f"https://{target_url}"

            print(f"[*] Verifying: {target_url} ({vuln_id})")
            try:
                res = requests.get(target_url, timeout=8, verify=False, headers=BROWSER_HEADERS, allow_redirects=True)
                response_body = res.text

                is_valid = False
                evidence = []

                # Check Regex Patterns
                for name, pattern in REGEX_PATTERNS.items():
                    matches = re.findall(pattern, response_body)
                    if matches:
                        is_valid = True
                        evidence.append(f"Matched {name}")

                # Check Keywords
                for kw in SECRET_KEYWORDS:
                    if kw.lower() in response_body.lower():
                        is_valid = True
                        evidence.append(f"Found keyword '{kw}'")

                # Fallback to status code for high severity
                if not is_valid and severity in ["high", "critical"] and res.status_code == 200:
                    is_valid = True
                    evidence.append(f"Accessible target (Status 200)")

                if is_valid:
                    validated_count += 1
                    evidence_str = "; ".join(evidence)
                    log_entry = f"=== VALIDATED BOUNTY LEAD #{validated_count} ===\n" \
                                f"Target: {target_url}\n" \
                                f"Vulnerability ID: {vuln_id}\n" \
                                f"Severity: {severity}\n" \
                                f"Evidence: {evidence_str}\n" \
                                f"========================================\n\n"
                    outfile.write(log_entry)
                    print(f"[+] SUCCESS: Verified {target_url}")

            except Exception:
                pass

        except Exception as err:
            print(f"[-] Error: {err}")

print(f"[+] Validation complete. {validated_count} leads preserved.")
