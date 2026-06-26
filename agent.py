import os
import re
import requests
from dotenv import load_dotenv
from anthropic import Anthropic
from datetime import datetime

load_dotenv()
client = Anthropic()

def log_verdict(indicator: str, result: str) -> None:
    """Append a timestamped record of a lookup to triage_log.txt."""
    timestamp = datetime.now().isoformat(timespec="seconds")
    line = f"{timestamp} | {indicator} | {result}\n"
    with open("triage_log.txt", "a") as f:
        f.write(line)

def defang(indicator: str) -> str:
    """Neutralize a URL or IP so it can't be accidentally clicked."""
    return indicator.replace("http", "hxxp").replace(".", "[.]")

def ip_lookup(ip: str) -> str:
    """Look up who owns an IP address and what country it's in (IPinfo Lite)."""
    token = os.getenv("IPINFO_TOKEN")
    try:
        resp = requests.get(
            f"https://api.ipinfo.io/lite/{ip}",
            params={"token": token},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return f"Lookup failed for {ip}: {e}"

    return (
        f"IP {data.get('ip', ip)} is in {data.get('country', 'unknown')} "
        f"({data.get('country_code', '?')}), on network "
        f"{data.get('asn', '?')} {data.get('as_name', '')} "
        f"(domain: {data.get('as_domain', '?')})."
    )

def hash_lookup(file_hash: str) -> str:
    """Check a file hash against VirusTotal's antivirus engines for a verdict."""
    api_key = os.getenv("VT_API_KEY")
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
    except requests.RequestException as e:
        return f"VirusTotal lookup failed for {file_hash}: {e}"

    if resp.status_code == 404:
        return f"Hash {file_hash} was not found in VirusTotal (never scanned). No verdict possible."
    if resp.status_code != 200:
        return f"VirusTotal returned HTTP {resp.status_code} for {file_hash}."

    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    # The verdict rule lives HERE, in code — deterministic and auditable.
    if malicious >= 3:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY BENIGN"

    return (
        f"Hash {file_hash}: {malicious} of {total} engines flagged it malicious, "
        f"{suspicious} suspicious. Verdict: {verdict}."
    )
def extract_iocs(text: str) -> str:
    """Pull IP addresses, domains, and file hashes out of a block of text."""
    # Each pattern below describes the SHAPE of one kind of indicator.
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

    ips = re.findall(ip_pattern, text)
    hashes = re.findall(hash_pattern, text)
    domains = re.findall(domain_pattern, text)

    # A hash can look domain-ish to the loose patterns; keep results clean.
    domains = [d for d in domains if d not in ips]

    lines = []
    if ips:
        lines.append("IPs: " + ", ".join(sorted(set(ips))))
    if hashes:
        lines.append("Hashes: " + ", ".join(sorted(set(hashes))))
    if domains:
        lines.append("Domains: " + ", ".join(sorted(set(domains))))

    return "\n".join(lines) if lines else "No indicators found in the text."

# --- describe our tool to the model
tools = [
    {
        "name": "defang",
        "description": "Neutralize a URL or IP address so it cannot be accidentally clicked. Use this whenever the user gives you a URL or IP indicator.",
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "The URL or IP address to defang",
                }
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "ip_lookup",
        "description": "Look up ownership and country of an IP address. Use this when the user wants to know who owns an IP, what network it's on, or where it's located.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IP address to look up",
                }
            },
            "required": ["ip"],
        },
    },
    {
        "name": "hash_lookup",
        "description": "Check a file hash (MD5, SHA-1, or SHA-256) against VirusTotal's antivirus engines to get a malicious/benign verdict. Use this when the user gives you a file hash.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_hash": {
                    "type": "string",
                    "description": "The file hash to check",
                }
            },
            "required": ["file_hash"],
        },
    },
    {
        "name": "extract_iocs",
        "description": "Extract all IP addresses, domains, and file hashes from a block of text such as an email or alert. Use this when the user pastes raw text and wants the indicators pulled out.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The raw text to extract indicators from",
                }
            },
            "required": ["text"],
        },
    },
]

# --- ask the model something that should make it want the tool ---
# --- start the conversation ---
messages = [
    {"role": "user", "content": "Pull the indicators out of this email and tell me which to check: 'Hi, please verify your account at http://secure-login.evil-malware.com. Our server 192.168.44.7 logged your access. Attached invoice hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'"}
]

# --- the agent loop ---
while True:
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=500,
        tools=tools,
        messages=messages,
    )

    # If the model is NOT asking for a tool, it's done. Print and stop.
    if response.stop_reason != "tool_use":
        print(response.content[0].text)
        break

    # The model wants a tool. Save its request into the conversation.
    messages.append({"role": "assistant", "content": response.content})

    # Run each tool the model asked for, and collect the results.
    tool_results = []
    for block in response.content:
        if block.type == "tool_use":
            if block.name == "defang":
                result = defang(block.input["indicator"])
            elif block.name == "ip_lookup":
                result = ip_lookup(block.input["ip"])
            elif block.name == "hash_lookup":
                result = hash_lookup(block.input["file_hash"])
            elif block.name == "extract_iocs":
                result = extract_iocs(block.input["text"])
            else:
                result = "Unknown tool."
            log_verdict(block.name, result)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result,
            })

    # Hand the results back to the model and loop again.
    messages.append({"role": "user", "content": tool_results})