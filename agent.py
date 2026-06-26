import os
import requests
from dotenv import load_dotenv
from anthropic import Anthropic

load_dotenv()
client = Anthropic()


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
]

# --- ask the model something that should make it want the tool ---
# --- start the conversation ---
messages = [
    {"role": "user", "content": "Is this hash dangerous? 1111111111111111111111111111111111111111111111111111111111111111"}
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
            else:
                result = "Unknown tool."
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result,
            })

    # Hand the results back to the model and loop again.
    messages.append({"role": "user", "content": tool_results})