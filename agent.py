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
]

# --- ask the model something that should make it want the tool ---
# --- start the conversation ---
messages = [
    {"role": "user", "content": "Look up the IP 8.8.8.8 and tell me who owns it and what country it's in."}
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
            else:
                result = "Unknown tool."
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result,
            })

    # Hand the results back to the model and loop again.
    messages.append({"role": "user", "content": tool_results})