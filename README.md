# SOC Triage Agent

A small AI agent for first-pass security indicator triage. Give it a URL or an
IP address and it uses tools to act on it — defanging risky indicators and
looking up who owns an IP — then explains the result in plain language.

I built this to understand how AI agents actually work from the ground up,
rather than leaning on a framework. The agent loop is hand-written and something
I can explain line by line.

## What it does

- **Defangs** URLs and IPs so they can't be accidentally clicked
  (`http://evil.com` → `hxxp://evil[.]com`).
- **Looks up an IP's owner, network, and country** using live data from the
  IPinfo Lite API.
- Decides on its own which tool a request needs, runs it, and folds the result
  into its answer.

## How it works

The core is a simple loop:

1. Send the conversation to the model (Claude Haiku) along with the list of
   available tools.
2. If the model asks to use a tool, run that tool and hand the result back.
3. Repeat until the model stops asking for tools and gives a final answer.

The model never runs code itself — it *requests* a tool, and the Python code
decides whether and how to run it. That separation is the heart of how agents
work.

## Tools

| Tool        | What it does                          | Source of truth      |
|-------------|---------------------------------------|----------------------|
| `defang`    | Neutralizes URLs/IPs                   | Local Python         |
| `ip_lookup` | IP owner, network (ASN), and country  | IPinfo Lite API (live) |

## Honest limitations

- `ip_lookup` provides **enrichment** (who owns an IP, where it's registered) —
  it is **not** a threat verdict. It won't tell you an IP is malicious. A real
  malicious/benign check is the next addition (see Roadmap).
- The agent's answers can mix **tool facts** (verified, live) with the **model's
  own knowledge** (not verified by any tool). Tool data should be trusted over
  volunteered model knowledge.
- This is a learning project, intentionally small.

## Roadmap

- Add a VirusTotal tool for real reputation/verdict checks across many engines.
- Add IOC extraction from pasted text.
- Combine signals into a single routed verdict.

## Running it

Requires Python 3.11+ and free API keys for Anthropic and IPinfo.

\`\`\`bash
python -m venv .venv
source .venv/bin/activate
pip install anthropic python-dotenv requests
\`\`\`

Create a `.env` file (never committed):

\`\`\`
ANTHROPIC_API_KEY=your-anthropic-key
IPINFO_TOKEN=your-ipinfo-token
\`\`\`

Then run:

\`\`\`bash
python agent.py
\`\`\`

## Built with

Python · Anthropic API (Claude Haiku) · IPinfo Lite · `requests`

IP data provided by [IPinfo](https://ipinfo.io).