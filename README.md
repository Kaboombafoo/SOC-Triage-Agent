# SOC Triage Agent

An AI agent for first-pass security indicator triage. Give it a URL, an IP, or a
file hash and it picks the right tool, enriches or checks the indicator against
live threat-intelligence APIs, and explains the result in plain language.

I built this from scratch to understand how AI agents actually work — the tool-use
loop is hand-written, with no agent framework. Every part is something I can
explain line by line.

## What it does

- **Defang** — neutralizes URLs and IPs so they can't be accidentally clicked
  (`http://evil.com` → `hxxp://evil[.]com`).
- **IOC extraction** — pulls every IP, domain, and file hash out of raw text
  (an email, an alert) so the whole message can be triaged at once.
- **IP lookup** — returns an IP's owner, network (ASN), and country, using live
  data from the IPinfo Lite API.
- **Hash lookup** — checks a file hash against VirusTotal's 70+ antivirus engines
  and returns a malicious / suspicious / benign verdict.
- **Verdict logging** — writes each lookup to a timestamped audit trail.

The model decides which tool a request needs, runs it through the loop, and folds
the result into its answer.

## How it works

The core is a hand-written loop:

1. Send the conversation to the model (Claude Haiku) with the list of available tools.
2. If the model asks to use a tool, run that tool and hand the result back.
3. Repeat until the model stops asking for tools and gives a final answer.

The model never runs code itself — it *requests* a tool, and the Python code
decides whether and how to run it.

## A deliberate design choice: verdicts live in code

The malicious / suspicious / benign verdict is decided by a fixed rule in the
code (e.g. 3+ engine detections → malicious), **not** by the model. The model
explains the verdict; it doesn't make it.

This keeps the security decision deterministic and auditable: the same indicator
always produces the same verdict, and "why was this flagged?" has a concrete
answer (the detection count and threshold) rather than depending on model
judgment. The pattern is: **deterministic decisions in code, explanation in the
model.**

## Tools

| Tool        | Indicator      | Source of truth        | Output            |
|-------------|----------------|------------------------|-------------------|
| `defang`    | URL / IP       | Local Python           | Defanged string   |
| `ip_lookup` | IP address     | IPinfo Lite (live)     | Owner, ASN, country |
| `hash_lookup` | File hash    | VirusTotal v3 (live)   | Detection ratio + verdict |

## Verifying it works

Tested against the **EICAR test file** — a harmless string that every antivirus
vendor flags by convention, designed for safely testing detection pipelines. Its
hash returns ~60/75 engines flagging it malicious, and the agent correctly
returns a **MALICIOUS** verdict.

Failure paths are tested too: an unknown hash returns a clean "not found in
VirusTotal — no verdict possible" rather than guessing, and the agent correctly
notes that *unknown does not mean safe*.

## Honest limitations

- `ip_lookup` provides enrichment (ownership, geography), not a threat verdict.
- A "not found" result from VirusTotal means an indicator hasn't been scanned —
  not that it's safe.
- The agent's answers mix verified tool data with the model's own knowledge; tool
  data should be trusted over volunteered model knowledge.

## Roadmap

## Roadmap

- Extend `hash_lookup`'s pattern to URL and domain reputation checks.
- Structured (JSON-lines) logging so the audit trail is machine-parsable.

## Running it

Requires Python 3.11+ and free API keys for Anthropic, IPinfo, and VirusTotal.

\`\`\`bash
python -m venv .venv
source .venv/bin/activate
pip install anthropic python-dotenv requests
\`\`\`

Create a `.env` file (never committed):

\`\`\`
ANTHROPIC_API_KEY=your-anthropic-key
IPINFO_TOKEN=your-ipinfo-token
VT_API_KEY=your-virustotal-key
\`\`\`

Then run:

\`\`\`bash
python agent.py
\`\`\`

## Built with

Python · Anthropic API (Claude Haiku) · IPinfo Lite · VirusTotal API v3 · `requests`

IP data provided by [IPinfo](https://ipinfo.io).