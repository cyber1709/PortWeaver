#!/usr/bin/env python3
"""
PortWeaver — Pipeline Nmap + local LLM (Ollama) — unified per-host reports (facts + explanation)

Highlights
- Fully chained pipeline: discovery → quick → deep → post-deep service enumerations → facts → LLM reports
- Final report includes EVERYTHING: org-level LLM summary + per-host Facts (verbatim) + per-host LLM report + enum highlights
- The LLM also receives facts + per-host reports + enum highlights as context for the org-level summary
- Clean terminal previews (colorized) without dumping raw Nmap output
- Model selection shows only locally available Ollama models (numbered menu)
- Compare multiple models in one run (reports per model + final org report per model)

Usage examples
- Single model (interactive selection):
  sudo python scanner.py --mode external --target 103.10.24.0/23 --org "Acme"

- Preselect models (comma-separated), skipping the menu:
  sudo python scanner.py --mode external --target 103.10.24.0/23 --org "Acme" \
       --models llama3.1,qwen2.5:7b-instruct --with-vuln

Requirements
- brew install nmap ollama
- ollama pull llama3.1
- pip install ollama
"""

import argparse
import ipaddress
import json
import re
import shlex
import subprocess
import sys
import textwrap
import shutil
from datetime import datetime
from pathlib import Path

# ============================== Colors & UI ==================================

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"
    MAGENTA = "\033[35m"; CYAN = "\033[36m"; WHITE = "\033[37m"
    BRED = "\033[91m"; BGREEN = "\033[92m"; BYELLOW = "\033[93m"; BBLUE = "\033[94m"
    BMAGENTA = "\033[95m"; BCYAN = "\033[96m"; BWHITE = "\033[97m"

def color(text, *styles): return "".join(styles) + str(text) + C.RESET
def hr(char="─", width=78): return char * width
def banner(title, fg=C.BWHITE):
    print()
    print(color("┌" + hr("─") + "┐", fg))
    line = f" {title} "
    pad = 78 - len(line)
    print(color("│", fg) + color(line + (" " * max(0, pad)), C.BOLD) + color("│", fg))
    print(color("└" + hr("─") + "┘", fg))
    print()

def status(label, msg, fg=C.CYAN): print(color(f"[{label}] ", fg, C.BOLD) + color(msg, C.WHITE))
def good(msg): status("OK", msg, fg=C.BGREEN)
def info(msg): status("INFO", msg, fg=C.BCYAN)
def warn(msg): status("WARN", msg, fg=C.BYELLOW)
def bad(msg):  status("ERR", msg, fg=C.BRED)
def print_box(title, body, fg=C.BWHITE):
    banner(title, fg)
    print(textwrap.dedent(body).strip() + "\n")

# -------- Intro panel (no ASCII art) --------
VERSION = "1.4.0"

def show_intro():
    top = color("┏" + hr("━") + "┓", C.BWHITE)
    mid = color("┃", C.BWHITE)
    bot = color("┗" + hr("━") + "┛", C.BWHITE)

    lines = [
        top,
        f"{mid} {color('PortWeaver', C.BWHITE, C.BOLD)}  {color(f'v{VERSION}', C.BCYAN)}",
        f"{mid} {color('Unified Nmap + LLM reporting', C.BWHITE)}",
        f"{mid} {color('• Clear terminal previews  • Per-host Markdown  • Novice-friendly analysis', C.BWHITE)}",
        f"{mid} {color('What happens:', C.BCYAN, C.BOLD)}",
        f"{mid} {color('  • Discover → Quick → Deep → Post-deep service enumerations', C.BWHITE)}",
        f"{mid} {color('  • Parse facts (ports, services, TLS, headers, SSH/SMB/RDP/DB/etc., CVEs, banners)', C.BWHITE)}",
        f"{mid} {color('  • Generate concise reports (facts + explanation + actions)', C.BWHITE)}",
        f"{mid} {color('Heads-up:', C.BYELLOW, C.BOLD)}",
        f"{mid} {color('  • Run only where you have permission. Some NSE scripts can be intrusive.', C.BWHITE)}",
        f"{mid} {color('Tip:', C.BGREEN, C.BOLD)}",
        f"{mid} {color('  • Pull at least one model, e.g., `ollama pull llama3.1`.', C.BWHITE)}",
        bot,
        ""
    ]
    print("\n".join(lines))

# ============================== Core Helpers =================================

def run(cmd, check=True, capture=True):
    """Run a shell command. If capture=False, stream live to terminal (we avoid it to keep output clean)."""
    cmd_list = shlex.split(cmd) if isinstance(cmd, str) else cmd
    if not capture:
        proc = subprocess.Popen(cmd_list)
        rc = proc.wait()
        if check and rc != 0:
            raise RuntimeError(f"Command failed ({rc}): {' '.join(cmd_list)}")
        return rc, "", ""
    else:
        proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check and proc.returncode != 0:
            raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd_list)}\nSTDERR:\n{proc.stderr}")
        return proc.returncode, (proc.stdout or ""), (proc.stderr or "")

def detect_cidr_mac():
    """Mac-oriented best-effort to get /24 from en0/en1."""
    for iface in ("en0", "en1"):
        try:
            _, out, _ = run(["ipconfig", "getifaddr", iface], check=False)
            ip = out.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return {"iface": iface, "ip": ip, "cidr": ".".join(ip.split(".")[:3]) + ".0/24"}
        except Exception:
            pass
    return None

def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True); return p
def write_list(path: Path, items): path.write_text("\n".join(items) + ("\n" if items else ""))

def parse_live_hosts_from_gnmap(gnmap_text: str):
    """Parse -oG discovery output for hosts marked 'Status: Up'."""
    hosts = []
    for line in gnmap_text.splitlines():
        m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m and "Status: Up" in line:
            hosts.append(m.group(1))
    return sorted(set(hosts))

def sanitize_token(s: str) -> str:
    s = (s or "").strip().replace("/", "_")
    s = re.sub(r"[^0-9A-Za-z._-]+", "-", s).strip("-_")
    return s or "unknown"

def unique_dir(base: Path) -> Path:
    if not base.exists(): return base
    i = 1
    while True:
        candidate = Path(str(base) + f"-{i}")
        if not candidate.exists(): return candidate
        i += 1

# ============================== Quick parsing helpers =========================

OPEN_LINE_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open[^\s]*\s+([^\s]+)(?:\s+(.*))?$", re.I)

def parse_quick_open_ports(quick_text: str):
    """Return dict: host -> list of (port, proto, service, version_str)."""
    mapping = {}
    current_host = None
    for raw in quick_text.splitlines():
        line = raw.strip()
        if line.startswith("Nmap scan report for "):
            current_host = line.split("Nmap scan report for ", 1)[1].strip()
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)$", current_host)
            if m: current_host = m.group(1)
            mapping.setdefault(current_host, [])
            continue
        m = OPEN_LINE_RE.match(line)
        if m and current_host:
            port = int(m.group(1)); proto = m.group(2).lower()
            service = (m.group(3) or "").lower()
            version = (m.group(4) or "").strip()
            mapping[current_host].append((port, proto, service, version))
    return mapping

def is_web_port(port:int, service:str) -> bool:
    if "http" in (service or ""): return True
    return port in {80,81,82,443,8000,8080,8443,8888,3000,5000,5601,7001,7002,9000,9200,9443}

# ============================== Ollama helpers ================================

def list_ollama_models() -> list:
    """Return list of model names available locally in Ollama."""
    try:
        rc, out, _ = run(["ollama", "list", "--format", "json"], check=False)
        if rc == 0 and out.strip():
            data = json.loads(out)
            names = [item.get("name") for item in data if item.get("name")]
            return sorted(set(names))
    except Exception:
        pass

    try:
        rc, out, _ = run(["ollama", "list"], check=False)
        if rc == 0:
            names = []
            for line in out.splitlines():
                cols = line.split()
                if cols and (":" in cols[0] or not cols[0].lower().startswith("name")):
                    names.append(cols[0])
            return sorted(set(names))
    except Exception:
        pass
    return []

def pick_models_interactively(preselected: list[str] | None) -> list[str]:
    if preselected:
        return preselected

    available = list_ollama_models()
    if not available:
        warn("No local Ollama models found. Example: `ollama pull llama3.1`")
        m = input(color("Enter a model to use (e.g., llama3.1): ", C.BCYAN)).strip()
        return [m] if m else []

    print_box("MODEL SELECTION", "Select the model(s) to generate reports.\n(Enter comma-separated numbers, or press Enter for the default [1])")
    for i, name in enumerate(available, 1):
        print(color(f"  {i}) {name}", C.BWHITE))
    print()
    choice = input(color("Your choice [1]: ", C.BCYAN)).strip()
    if not choice:
        return [available[0]]
    idxs = []
    for chunk in choice.split(","):
        chunk = chunk.strip()
        if not chunk: continue
        if chunk.isdigit():
            n = int(chunk)
            if 1 <= n <= len(available):
                idxs.append(n-1)
    if not idxs:
        return [available[0]]
    return [available[i] for i in idxs]

# ============================== LLM (Ollama) =================================

MAX_CHARS = 60000
def trim_text(s: str, limit: int = MAX_CHARS) -> str:
    if len(s) <= limit: return s
    head = "…[TRIMMED OUTPUT; SHOWING LAST PART]…\n"
    return head + s[-limit:]

PER_HOST_SYSTEM = """You are a cautious security analyst.
You will receive a FACTS block for ONE host (merged from quick scan, deep scan, and service enumerations).
Create a UNIFIED HOST REPORT that already contains the factual details and a concise explanation
SUITABLE FOR A NOVICE (simple language, minimal jargon). Keep it accurate and actionable.

Strict rules:
- COPY FACTS VERBATIM into the 'Facts Digest' tables/lists (do NOT invent or reword values).
- Only add short, crisp interpretations under 'Analysis & Risk' and 'Priority Actions'.
- Add high-confidence CVEs only if explicitly present in the facts or clearly implied by product+version;
  otherwise list 'Candidate CVEs to verify' (product+version search terms).
- Keep it concise and easy to read.

Sections to output (exact order):
1) Host Overview (one-line role guess if obvious)
2) Facts Digest
   2.1) Open Ports / Services / Versions (table)
   2.2) OS / CPE Evidence (bullets)
   2.3) Web Evidence (server/title/methods/robots/vhosts and any HTTP headers lines)
   2.4) TLS / Certificate Evidence (protocols, subject/issuer/validity/keybits/sig alg)
   2.5) SSH Evidence (algorithms, hostkeys)
   2.6) Explicit CVEs from Scan (bullets with exact IDs)
   2.7) Banners (bullets)
   2.8) Other Service Evidence (SMB/RDP/FTP/SMTP/DNS/DBs/Redis/Mongo/etc. — selected lines)
3) Analysis & Risk (3–6 bullets, in simple language)
4) Candidate CVEs to Verify (product+version search terms, only if needed)
5) Priority Actions (top 3–6, ordered)

Never paste the raw deep scan; the facts you copy must come ONLY from the FACTS block provided."""

FINAL_SYSTEM = """You are a security lead. You will receive, for each host:
- Merged FACTS (authoritative, to be copied if you need verbatim details)
- Enum Highlights (additional notable lines from service enumerations)
- The per-host MODEL REPORT (LLM explanation)

Produce a COMPLETE org-level report suitable for novices:
A) Executive Summary (themes & biggest risks)
B) Factual Rollup (counts of exposed services/versions, common TLS/HTTP/SSH/SMB issues)
C) Priority Remediations (ordered, actionable)
D) Notable Hosts to Triage First (3–10 with one-line reason)

THEN include a PER-HOST APPENDIX. For each host, add:
- Host header
- Facts Digest (copy verbatim from FACTS; keep tables and bullet lists)
- Model Report (verbatim)
- Enum Highlights (only concise highlights; do not dump repetitive noise)

Keep language simple and avoid speculation. If unsure, say 'verify'. Avoid exploit guidance."""

def safe_chat(model: str, messages: list[dict], options: dict, fallback_tokens: int = 700):
    from ollama import chat
    try:
        return chat(model=model, messages=messages, options=options)
    except Exception:
        options2 = dict(options)
        options2["num_predict"] = min(options.get("num_predict", fallback_tokens), fallback_tokens)
        options2["num_ctx"] = min(options.get("num_ctx", 8192), 8192)
        return chat(model=model, messages=messages, options=options2)

def llm_unified_host_report(model: str, host: str, facts_md: str) -> str:
    text = f"HOST: {host}\n\n=== FACTS (use this to copy into your Facts Digest) ===\n{trim_text(facts_md, 15000)}"
    resp = safe_chat(
        model=model,
        messages=[
            {"role": "system", "content": PER_HOST_SYSTEM},
            {"role": "user", "content": text},
        ],
        options={"temperature": 0.15, "top_p": 0.9, "repeat_penalty": 1.05, "num_ctx": 16384, "num_predict": 1100}
    )
    return (resp.get("message", {}).get("content") or "").strip()

def llm_final_report(model: str,
                     host_reports: list[tuple[str, str]],
                     host_facts_map: dict[str,str],
                     host_enum_highlights: dict[str,str],
                     org: str, target_label: str) -> str:
    """
    Give the LLM EVERYTHING it needs:
      - per-host unified LLM report
      - per-host facts (verbatim)
      - per-host enumeration highlights (trimmed)
    Ask it to create an org-level summary + per-host appendix.
    """
    # Build a compact-but-complete pack
    packs = []
    total = 0
    for host, report_md in host_reports:
        facts = host_facts_map.get(host, "")
        enums = host_enum_highlights.get(host, "")
        # Reasonable per-host caps to avoid blowing context on huge subnets
        report_snip = trim_text(report_md, 9000)
        facts_snip  = trim_text(facts, 9000)
        enums_snip  = trim_text(enums, 4000)
        part = f"### HOST: {host}\n\n==== FACTS ====\n{facts_snip}\n\n==== ENUM HIGHLIGHTS ====\n{enums_snip}\n\n==== MODEL REPORT ====\n{report_snip}\n"
        packs.append(part)
        total += len(part)
        if total > 140000:  # hard stop for gigantic scopes
            packs.append("…[TRUNCATED ADDITIONAL HOSTS IN CONTEXT TO FIT LIMITS]…\n")
            break

    header = f"Organization: {org}\nTarget: {target_label}\n\nBelow is the per-host material."
    resp = safe_chat(
        model=model,
        messages=[
            {"role": "system", "content": FINAL_SYSTEM},
            {"role": "user", "content": header + "\n\n" + "\n".join(packs)}
        ],
        options={"temperature": 0.12, "top_p": 0.9, "repeat_penalty": 1.05, "num_ctx": 16384, "num_predict": 1600}
    )
    return (resp.get("message", {}).get("content") or "").strip()

# ============================== FACT extraction ===============================

PORT_LINE      = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open[^\s]*\s+([^\s]+)(?:\s+(.*))?$", re.I)
OS_DETAILS     = re.compile(r"^(OS details:|Running:|Aggressive OS guesses:|OS CPE:)\s*(.*)$", re.I)

HTTP_TITLE     = re.compile(r"^\|_?\s*http-title:\s*(.*)$", re.I)
HTTP_SERVER    = re.compile(r"^\|_?\s*http-server-header:\s*(.*)$", re.I)
HTTP_METHODS   = re.compile(r"^\|_?\s*http-methods:\s*(.*)$", re.I)
HTTP_ROBOTS    = re.compile(r"^\|_?\s*http-robots\.txt:\s*(.*)$", re.I)
HTTP_VHOSTS    = re.compile(r"^\|_?\s*http-vhosts:\s*(.*)$", re.I)
HTTP_HDR_RAW   = re.compile(r"^\|_?\s+([A-Za-z0-9\-]{2,}):\s*(.*)$", re.I)

SSL_CERT_PROP  = re.compile(r"^\|_?\s*(Subject:|Issuer:|Public Key type:|Public Key bits:|Signature Algorithm:|Not valid (?:before|after).*)$", re.I)
SSL_VER        = re.compile(r"^\|_?\s*(TLSv[0-9\.]+|SSLv[0-9])\s*:", re.I)

SSH_ALGOS      = re.compile(r"^\|_?\s*ssh2-enum-algos:\s*(.*)$", re.I)
SSH_HOSTKEY    = re.compile(r"^\|_?\s*ssh-hostkey:\s*(.*)$", re.I)

BANNER_LINE    = re.compile(r"^\|_?\s*banner:\s*(.*)$", re.I)
VULN_LINE      = re.compile(r"^\|_?\s*(?:vulners|vuln|cves?):\s*(.*)$", re.I)
STATE_VULN     = re.compile(r"State:\s*VULNERABLE", re.I)
CVE_RE         = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def extract_facts_for_host(host: str, quick_snip: str, enum_snip: str, deep_text: str) -> str:
    """Return a markdown FACTS block for the host (deterministic, no LLM)."""
    ports = []
    os_lines = []
    http_titles, http_servers, http_methods, http_robots, http_vhosts = [], [], [], [], []
    http_raw_headers = []
    ssl_props, ssl_versions = [], []
    ssh_algos, ssh_keys, banners = [], [], []
    explicit_cves, vuln_evidence = set(), []

    # Parse deep scan lines
    for raw in deep_text.splitlines():
        line = raw.rstrip()
        m = PORT_LINE.match(line)
        if m:
            port, proto, service = m.group(1), m.group(2), m.group(3)
            version = (m.group(4) or "").strip()
            ports.append((port, proto, service, version))
            for cve in CVE_RE.findall(line): explicit_cves.add(cve.upper())
            continue

        if OS_DETAILS.match(line): os_lines.append(line); continue

        m = HTTP_TITLE.match(line)
        if m: http_titles.append(m.group(1).strip()); continue
        m = HTTP_SERVER.match(line)
        if m: http_servers.append(m.group(1).strip()); continue
        m = HTTP_METHODS.match(line)
        if m: http_methods.append(m.group(1).strip()); continue
        m = HTTP_ROBOTS.match(line)
        if m: http_robots.append(m.group(1).strip()); continue
        m = HTTP_VHOSTS.match(line)
        if m: http_vhosts.append(m.group(1).strip()); continue
        m = HTTP_HDR_RAW.match(line)
        if m: http_raw_headers.append(f"{m.group(1)}: {m.group(2)}"); continue

        if SSL_CERT_PROP.match(line): ssl_props.append(line.strip()); continue
        m = SSL_VER.match(line)
        if m: ssl_versions.append(m.group(1)); continue

        if SSH_ALGOS.match(line): ssh_algos.append(line.strip()); continue
        if SSH_HOSTKEY.match(line): ssh_keys.append(line.strip()); continue

        m = BANNER_LINE.match(line)
        if m: banners.append(m.group(1).strip()); continue

        if STATE_VULN.search(line) or VULN_LINE.match(line):
            vuln_evidence.append(line)
        for cve in CVE_RE.findall(line): explicit_cves.add(cve.upper())

    # Include ALL enumeration outputs
    other_evidence_lines = []
    for ln in enum_snip.splitlines():
        l = ln.strip()
        # Reuse existing parsers to enrich the key sections
        m = HTTP_HDR_RAW.match(l)
        if m: http_raw_headers.append(f"{m.group(1)}: {m.group(2)}")
        if SSL_CERT_PROP.match(l): ssl_props.append(l)
        m = SSL_VER.match(l)
        if m: ssl_versions.append(m.group(1))
        m = HTTP_TITLE.match(l)
        if m: http_titles.append(m.group(1).strip())
        m = HTTP_SERVER.match(l)
        if m: http_servers.append(m.group(1).strip())
        m = HTTP_METHODS.match(l)
        if m: http_methods.append(m.group(1).strip())
        m = HTTP_ROBOTS.match(l)
        if m: http_robots.append(m.group(1).strip())
        m = HTTP_VHOSTS.match(l)
        if m: http_vhosts.append(m.group(1).strip())
        if SSH_ALGOS.match(l): ssh_algos.append(l)
        if SSH_HOSTKEY.match(l): ssh_keys.append(l)
        for cve in CVE_RE.findall(l): explicit_cves.add(cve.upper())

        # Keep a trimmed list of other unparsed evidence lines for section "Other Service Evidence"
        if l.startswith("|") or l.lower().startswith((
            "smb-", "rdp-", "ftp", "smtp", "dns", "mysql", "pgsql", "redis", "mongodb",
            "memcached", "vnc", "rdp", "winrm", "docker", "kube", "elasticsearch", "jenkins"
        )):
            other_evidence_lines.append(l)

    # Build the FACTS markdown
    md = [f"# Host: {host}", ""]

    if ports:
        md.append("**Open Ports / Services / Versions:**")
        md.append("")
        md.append("| Port | Proto | Service | Version |")
        md.append("|-----:|:-----:|:--------|:--------|")
        for port, proto, svc, ver in ports[:300]:
            md.append(f"| {port} | {proto} | {svc} | {ver or ''} |")
        md.append("")

    if os_lines:
        md += ["**OS / CPE Evidence:**"] + [f"- {l}" for l in os_lines[:30]] + [""]

    if (http_servers or http_titles or http_methods or http_robots or http_vhosts or http_raw_headers):
        md.append("**Web Evidence:**")
        if http_servers:  md += [f"- Server: {s}" for s in sorted(set(http_servers))[:30]]
        if http_titles:   md += [f"- Title: {t}" for t in sorted(set(http_titles))[:30]]
        if http_methods:  md += [f"- Methods: {m}" for m in sorted(set(http_methods))[:30]]
        if http_robots:   md += [f"- Robots: {r}" for r in sorted(set(http_robots))[:30]]
        if http_vhosts:   md += [f"- VHosts: {v}" for v in sorted(set(http_vhosts))[:30]]
        if http_raw_headers:
            md.append("- HTTP Headers (sample):")
            for h in http_raw_headers[:30]:
                md.append(f"  - {h}")
        md.append("")

    if ssl_props or ssl_versions:
        md.append("**TLS / Certificate Evidence:**")
        if ssl_versions:
            md.append(f"- Protocols: {', '.join(sorted(set(ssl_versions)))}")
        for l in ssl_props[:30]:
            md.append(f"- {l}")
        md.append("")

    if ssh_algos or ssh_keys:
        md.append("**SSH Evidence:**")
        for l in ssh_algos[:20]: md.append(f"- {l}")
        for l in ssh_keys[:15]: md.append(f"- {l}")
        md.append("")

    if explicit_cves or vuln_evidence:
        md.append("**Explicit CVEs / Vulnerability Evidence:**")
        if explicit_cves:
            md.append(f"- CVEs: {', '.join(sorted(explicit_cves))}")
        for l in vuln_evidence[:30]:
            md.append(f"- {l}")
        md.append("")

    if banners:
        md.append("**Banners:**")
        md += [f"- {b}" for b in banners[:30]]
        md.append("")

    if other_evidence_lines:
        md.append("**Other Service Evidence:**")
        md += [f"- {l}" for l in other_evidence_lines[:60]]
        md.append("")

    if quick_snip:
        md += ["**Quick Scan Snippet (22/80/443):**", "```", quick_snip.strip(), "```", ""]

    return "\n".join(md).strip()

# ============================== Terminal previews =============================

def _collect_section(lines, start_idx):
    out = []
    i = start_idx + 1
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("**") and s.endswith("**:"):
            break
        if s.startswith("# "):
            break
        out.append(lines[i])
        i += 1
    return out

def render_report_preview(host: str, model: str, report_md: str, width: int = 92):
    title = f"{host} — {model}"
    print(color("┌" + "─" * width + "┐", C.BWHITE))
    line = f"  Report Preview: {title} "
    pad = max(0, width - len(line))
    print(color("│", C.BWHITE) + color(line + " " * pad, C.BWHITE, C.BOLD) + color("│", C.BWHITE))
    print(color("├" + "─" * width + "┤", C.BWHITE))

    lines = report_md.splitlines()
    header_indices = {}
    for idx, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("**") and s.endswith("**:"):
            key = s[2:-3].strip().lower()
            header_indices[key] = idx

    def add_block(title_key, emphasize=False, max_items=None):
        key = title_key.lower()
        if key not in header_indices:
            return
        start = header_indices[key]
        block = _collect_section(lines, start)
        print(color("│ ", C.BWHITE) + color(lines[start], C.BMAGENTA if emphasize else C.BWHITE, C.BOLD))
        if max_items is not None and len(block) > max_items:
            block = block[:max_items] + [color("… (truncated in preview)", C.BYELLOW)]
        for b in block:
            if b.startswith("| Port") or b.startswith("|-----"):
                print(color("│ ", C.BWHITE) + color(b, C.BGREEN)); continue
            if b.startswith("|"):
                print(color("│ ", C.BWHITE) + color(b, C.WHITE)); continue
            print(color("│ ", C.BWHITE) + b)

    add_block("Open Ports / Services / Versions", emphasize=True, max_items=18)
    add_block("Web Evidence", emphasize=True, max_items=24)
    add_block("TLS / Certificate Evidence", max_items=18)
    add_block("SSH Evidence", max_items=14)
    add_block("Explicit CVEs / Vulnerability Evidence", max_items=18)
    add_block("Other Service Evidence", max_items=24)

    def print_llm_section(name, max_lines=10):
        printed = False; count = 0
        for line in lines:
            if line.strip().lower().startswith(name.lower()):
                if not printed:
                    print(color("│ ", C.BWHITE) + color(line, C.BBLUE, C.BOLD))
                    printed = True
                continue
            if printed:
                if line.strip().startswith(("# ", "**")):
                    break
                print(color("│ ", C.BWHITE) + line)
                count += 1
                if count >= max_lines:
                    print(color("│ ", C.BWHITE) + color("… (truncated in preview)", C.BYELLOW))
                    break

    print_llm_section("3) Analysis & Risk", max_lines=8)
    print_llm_section("5) Priority Actions", max_lines=8)

    print(color("└" + "─" * width + "┘", C.BWHITE))
    print()

# ============================== Nmap Wrapper & Enum Profiles ==================

class NmapTools:
    def __init__(self, outdir: Path, with_vuln: bool, timing: str):
        self.outdir = outdir
        self.with_vuln = with_vuln
        self.timing = timing  # -T4 / -T5

    def discover_hosts(self, cidr: str):
        ensure_dir(self.outdir)
        p1 = self.outdir / "discover1.gnmap"
        p2 = self.outdir / "discover2.gnmap"

        banner(f"DISCOVERY: {cidr}")
        info("Unprivileged ping sweep…")
        run(["nmap","--unprivileged","-sn",cidr,"-oG",str(p1)], check=False, capture=True)
        text1 = p1.read_text(errors="ignore") if p1.exists() else ""
        live1 = parse_live_hosts_from_gnmap(text1)
        live_all = set(live1)

        if not live1:
            warn("No hosts via unprivileged sweep; trying privileged probes…")
            run(["sudo","nmap","-sn","-PE","-PP","-PS80,443","-PA80,443",
                 "--max-retries","1","--host-timeout","5s",cidr,"-oG",str(p2)], check=False, capture=True)
            text2 = p2.read_text(errors="ignore") if p2.exists() else ""
            live2 = parse_live_hosts_from_gnmap(text2)
            live_all.update(live2)

        live = sorted(live_all)
        write_list(self.outdir / "live.txt", live)
        if live: good(f"Live hosts discovered: {len(live)}")
        else:    warn("Discovery found 0 hosts (subsequent scans may still proceed with -Pn).")
        return live

    def quick_scan(self, live_hosts: list[str]):
        prefix = self.outdir / "quick-22-80-443"
        live_file = self.outdir / "live.txt"
        banner(f"QUICK SCAN: {len(live_hosts)} host(s), ports 22,80,443 (service & OS detect)")
        run(["sudo","nmap","-Pn","-n","-p22,80,443","-sV","-O",self.timing,"--reason",
             "-iL",str(live_file),"-oN",str(prefix)+".txt"], check=False, capture=True)
        txt_path = Path(str(prefix)+".txt")
        if txt_path.exists(): good(f"Quick scan saved: {txt_path}")
        return txt_path

    def deep_scan_per_host(self, hosts: list[str]):
        outdir_hosts = ensure_dir(self.outdir / "deep-hosts")
        index = {}
        deep_scripts = [
            "default","banner",
            "ssl-cert","ssl-enum-ciphers",
            "http-title","http-headers","http-methods","http-robots.txt","http-server-header","http-enum","http-vhosts"
        ]
        if self.with_vuln:
            deep_scripts.append("vuln")

        banner(f"DEEP SCAN: {len(hosts)} host(s) (full TCP, service/version/OS, +web/TLS scripts)")
        for i, host in enumerate(hosts, 1):
            txt_path = outdir_hosts / f"{host.replace(':','_').replace('/','_')}.txt"
            info(f"[{i}/{len(hosts)}] Deep scanning {host} …")
            run(["sudo","nmap","-Pn","-n",
                 "-p-","-sS","-sV","--version-all","--version-intensity","9",
                 "-O","-A",self.timing,
                 "--script", ",".join(deep_scripts),
                 "-oN",str(txt_path), host], check=False, capture=True)
            if txt_path.exists():
                good(f"Deep scan saved: {txt_path}")
                index[host] = {"txt": str(txt_path)}
            else:
                warn(f"No deep output for {host}")
        return outdir_hosts, index

# ----- Post-deep "enumerate everything" profiles (safe-ish info scripts) -----

ENUM_PROFILES = [
    ("web",      is_web_port, ["http-headers","http-methods","http-title","http-robots.txt","http-server-header","http-enum","http-vhosts","ssl-cert","ssl-enum-ciphers"]),
    ("ssh",      lambda p,s: p==22, ["ssh2-enum-algos","ssh-hostkey","banner"]),
    ("smb",      lambda p,s: p in (139,445), ["smb-os-discovery","smb-protocols","smb2-security-mode","smb-enum-shares","smb-enum-users"]),
    ("rdp",      lambda p,s: p==3389, ["rdp-enum-encryption","rdp-ntlm-info"]),
    ("ftp",      lambda p,s: p==21, ["ftp-anon","ftp-syst","banner"]),
    ("smtp",     lambda p,s: p in (25,465,587), ["smtp-commands","smtp-enum-users","banner"]),
    ("pop3",     lambda p,s: p in (110,995), ["pop3-capabilities","banner"]),
    ("imap",     lambda p,s: p in (143,993), ["imap-capabilities","banner"]),
    ("dns",      lambda p,s: p==53, ["dns-nsid","dns-recursion"]),
    ("mysql",    lambda p,s: p==3306, ["mysql-info"]),
    ("postgres", lambda p,s: p==5432, ["pgsql-version"]),
    ("redis",    lambda p,s: p==6379, ["redis-info"]),
    ("mongodb",  lambda p,s: p==27017, ["mongodb-info"]),
    ("memcached",lambda p,s: p==11211, ["memcached-info"]),
    ("vnc",      lambda p,s: 5900<=p<=5905, ["vnc-info"]),
    ("winrm",    lambda p,s: p in (5985,5986), ["http-headers","http-title","http-methods","ssl-cert"]),
    ("docker",   lambda p,s: p in (2375,2376), ["banner","http-headers","http-title","ssl-cert"]),
    ("kubelet",  lambda p,s: p==10250, ["http-headers","http-title","http-methods"]),
    ("elastic",  lambda p,s: p in (9200,9300), ["http-headers","http-title"]),
    ("jenkins",  lambda p,s: p==8080, ["http-headers","http-title"]),
]

def parse_open_ports_from_deep(text: str):
    """Return list of (port:int, proto:str, service:str, version:str)."""
    found = []
    for line in text.splitlines():
        m = OPEN_LINE_RE.match(line.strip())
        if m:
            found.append((int(m.group(1)), m.group(2).lower(), (m.group(3) or "").lower(), (m.group(4) or "").strip()))
    return found

def post_deep_enumerations(outdir: Path, deep_index: dict, with_vuln: bool, timing: str):
    """Enumerate services AFTER deep scan using broad, safe-ish profiles."""
    base_dir = ensure_dir(outdir / "enumerations_postdeep")
    if with_vuln:
        info("Vuln scripts will be appended where relevant (may be intrusive).")

    for host, meta in deep_index.items():
        deep_path = Path(meta.get("txt",""))
        if not deep_path.exists():
            continue
        deep_txt = deep_path.read_text(errors="ignore")
        open_ports = parse_open_ports_from_deep(deep_txt)

        plan = {}
        for (p, proto, svc, ver) in open_ports:
            for name, selector, scripts in ENUM_PROFILES:
                try:
                    if selector(p, svc):
                        plan.setdefault(name, []).append(p)
                except Exception:
                    pass

        for name, ports in plan.items():
            ports = sorted(set(ports))
            enum_dir = ensure_dir(base_dir / name)
            out_path = enum_dir / f"{host}.txt"
            scripts = None
            for nm, sel, scr in ENUM_PROFILES:
                if nm == name:
                    scripts = list(scr)
            if with_vuln and name in ("web","smb","rdp","ftp","smtp","dns"):
                scripts = scripts + ["vuln"]
            banner(f"POST-DEEP ENUM • {name.upper()} • {host} • ports {ports}", fg=C.BYELLOW)
            run(["sudo","nmap","-Pn","-n",
                 "-p", ",".join(str(p) for p in ports),
                 "-sV", timing,
                 "--script", ",".join(scripts),
                 "-oN", str(out_path),
                 host], check=False, capture=True)
            good(f"{name.upper()} enum saved: {out_path}")

    return base_dir

# ============================== Main =========================================

def main():
    show_intro()

    ap = argparse.ArgumentParser(description="PortWeaver — Nmap unified reports (facts + explanation) with model selection.")
    ap.add_argument("--mode", choices=["internal","external"], help="Internal or external mode.")
    ap.add_argument("--target", help="External target (IPv4 or CIDR) for external mode.")
    ap.add_argument("--cidr", help="CIDR override for internal mode.")
    ap.add_argument("--org", help="Organization name for output folder.")
    ap.add_argument("--models", help="Comma-separated list of Ollama models to use (skip menu).")
    ap.add_argument("--with-vuln", action="store_true", help="Include NSE 'vuln' scripts (slower, potentially intrusive).")
    ap.add_argument("--aggressive", action="store_true", help="Use -T5 timing (default T4).")
    ap.add_argument("--outdir", help="Override output dir (optional).")
    args = ap.parse_args()

    # Mode selection
    if not args.mode:
        print_box("MODE", "1) Internal network\n2) External target")
        choice = input(color("Enter 1 or 2: ", C.BCYAN)).strip()
        args.mode = "internal" if choice == "1" else "external"

    # Target & ORG
    if args.mode == "external" and not args.target:
        args.target = input(color("Enter external target (IPv4 or CIDR): ", C.BCYAN)).strip()
    org = args.org or input(color("Enter organization name: ", C.BCYAN)).strip() or "unknown"

    # Requirements
    if not shutil.which("nmap"):
        bad("nmap not found. Install: brew install nmap"); sys.exit(1)
    try:
        from ollama import chat  # noqa
    except Exception:
        bad("Python package 'ollama' not found. Install: pip install ollama"); sys.exit(1)

    # Resolve target/CIDR + outdir
    if args.mode == "internal":
        det = detect_cidr_mac()
        cidr = (det["cidr"] if det else None) or args.cidr
        if not cidr:
            bad("Could not determine internal CIDR; pass --cidr (e.g., 192.168.1.0/24)."); sys.exit(1)
        target_label = cidr
    else:
        t = args.target
        try:
            if "/" in t: ipaddress.ip_network(t, strict=False)
            else: ipaddress.ip_address(t)
        except Exception:
            bad(f"Invalid external target: {t}"); sys.exit(1)
        cidr, target_label = t, t

    date_str = datetime.now().strftime("%Y%m%d")
    folder_name = f"{date_str}-{sanitize_token(target_label)}-{sanitize_token(org)}"
    outdir = Path(args.outdir).absolute() if args.outdir else unique_dir((Path("scans")/folder_name).absolute())
    ensure_dir(outdir)

    timing = "-T5" if args.aggressive else "-T4"

    # Models (show only available if not provided)
    preselected = None
    if args.models:
        preselected = [m.strip() for m in args.models.split(",") if m.strip()]
    models = pick_models_interactively(preselected)
    if not models:
        bad("No models selected. Pull one with `ollama pull llama3.1` and rerun."); sys.exit(1)

    print_box("CONFIG", f"""
    Mode:        {args.mode}
    Target:      {target_label}
    Org:         {org}
    Models:      {', '.join(models)}
    With Vuln:   {"yes" if args.with_vuln else "no"}
    Timing:      {"T5 (aggressive)" if args.aggressive else "T4 (default)"}
    Outdir:      {outdir}
    """)

    tools = NmapTools(outdir, with_vuln=args.with_vuln, timing=timing)

    # Stage 1: Discovery
    live_hosts = tools.discover_hosts(cidr)
    if not live_hosts and "/" in cidr:
        warn("No live hosts; proceeding to scan CIDR with -Pn (may be slow).")
        (outdir / "live.txt").write_text(cidr + "\n")
        live_hosts = [cidr]
    elif not live_hosts:
        bad("No live hosts; nothing to scan."); sys.exit(0)

    # Stage 2: Quick scan
    quick_txt = tools.quick_scan(live_hosts)
    quick_text = quick_txt.read_text(errors="ignore") if quick_txt.exists() else ""

    # Stage 3: Deep scan per host
    deep_dir, deep_index = tools.deep_scan_per_host(live_hosts)

    # Stage 4: Post-deep service enumerations
    enum_base = post_deep_enumerations(outdir, deep_index, with_vuln=args.with_vuln, timing=timing)

    # Stage 5: Build factual blocks per host
    facts_dir = ensure_dir(outdir / "facts-hosts")

    def read_txt(p: Path) -> str:
        try: return p.read_text(errors="ignore")
        except Exception: return ""

    def collect_all_enums_for_host(h: str) -> str:
        buf = []
        if enum_base.exists():
            for sub in sorted(p for p in enum_base.iterdir() if p.is_dir()):
                f = sub / f"{h}.txt"
                if f.exists():
                    buf.append(f"\n# [{sub.name}] {h}\n")
                    buf.append(read_txt(f))
        return "\n".join(buf)

    banner("BUILDING FACTS (deterministic)")
    host_facts_map = {}
    host_enum_highlights = {}
    for host in live_hosts:
        # Quick snippet for host (optional)
        quick_snip_lines, include = [], False
        if quick_text:
            for ln in quick_text.splitlines():
                if ln.startswith("Nmap scan report for "):
                    include = (host in ln) or ln.strip().endswith(f"({host})")
                if include:
                    quick_snip_lines.append(ln)
        quick_snip = "\n".join(quick_snip_lines)

        deep_path = Path(deep_index.get(host, {}).get("txt",""))
        deep_text = read_txt(deep_path)
        enum_snip = collect_all_enums_for_host(host)

        if not deep_text and not quick_snip and not enum_snip:
            warn(f"No evidence for {host}; skipping facts.")
            continue

        facts_md = extract_facts_for_host(host, quick_snip, enum_snip, deep_text)
        (facts_dir / f"{host}.md").write_text(facts_md + "\n")
        good(f"Facts built: {facts_dir / (host + '.md')}")
        host_facts_map[host] = facts_md

        # Keep a trimmed, readable highlight set from enum_snip to feed the final LLM and to append
        # Simple heuristic: keep first 200 lines after removing empty lines
        enum_lines = [ln for ln in enum_snip.splitlines() if ln.strip()]
        host_enum_highlights[host] = "\n".join(enum_lines[:200])

    # Stage 6 & 7: For each model, generate per-host reports and final org report (with appendices)
    for model in models:
        model_sanitized = sanitize_token(model)
        banner(f"UNIFIED HOST REPORTS — MODEL: {model}")
        reports_dir = ensure_dir(outdir / "reports" / model_sanitized)
        per_host_reports = []

        for host, facts_md in host_facts_map.items():
            try:
                unified_md = llm_unified_host_report(model, host, facts_md)
            except Exception as e:
                warn(f"[{model}] LLM unified report failed for {host}: {e}")
                unified_md = f"# Host {host}\n\n{facts_md}\n\n> LLM unavailable; showing facts only."

            rpt_out = reports_dir / f"host-{host.replace(':','_').replace('/','_')}.md"
            rpt_out.write_text(unified_md)
            good(f"[{model}] Unified host report saved: {rpt_out}")
            per_host_reports.append((host, unified_md))

            # Terminal preview (section-targeted)
            render_report_preview(host, model, unified_md)

        banner(f"FINAL ORG REPORT — MODEL: {model}")
        final_md_path = outdir / f"final-report-{model_sanitized}.md"

        # (A) Ask LLM to write the org-level summary + per-host appendix (with everything)
        if per_host_reports:
            try:
                llm_summary_and_appendix = llm_final_report(
                    model=model,
                    host_reports=per_host_reports,
                    host_facts_map=host_facts_map,
                    host_enum_highlights=host_enum_highlights,
                    org=org, target_label=target_label
                )
            except Exception as e:
                warn(f"[{model}] Final LLM report failed: {e}")
                llm_summary_and_appendix = ""

        else:
            warn(f"[{model}] No host reports to aggregate.")
            llm_summary_and_appendix = ""

        # (B) Build a deterministic final file that appends everything verbatim beneath LLM output
        #     so the final file never misses information even if the model truncates.
        deterministic_appendix = ["\n---\n# Per-Host Appendix (Deterministic)\n"]
        for host, report_md in per_host_reports:
            deterministic_appendix.append(f"\n## {host}\n")
            deterministic_appendix.append("### Facts Digest (verbatim)\n")
            deterministic_appendix.append(host_facts_map.get(host, ""))

            deterministic_appendix.append("\n### Model Report (verbatim)\n")
            deterministic_appendix.append(report_md)

            enum_h = host_enum_highlights.get(host, "")
            if enum_h:
                deterministic_appendix.append("\n### Enum Highlights (trimmed)\n```\n")
                deterministic_appendix.append(enum_h)
                deterministic_appendix.append("\n```\n")

        final_md_path.write_text((llm_summary_and_appendix or "# Final Report\n\n(No LLM summary available)\n")
                                 + "\n" + "\n".join(deterministic_appendix) + "\n")
        good(f"[{model}] Wrote overall report: {final_md_path}")

    print_box("DONE", color(f"""
    Artifacts in: {outdir}
      - live.txt, discover*.gnmap
      - quick-22-80-443.txt                    (light triage)
      - deep-hosts/<host>.txt                  (full TCP + service/OS + web/TLS scripts)
      - enumerations_postdeep/<profile>/<host>.txt   (broad post-deep service enums)
      - facts-hosts/<host>.md                  (FULL facts: quick + deep + all enums)
      - reports/<model>/host-<host>.md         (UNIFIED: facts + LLM explanation, per model)
      - final-report-<model>.md                (LLM summary + full appendices — nothing is missing)

    Tip: Use --with-vuln only when allowed. It appends NSE 'vuln' to key profiles.
    """, C.BGREEN))

if __name__ == "__main__":
    # ⚠️ Only scan systems you own / have explicit permission to test.
    main()
