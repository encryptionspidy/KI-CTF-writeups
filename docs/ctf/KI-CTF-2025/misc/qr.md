---
layout: writeup
title: "QR"
challenge: "QR"
category: "Misc"
difficulty: "Easy"
tags: [qr-code, image-reconstruction, base64, binary-matrix, zbar]
---

# Challenge Overview

**QR** provides a text file (`qr.txt`) containing a 192×192 binary matrix (CSV of 0s and 1s). Reconstructing this matrix into a QR code image and scanning it reveals a base64-encoded string that decodes to the flag.

<div class="flag-box">KICTF{hello_bro}</div>

---

## Initial Recon

```bash
$ wc -l qr.txt
192

$ head -1 qr.txt | tr ',' '\n' | wc -l
192
```

The file contains 192 rows of 192 comma-separated binary values — a 192×192 binary matrix.

---

## Vulnerability / Weakness

The flag is simply encoded as a QR code represented in a plain-text matrix format. The "vulnerability" is format obfuscation — the QR code data is intact but requires image reconstruction before scanning tools can decode it.

```
┌──────────────────────────────────────────────────────────┐
│                  QR RECONSTRUCTION PIPELINE                │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  qr.txt (192 lines × 192 values)                        │
│    │                                                     │
│    ▼  Parse CSV → 192×192 numpy array                    │
│  ┌───────────────────────────────────────┐               │
│  │ 0 = white pixel, 1 = black pixel     │               │
│  │ Reconstruct as PNG image (×4 scale)  │               │
│  └───────────────────────────────────────┘               │
│    │                                                     │
│    ▼  zbarimg scan                                       │
│  ┌───────────────────────────────────────┐               │
│  │ QR data: S0lDVEZ7aGVsbG9fYnJvfQ==   │               │
│  └───────────────────────────────────────┘               │
│    │                                                     │
│    ▼  base64 decode                                      │
│  ┌───────────────────────────────────────┐               │
│  │ KICTF{hello_bro}                     │               │
│  └───────────────────────────────────────┘               │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Parse the CSV binary matrix
2. Reconstruct as a QR code PNG image
3. Scan with `zbarimg`
4. Base64 decode the result

---

## Exploitation Walkthrough

### Step 1: Reconstruct QR Image

```python
from PIL import Image
import csv

SCALE = 4  # upscale for reliable scanning

with open("qr.txt") as f:
    matrix = [list(map(int, row.split(','))) for row in f]

size = len(matrix)
img = Image.new('L', (size * SCALE, size * SCALE), 255)

for y, row in enumerate(matrix):
    for x, val in enumerate(row):
        if val == 1:
            for dy in range(SCALE):
                for dx in range(SCALE):
                    img.putpixel((x*SCALE+dx, y*SCALE+dy), 0)

img.save("qr_reconstructed.png")
```

### Step 2: Scan QR Code

```bash
$ zbarimg qr_reconstructed.png
QR-Code:S0lDVEZ7aGVsbG9fYnJvfQ==
```

### Step 3: Base64 Decode

```bash
$ echo "S0lDVEZ7aGVsbG9fYnJvfQ==" | base64 -d
KICTF{hello_bro}
```

---

## Flag Extraction

```
QR data (base64): S0lDVEZ7aGVsbG9fYnJvfQ==
Decoded: KICTF{hello_bro}
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""QR - Binary Matrix to Flag"""

import base64, subprocess
from PIL import Image

# Parse matrix
with open("qr.txt") as f:
    matrix = [list(map(int, line.strip().split(','))) for line in f]

# Reconstruct QR image
S = 4
n = len(matrix)
img = Image.new('L', (n*S, n*S), 255)
for y, row in enumerate(matrix):
    for x, v in enumerate(row):
        if v:
            for dy in range(S):
                for dx in range(S):
                    img.putpixel((x*S+dx, y*S+dy), 0)
img.save("/tmp/qr.png")

# Scan and decode
out = subprocess.check_output(["zbarimg", "-q", "/tmp/qr.png"]).decode()
b64 = out.split("QR-Code:")[-1].strip()
flag = base64.b64decode(b64).decode()
print(f"[+] {flag}")
```

---

## Lessons Learned

- **Binary matrix representation** of QR codes is a common CTF encoding trick — always look for NxN binary data.
- **QR codes need sufficient resolution** for scanning tools. Upscaling by 4x ensures reliable decoding.
- **Double encoding** (QR → base64 → flag) adds minimal difficulty but tests the solver's pipeline completeness.

---

## Defensive Takeaways

This is a puzzle challenge with no real "vulnerability" — the QR code is intentionally obfuscated as a text matrix. In real-world scenarios, QR codes in unusual formats (text, CSV, binary dumps) should be reconstructed and scanned as part of standard forensic analysis.
