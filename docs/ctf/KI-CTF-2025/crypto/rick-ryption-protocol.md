---
layout: writeup
title: "Rick-ryption Protocol"
challenge: "Rick-ryption Protocol"
category: "Crypto"
difficulty: "Hard"
tags: [chaos-cryptography, henon-map, png-metadata, seed-leak, image-encryption]
---

# Challenge Overview

**Rick-ryption Protocol** implements a chaos-based image encryption scheme using the **Hénon map** — a classic chaotic dynamical system. Two images are encrypted with the same key derived from chaotic sequences. A critical seed leak in the PNG metadata of `enc_2.png` allows complete key recovery and decryption.

<div class="flag-box">KICTF{CH40S_1S_D3T3RM1N1ST1C_1N_F1N1T3_PR3C1S10N}</div>

---

## Initial Recon

Provided files:
- `chall.py` — encryption script (with redacted seeds)
- `enc_1.png` — encrypted image 1
- `enc_2.png` — encrypted image 2

The encryption algorithm in `chall.py`:
1. Generate chaotic sequence using Hénon map with secret seeds `(x0, y0)`
2. First half of sequence → **permutation** (pixel shuffle)
3. Second half → **keystream** for XOR
4. Apply **CBC-like chaining** (each ciphertext byte XORed with previous)

```python
# Hénon map iteration (from chall.py)
def gen(x0, y0, N):
    a, b = 1.4, 0.3
    x, y = x0, y0
    seq = []
    for _ in range(N):
        x_new = 1 - a*x*x + y
        y_new = b * x
        # Overflow protection
        if abs(x_new) > 10: x_new = np.tanh(x_new)
        if abs(y_new) > 10: y_new = np.tanh(y_new)
        x = round(x_new, 10)
        y = round(y_new, 10)
        seq.append(abs(x))
    return seq
```

---

## Vulnerability / Weakness

**Seed Leak via PNG Metadata (CWE-312):** The encrypted file `enc_2.png` contains a `tEXt` metadata chunk with a base64-encoded comment revealing the exact seeds:

```
Comment: eD0wLjEseT0wLjE=
       ↓ base64 decode
x=0.1,y=0.1
```

With the seeds known, the entire chaotic sequence is deterministic and the encryption becomes trivially reversible.

```
┌───────────────────────────────────────────────────────────────┐
│                 HENON MAP CRYPTO ATTACK FLOW                   │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  enc_2.png                                                    │
│    │                                                          │
│    ├─ tEXt chunk: "Comment" = base64("x=0.1,y=0.1")         │
│    │                                                          │
│    ▼                                                          │
│  Seeds: x0=0.1, y0=0.1                                       │
│    │                                                          │
│    ▼                                                          │
│  gen(0.1, 0.1, 2*N) → deterministic chaotic sequence          │
│    │                                                          │
│    ├─ seq[:N]  → perm = argsort → pixel permutation           │
│    ├─ seq[N:]  → keystream = int((v * 10^10) % 256)          │
│    │                                                          │
│    ▼                                                          │
│  DECRYPT (inverse of encrypt):                                │
│    1. Undo CBC-XOR: plain[i] = cipher[i] ⊕ key[i] ⊕ prev    │
│    2. Undo permutation: place scrambled[i] at perm[i]         │
│    │                                                          │
│    ▼                                                          │
│  dec_1.png → contains flag text                               │
│  dec_2.png → secondary image                                  │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Parse PNG chunks of `enc_2.png` to find `tEXt` metadata
2. Base64 decode the comment to recover seeds
3. Regenerate the exact chaotic sequence
4. Derive permutation and keystream
5. Implement inverse decryption (undo CBC-XOR, then undo permutation)
6. Decrypt both images; read flag from `dec_1.png`

---

## Exploitation Walkthrough

### Step 1: Extract Seeds from PNG Metadata

```python
import base64

def extract_seeds(png_path):
    data = open(png_path, 'rb').read()
    idx = 8  # skip PNG signature
    while idx + 12 <= len(data):
        length = int.from_bytes(data[idx:idx+4], 'big')
        ctype = data[idx+4:idx+8]
        payload = data[idx+8:idx+8+length]
        idx += 12 + length
        
        if ctype == b'tEXt' and b'\x00' in payload:
            key, value = payload.split(b'\x00', 1)
            if key == b'Comment':
                decoded = base64.b64decode(value).decode()
                # "x=0.1,y=0.1"
                parts = dict(item.split('=') for item in decoded.split(','))
                return float(parts['x']), float(parts['y'])
    
    raise RuntimeError("No seed comment found")

x0, y0 = extract_seeds("enc_2.png")
# x0=0.1, y0=0.1
```

### Step 2: Regenerate Chaotic Sequence

```python
import math

def gen_seq(x0, y0, n):
    a, b = 1.4, 0.3
    x, y = x0, y0
    seq = [0.0] * n
    for i in range(n):
        x_new = 1 - a*x*x + y
        y_new = b * x
        if abs(x_new) > 10: x_new = math.tanh(x_new)
        if abs(y_new) > 10: y_new = math.tanh(y_new)
        x = round(x_new, 10)
        y = round(y_new, 10)
        seq[i] = abs(x)
    return seq
```

### Step 3: Decrypt

```python
from PIL import Image

img = Image.open("enc_1.png").convert("L")
cipher = img.tobytes()
N = len(cipher)

seq = gen_seq(x0, y0, 2 * N)
perm = sorted(range(N), key=seq[:N].__getitem__)
keystream = [int((v * 1e10) % 256) for v in seq[N:]]

# Undo CBC-XOR
scrambled = [0] * N
prev = 0
for i, c in enumerate(cipher):
    scrambled[i] = c ^ keystream[i] ^ prev
    prev = c

# Undo permutation
plain = [0] * N
for i, p_idx in enumerate(perm):
    plain[p_idx] = scrambled[i]

Image.frombytes("L", img.size, bytes(plain)).save("dec_1.png")
```

### Step 4: Read Flag from Decrypted Image

The decrypted `dec_1.png` contains visible text:

```
KICTF{CH40S_1S_D3T3RM1N1ST1C_1N_F1N1T3_PR3C1S10N}
```

---

## Flag Extraction

The flag is visually embedded in the decrypted image `dec_1.png`:

```
KICTF{CH40S_1S_D3T3RM1N1ST1C_1N_F1N1T3_PR3C1S10N}
```

Meaning: *"Chaos is deterministic in finite precision"* — a reference to the fact that chaotic systems implemented in finite-precision arithmetic are entirely deterministic.

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Rick-ryption Protocol - Hénon Map Chaos Decryptor"""

import base64, math
from PIL import Image

def extract_seeds(png_path):
    data = open(png_path, 'rb').read()
    idx = 8
    while idx + 12 <= len(data):
        length = int.from_bytes(data[idx:idx+4], 'big')
        ctype = data[idx+4:idx+8]
        payload = data[idx+8:idx+8+length]
        idx += 12 + length
        if ctype == b'tEXt' and b'\x00' in payload:
            key, val = payload.split(b'\x00', 1)
            if key == b'Comment':
                d = base64.b64decode(val).decode()
                p = dict(i.split('=') for i in d.split(','))
                return float(p['x']), float(p['y'])

def gen_seq(x0, y0, n):
    a, b = 1.4, 0.3
    x, y = x0, y0
    seq = []
    for _ in range(n):
        xn = 1 - a*x*x + y
        yn = b * x
        if abs(xn) > 10: xn = math.tanh(xn)
        if abs(yn) > 10: yn = math.tanh(yn)
        x, y = round(xn, 10), round(yn, 10)
        seq.append(abs(x))
    return seq

def decrypt(cipher, perm, keystream):
    n = len(cipher)
    scrambled = [0]*n
    prev = 0
    for i, c in enumerate(cipher):
        scrambled[i] = c ^ keystream[i] ^ prev
        prev = c
    plain = [0]*n
    for i, p in enumerate(perm):
        plain[p] = scrambled[i]
    return bytes(plain)

x0, y0 = extract_seeds("enc_2.png")
img = Image.open("enc_1.png").convert("L")
c = img.tobytes()
N = len(c)

seq = gen_seq(x0, y0, 2*N)
perm = sorted(range(N), key=seq[:N].__getitem__)
ks = [int((v*1e10) % 256) for v in seq[N:]]

plain = decrypt(c, perm, ks)
Image.frombytes("L", img.size, plain).save("dec_1.png")
print("[+] Decrypted → dec_1.png (contains flag)")
```

---

## Lessons Learned

- **PNG metadata** is frequently overlooked during challenge design. Always scrub metadata from encrypted artifacts.
- **Chaotic cryptosystems** with known seeds are completely broken — the entire keystream is deterministically reproducible.
- The Hénon map's sensitivity to initial conditions is irrelevant when those conditions are leaked.
- **CBC-mode chaining** in custom crypto is easily invertible when the keystream is known — it adds no security beyond obscurity.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Seed leak in metadata | Strip all metadata from outputs (`pngcrush -rem allb`) |
| Deterministic chaos | Use cryptographically secure PRNGs (e.g., AES-CTR), not mathematical chaos maps |
| Same key for both images | Use unique IVs/nonces per encryption |
| Custom cryptography | Use established algorithms (AES-GCM, ChaCha20-Poly1305) — never roll your own |
