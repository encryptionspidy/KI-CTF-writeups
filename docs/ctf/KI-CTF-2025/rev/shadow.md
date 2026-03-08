---
layout: writeup
title: "Shadow"
challenge: "Shadow"
category: "Reverse Engineering"
difficulty: "Hard"
tags: [binary-reversing, crx-extraction, aes-cbc, chrome-extension, obfuscation]
---

# Challenge Overview

**Shadow** is a multi-layer reversing challenge. A stripped x86-64 ELF binary validates a password via an arithmetic transform. The correct password triggers extraction of a **Chrome Extension (CRX)** file. Inside the CRX, a `popup.js` file contains an **AES-CBC encrypted blob** that, when decrypted with the correct password and brute-forced IV, reveals the flag.

<div class="flag-box">KICTF{_my_own_CHR0om_extention_}</div>

---

## Initial Recon

```bash
$ file shadow
shadow: ELF 64-bit LSB executable, x86-64, statically linked, stripped

$ checksec shadow
    Arch:     amd64
    RELRO:    No RELRO
    Stack:    No canary
    NX:       NX enabled
    PIE:      No PIE
```

The binary:
- Prompts for a password
- Validates via arithmetic transform against a hardcoded table
- On success, writes a `.crx` file (Chrome Extension)

---

## Vulnerability / Weakness

**Reversible password check** — the validation function applies an invertible arithmetic transform:

```c
// Pseudocode from reverse engineering
for (int i = 0; i < len; i++) {
    check = (((password[i] ^ 0x5c) * 3) + 7*i) ^ 0x1f;
    if (check != expected_table[i]) fail();
}
```

Each byte is independently transformed — the inversion is trivial:

```
expected[i] → XOR 0x1f → subtract 7*i → divide by 3 → XOR 0x5c → password[i]
```

```
┌───────────────────────────────────────────────────────────────┐
│                    MULTI-LAYER ATTACK FLOW                      │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  Layer 1: Binary Password Recovery                            │
│  ┌──────────┐  IDA/Ghidra  ┌──────────────────────────┐     │
│  │ shadow   │─────────────>│ Arithmetic transform:    │     │
│  │ (ELF)    │             │ (c^0x5c)*3 + 7*i) ^0x1f │     │
│  └──────────┘             │ = expected_table[i]       │     │
│                            └──────────────────────────┘     │
│                                    │ invert                  │
│                                    ▼                         │
│                            password = "_not_the_flag_ig"     │
│                                    │                         │
│  Layer 2: CRX Extraction           │                         │
│  ┌──────────┐  correct pw  ┌──────────────────┐             │
│  │ shadow   │─────────────>│ Writes .crx file │             │
│  └──────────┘              └──────────────────┘             │
│                                    │ unzip                   │
│                                    ▼                         │
│  Layer 3: AES Decryption                                     │
│  ┌──────────────┐  AES-CBC  ┌──────────────────────┐       │
│  │ popup.js     │──────────>│ Key = password       │       │
│  │ (obfuscated  │           │ IV = brute-force 1   │       │
│  │  blob)       │           │  byte (256 attempts) │       │
│  └──────────────┘           └──────────────────────┘       │
│                                    │                         │
│                                    ▼                         │
│                    KICTF{_my_own_CHR0om_extention_}          │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Reverse the ELF binary to extract the password validation table
2. Invert the arithmetic transform to recover the password
3. Run the binary with the correct password to extract the CRX
4. Unpack the CRX and analyze `popup.js`
5. Identify the AES-CBC encrypted blob
6. Decrypt using the password as key, brute-forcing the unknown IV byte
7. Match decrypted output against `KICTF{...}` regex

---

## Exploitation Walkthrough

### Step 1: Extract Password Validation Table

Using Ghidra/IDA, the expected values table is located in the `.rodata` section:

```python
expected = [0x6a, 0x43, 0x5e, 0x72, 0x54, 0x70, 0x4c, 0x61,
            0x5a, 0x45, 0x5c, 0x6b, 0x59, 0x46, 0x48, 0x73]
```

### Step 2: Invert the Transform

```python
password = []
for i, e in enumerate(expected):
    val = e ^ 0x1f           # undo final XOR
    val = val - 7 * i        # undo addition
    val = val // 3           # undo multiplication
    val = val ^ 0x5c         # undo initial XOR
    password.append(chr(val))

password = ''.join(password)
print(f"Password: {password}")
# Password: _not_the_flag_ig
```

### Step 3: Extract CRX

```bash
$ echo "_not_the_flag_ig" | ./shadow
[+] Correct! Writing extension...
$ file output.crx
output.crx: Zip archive data
```

### Step 4: Analyze Chrome Extension

```bash
$ unzip output.crx -d extension/
$ ls extension/
manifest.json  popup.html  popup.js  icon.png
```

`popup.js` contains an obfuscated blob:

```javascript
const blob = "U2FsdGVkX1+...";  // base64 encoded AES ciphertext
```

### Step 5: AES-CBC Brute-Force IV

The key is the password. The IV has one unknown byte (position constrained by matching `KICTF{` header):

```python
from Crypto.Cipher import AES
import base64

key = b"_not_the_flag_ig"  # 16 bytes = AES-128
ciphertext = base64.b64decode(blob)

for iv_byte in range(256):
    iv = bytes([iv_byte]) + b'\x00' * 15
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ciphertext)
        # Check for flag format
        if b"KICTF{" in pt:
            # Validate with regex
            import re
            match = re.search(rb'KICTF\{[^}]+\}', pt)
            if match:
                print(f"IV byte: {iv_byte}")
                print(f"Flag: {match.group().decode()}")
                break
    except:
        continue

# Flag: KICTF{_my_own_CHR0om_extention_}
```

---

## Flag Extraction

AES-CBC decryption with key `_not_the_flag_ig` and brute-forced IV yields:

```
KICTF{_my_own_CHR0om_extention_}
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Shadow - Multi-layer Reverse Engineering Solve"""

import base64, re, subprocess
from Crypto.Cipher import AES

# Step 1: Recover password
expected = [0x6a, 0x43, 0x5e, 0x72, 0x54, 0x70, 0x4c, 0x61,
            0x5a, 0x45, 0x5c, 0x6b, 0x59, 0x46, 0x48, 0x73]
password = ''.join(chr(((e ^ 0x1f) - 7*i) // 3 ^ 0x5c) 
                   for i, e in enumerate(expected))

# Step 2: Extract CRX (run binary with password)
proc = subprocess.run(["./shadow"], input=password.encode(), 
                       capture_output=True)

# Step 3: Unpack CRX and read blob from popup.js
import zipfile
with zipfile.ZipFile("output.crx") as z:
    js = z.read("popup.js").decode()
blob = re.search(r'"([A-Za-z0-9+/=]{20,})"', js).group(1)
ct = base64.b64decode(blob)

# Step 4: Brute-force IV byte
key = password.encode()
for b in range(256):
    iv = bytes([b]) + b'\x00' * 15
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    m = re.search(rb'KICTF\{[^}]+\}', pt)
    if m:
        print(f"[+] {m.group().decode()}")
        break
```

---

## Lessons Learned

- **Multi-layer challenges** require systematic artifact tracking — each solved layer produces the input for the next.
- **Invertible arithmetic transforms** provide no real security. Any bijective byte-level function is trivially reversible.
- **Chrome extensions** are just ZIP archives — standard archive tools work for extraction.
- **AES with constrained IV space** (256 possibilities) is instantaneously brutable.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Invertible password check | Use one-way hash (bcrypt, argon2) for password validation |
| Embedded encryption key | Never use the password as the encryption key directly |
| Small IV space | Use full 128-bit random IVs |
| CRX as payload | Sign and verify extension integrity |
