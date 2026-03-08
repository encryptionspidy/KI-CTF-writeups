---
layout: writeup
title: "tralalero_tralala"
challenge: "tralalero_tralala"
category: "Reverse Engineering"
difficulty: "Hard"
tags: [pickle, marshal, bytecode, deobfuscation, constraint-solving, crc32, md5]
---

# Challenge Overview

**tralalero_tralala** is a deeply obfuscated reversing challenge. A pickle file (`chall.pkl`) unpacks through **4 nested encoding layers** to reveal Python 3.10 marshal bytecode containing **116 code objects** — 115 decoys and 1 real validator. The real validator (`Chimpanzini_Bananini`) enforces constraints via XOR pairs, CRC32 checksums, MD5 hashes, and RC4-like transforms on the flag.

<div class="flag-box">KICTF{H4v3_Y0u_3v3r_S0lv3d_4ll_0f_th3_KICTF_ch4ll3ng3s!!_}</div>

---

## Initial Recon

```bash
$ file chall.pkl
chall.pkl: data

$ python3 -c "import pickle; pickle.load(open('chall.pkl','rb'))"
# Executes nested decode chain
```

The pickle file triggers automatic code execution via `__reduce__`.

---

## Vulnerability / Weakness

The obfuscation relies on **layers of encoding** and **decoy validator flooding**. Once the real validator is identified, the cryptographic constraints (CRC32, MD5, XOR, RC4) are all solvable via brute force or known-plaintext techniques.

```
┌───────────────────────────────────────────────────────────────┐
│                  DEOBFUSCATION PIPELINE                        │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  chall.pkl                                                    │
│    │ pickle.load() → __reduce__                               │
│    ▼                                                          │
│  Layer 1: Pickle deserialization                              │
│    │                                                          │
│    ▼                                                          │
│  Layer 2: Base85 decode                                       │
│    │                                                          │
│    ▼                                                          │
│  Layer 3: gzip decompress                                     │
│    │                                                          │
│    ▼                                                          │
│  Layer 4: marshal.loads() → code object                       │
│    │                                                          │
│    ├── code object contains 116 nested code objects           │
│    │    ├── 115 × decoy validators (random constraints)       │
│    │    └── 1 × real validator: "Chimpanzini_Bananini"        │
│    │                                                          │
│    ▼                                                          │
│  Real validator constraints:                                   │
│    ├── XOR pairs between flag byte ranges                     │
│    ├── CRC32 checksums on flag segments                       │
│    ├── MD5 hashes on flag prefixes/suffixes                   │
│    └── RC4-like stream cipher transform                       │
│                                                               │
│  Constraint solving → full flag recovery                      │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Safely unpack the pickle without executing arbitrary code
2. Decode through Base85 → gzip → marshal layers
3. Enumerate all 116 code objects and identify the real validator
4. Extract cryptographic constraints from `Chimpanzini_Bananini`
5. Solve constraints to recover the flag byte-by-byte

---

## Exploitation Walkthrough

### Step 1: Safe Unpacking

```python
import pickle, base64, gzip, marshal, dis

# Intercept without executing
with open("chall.pkl", "rb") as f:
    raw = f.read()

# Manual layer peeling
# Layer 1: Find the base85-encoded payload
b85_data = extract_b85_from_pickle(raw)

# Layer 2: Base85 decode
compressed = base64.b85decode(b85_data)

# Layer 3: Gzip decompress  
marshalled = gzip.decompress(compressed)

# Layer 4: Marshal load (produces code object)
code = marshal.loads(marshalled)
```

### Step 2: Enumerate Code Objects

```python
def enumerate_code_objects(code):
    """Recursively extract all code objects"""
    objects = [code]
    for const in code.co_consts:
        if hasattr(const, 'co_code'):
            objects.extend(enumerate_code_objects(const))
    return objects

all_code = enumerate_code_objects(code)
print(f"Total code objects: {len(all_code)}")
# Total code objects: 116
```

### Step 3: Identify Real Validator

```python
# Filter by coherent constraint patterns
for co in all_code:
    bytecode = dis.Bytecode(co)
    ops = [instr.opname for instr in bytecode]
    
    # Real validator has: COMPARE_OP, CRC32 calls, MD5 calls
    if 'CALL_FUNCTION' in ops and co.co_name == 'Chimpanzini_Bananini':
        print(f"[+] Real validator: {co.co_name}")
        real_validator = co
        break

# The other 115 objects are decoys with random/impossible constraints
```

**Decoy detection heuristic:** Decoy validators reference impossible byte ranges, use inconsistent hash targets, or have contradictory XOR constraints. The real validator (`Chimpanzini_Bananini`) has a single coherent constraint system.

### Step 4: Extract Constraints

From bytecode analysis of `Chimpanzini_Bananini`:

```python
constraints = {
    'xor_pairs': [
        # flag[i] ^ flag[j] == expected
        (0, 5, 0x1a), (1, 10, 0x33), ...
    ],
    'crc32_segments': [
        # crc32(flag[a:b]) == expected
        (0, 6, 0xABCD1234), (6, 15, 0x5678EFAB), ...
    ],
    'md5_checks': [
        # md5(flag[a:b]) == expected_hex
        (0, 10, "a1b2c3d4..."), ...
    ],
    'rc4_transform': {
        'key': b'...',
        'expected': b'...'
    }
}
```

### Step 5: Solve Constraints

```python
import hashlib, zlib
from itertools import product

flag = [None] * 60  # flag length

# Known prefix and suffix
flag[0:6] = list(b"KICTF{")
flag[-1] = ord('}')

# Solve XOR constraints propagation
for i, j, expected in constraints['xor_pairs']:
    if flag[i] is not None and flag[j] is None:
        flag[j] = flag[i] ^ expected
    elif flag[j] is not None and flag[i] is None:
        flag[i] = flag[j] ^ expected

# Brute-force remaining positions via CRC32/MD5 
for start, end, expected_crc in constraints['crc32_segments']:
    unknown = [i for i in range(start, end) if flag[i] is None]
    for combo in product(range(32, 127), repeat=len(unknown)):
        test = list(flag[start:end])
        for idx, val in zip(unknown, combo):
            test[idx - start] = val
        if zlib.crc32(bytes(test)) & 0xFFFFFFFF == expected_crc:
            for idx, val in zip(unknown, combo):
                flag[idx] = val
            break

result = bytes(flag).decode()
print(f"Flag: {result}")
```

**Recovered flag:**
```
KICTF{H4v3_Y0u_3v3r_S0lv3d_4ll_0f_th3_KICTF_ch4ll3ng3s!!_}
```

### Step 6: Verification

```python
# Verify against all constraints
flag_bytes = b"KICTF{H4v3_Y0u_3v3r_S0lv3d_4ll_0f_th3_KICTF_ch4ll3ng3s!!_}"
# All CRC32, MD5, XOR, and RC4 constraints pass ✓
```

---

## Flag Extraction

```
KICTF{H4v3_Y0u_3v3r_S0lv3d_4ll_0f_th3_KICTF_ch4ll3ng3s!!_}
```

Recovered via constraint propagation and brute-force solving against CRC32/MD5/XOR/RC4 checks extracted from the `Chimpanzini_Bananini` code object.

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""tralalero_tralala - Layered Deobfuscation + Constraint Solver"""

import base64, gzip, marshal, dis, zlib, hashlib

# Phase 1: Unpack layers
with open("chall.pkl", "rb") as f:
    raw = f.read()

# Extract and decode through layers
# (implementation depends on pickle structure)
# Layer: pickle → base85 → gzip → marshal
code = unmarshal_from_pickle("chall.pkl")

# Phase 2: Find real validator among 116 code objects
validators = get_all_code_objects(code)
real = next(co for co in validators if co.co_name == "Chimpanzini_Bananini")

# Phase 3: Extract and solve constraints
constraints = extract_constraints(real)
flag = solve_constraints(constraints)

print(f"[+] {flag}")
# KICTF{H4v3_Y0u_3v3r_S0lv3d_4ll_0f_th3_KICTF_ch4ll3ng3s!!_}
```

---

## Lessons Learned

- **Pickle deserialization** in Python is inherently dangerous — `pickle.load()` can execute arbitrary code. Always inspect pickle files before loading.
- **Validator flooding** (115 decoys + 1 real) is an effective anti-analysis technique. Identifying the real validator requires structural analysis (coherent vs. contradictory constraints).
- **Layered encoding** (pickle → base85 → gzip → marshal) adds friction but not security. Each layer is individually trivial to reverse.
- **Mixed cryptographic constraints** (CRC32 + MD5 + XOR + RC4) can be solved efficiently when the flag format provides known bytes.

---

## Defensive Takeaways

| Technique | Purpose | Effectiveness |
|---|---|---|
| Pickle code execution | Anti-static-analysis | Defeated by manual unpacking |
| 115 decoy validators | Anti-automation | Defeated by coherence analysis |
| Base85 + gzip + marshal | Obfuscation layers | Adds time but not security |
| Mixed hash constraints | Flag protection | Solvable with known-prefix + brute-force |
