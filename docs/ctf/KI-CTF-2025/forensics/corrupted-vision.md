---
layout: writeup
title: "Corrupted Vision"
challenge: "Corrupted Vision"
category: "Forensics"
difficulty: "Hard"
tags: [lsb-stego, png-repair, chunk-corruption, multi-stage, ocr, font-matching]
---

# Challenge Overview

**Corrupted Vision** is a multi-stage forensic challenge that chains **LSB steganography extraction**, an **external artifact pivot via Google Drive**, **malformed PNG repair**, and **glyph-level font matching** to recover the flag. The initial artifact is a decoy — the real flag is hidden behind three layers of indirection.

<div class="flag-box">KICTF{y0u_f1nd_th3_c0rrupt3d_0n3}</div>

---

## Initial Recon

```bash
$ file decoy.png
decoy.png: PNG image data, 500 x 500, 8-bit/color RGB

$ exiftool decoy.png
# No suspicious metadata

$ binwalk decoy.png
# Standard PNG, no appended archives
```

Standard triage shows a clean 500×500 RGB PNG. No obvious anomalies — but LSB analysis reveals more.

---

## Vulnerability / Weakness

A **multi-layer steganographic chain**:

1. **LSB Steganography** in `decoy.png` hides a decoy flag AND a Google Drive link
2. The Drive artifact has **intentionally corrupted PNG structure** (`XNG` signature, `IHDX` chunk, fake CRC `0xDEADBEEF`)
3. The repaired PNG contains **text encoded in the green channel** that standard OCR struggles with
4. Deterministic **font-glyph component matching** resolves OCR ambiguity

```
┌─────────────────────────────────────────────────────────────────┐
│                   MULTI-STAGE FORENSIC CHAIN                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Stage 1: LSB Extraction                                        │
│  ┌───────────┐  zsteg b1,rgb,lsb,xy  ┌──────────────────┐     │
│  │ decoy.png │───────────────────────>│ LSB payload:     │     │
│  │ 500×500   │                        │  • decoy flag ✗  │     │
│  └───────────┘                        │  • GDrive link → │     │
│                                       └──────────────────┘     │
│                                              │                  │
│  Stage 2: External Artifact                  ▼                  │
│                                       ┌──────────────────┐     │
│                                       │ drive_artifact   │     │
│                                       │ Corrupted PNG:   │     │
│                                       │  sig: XNG ✗      │     │
│                                       │  chunk: IHDX ✗   │     │
│                                       │  CRC: 0xDEADBEEF │     │
│                                       └──────────────────┘     │
│                                              │                  │
│  Stage 3: PNG Repair                         ▼                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ fix_xng.py:                                             │   │
│  │   XNG  → 89 50 4E 47 0D 0A 1A 0A  (PNG sig)           │   │
│  │   IHDX → IHDR                                          │   │
│  │   CRC  → recalculated                                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                              │                  │
│  Stage 4: Signal Extraction                  ▼                  │
│  ┌──────────────────────────────────────────┐                  │
│  │ drive_artifact_fixed.png (700×120)       │                  │
│  │ Green channel → text signal              │                  │
│  │ DejaVuSans-Bold glyph matching:          │                  │
│  │   score=0 → KICTF{y0u_f1nd_th3_...}     │                  │
│  └──────────────────────────────────────────┘                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Run LSB extraction on `decoy.png` with `zsteg`
2. Identify the real payload (Google Drive link, ignore decoy flag)
3. Download the external artifact
4. Analyze and repair the corrupted PNG structure
5. Extract green channel text signal
6. Apply font-based component matching for deterministic decoding
7. Validate flag format

---

## Exploitation Walkthrough

### Step 1: LSB Extraction

```bash
$ zsteg decoy.png
b1,rgb,lsb,xy .. text: "DECOY_FLAG{not_the_real_one} ... 
                         https://drive.google.com/file/d/<id>/view"
```

Two items extracted:
- A decoy flag (trap for hasty solvers)
- A Google Drive link pointing to the real artifact

### Step 2: Download External Artifact

```bash
$ curl -L "https://drive.google.com/uc?id=<file_id>" -o drive_artifact

$ file drive_artifact
drive_artifact: data

$ xxd drive_artifact | head -3
00000000: 8958 4e47 ...  # 'XNG' instead of 'PNG'
```

### Step 3: Analyze Corruption

```python
# Chunk analysis
chunks = parse_png_chunks("drive_artifact")
# Chunk 0: type='IHDX', length=13, CRC=0xDEADBEEF  ← corrupted
# Chunk 1: type='IDAT', length=..., CRC=valid
# Chunk 2: type='IEND', length=0, CRC=valid
```

Three corruptions:
1. **Signature:** `89 58 4E 47` (`XNG`) instead of `89 50 4E 47` (`PNG`)
2. **First chunk type:** `IHDX` instead of `IHDR`
3. **First chunk CRC:** `0xDEADBEEF` instead of correct CRC

### Step 4: Repair PNG

```python
#!/usr/bin/env python3
"""fix_xng.py - Repair corrupted PNG"""
import struct, zlib

data = bytearray(open("drive_artifact", "rb").read())

# Fix PNG signature
data[0:8] = b'\x89PNG\r\n\x1a\n'

# Fix IHDR chunk type
data[12:16] = b'IHDR'

# Recalculate CRC for IHDR chunk
ihdr_data = data[12:12+4+13]  # type + data
correct_crc = zlib.crc32(ihdr_data) & 0xFFFFFFFF
struct.pack_into('>I', data, 12+4+13, correct_crc)

open("fixed.png", "wb").write(data)
```

```bash
$ file fixed.png
fixed.png: PNG image data, 700 x 120, 8-bit/color RGB
```

### Step 5: Green Channel Text Extraction

```python
from PIL import Image
import numpy as np

img = np.array(Image.open("fixed.png"))
green = img[:, :, 1]  # Green channel

# Text signal is present — green channel has non-zero values
# forming letter shapes in a bounding box
```

### Step 6: Font-Based Component Matching

Standard OCR produced noisy results. Deterministic matching against **DejaVuSans-Bold** glyphs:

```python
# For each candidate flag string:
#   render with DejaVuSans-Bold at matching size
#   compute pixel-level difference score
# Score 0 = perfect match

candidates = generate_candidates(ocr_results)
best = min(candidates, key=lambda c: match_score(c, green_channel))
# best = "KICTF{y0u_f1nd_th3_c0rrupt3d_0n3}", score=0
```

The unique best candidate with score `0` (perfect pixel match):

```
KICTF{y0u_f1nd_th3_c0rrupt3d_0n3}
```

---

## Flag Extraction

```
KICTF{y0u_f1nd_th3_c0rrupt3d_0n3}
```

Validated via regex (`^KICTF\{.*\}$`) and deterministic font component matching with score 0.

---

## Proof of Concept

```bash
#!/bin/bash
# Corrupted Vision - Full solve pipeline

# Stage 1: LSB extraction
zsteg decoy.png -E b1,rgb,lsb,xy > lsb_payload.txt
grep -oP 'https://drive\.google\.com/\S+' lsb_payload.txt

# Stage 2: Download
curl -L "https://drive.google.com/uc?id=<id>" -o artifact

# Stage 3: Repair
python3 fix_xng.py artifact fixed.png

# Stage 4: Inspect green channel
python3 -c "
from PIL import Image; import numpy as np
img = np.array(Image.open('fixed.png'))
Image.fromarray(img[:,:,1]).save('green_channel.png')
"

# Stage 5: Font matching (verify_flag_candidate.py)
python3 verify_flag_candidate.py \
  --candidate 'KICTF{y0u_f1nd_th3_c0rrupt3d_0n3}'
# component_count=41, score=0, match=true
```

---

## Lessons Learned

- **Decoy flags** are an effective anti-speedrun mechanism. Always verify flags against the challenge context before submitting.
- **External artifact pivots** (URLs embedded in stego payloads) create multi-stage chains that require systematic investigation.
- **PNG structure corruption** with known marker mutations (`XNG`/`IHDX`/`DEADBEEF`) is a fingerprint-based obfuscation — repairs are deterministic once the pattern is recognized.
- **Font-based glyph matching** outperforms OCR when the exact font is identifiable, providing score-0 deterministic verification.

---

## Defensive Takeaways

| Technique | Detection Method |
|---|---|
| LSB steganography | `zsteg`, `stegsolve`, statistical analysis |
| External pivots | URL extraction from all decoded payloads |
| PNG chunk corruption | Hex analysis of magic bytes and chunk headers |
| Green channel signals | Per-channel analysis and thresholding |
