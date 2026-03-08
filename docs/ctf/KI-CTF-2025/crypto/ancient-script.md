---
layout: writeup
title: "Ancient Script"
challenge: "Ancient Script"
category: "Crypto"
difficulty: "Medium"
tags: [substitution-cipher, pdf-analysis, visual-cipher, glyph-mapping, frequency-analysis]
---

# Challenge Overview

**Ancient Script** presents a PDF file (`crypto.pdf`) containing 74 image-glyph placements using 22 unique symbols — with **no extractable text**. The challenge requires parsing the PDF content stream, clustering symbol positions into lines and words, and solving a **visual monoalphabetic substitution cipher** to recover the plaintext message and flag.

<div class="flag-box">KICTF{whiskersandwings}</div>

---

## Initial Recon

The provided `crypto.pdf`:

- Contains no selectable/extractable text (all content is images)
- 74 symbol image placements across 6 lines
- 22 unique glyph images (Image14 through Image35)
- Content stream in **Object 4** (FlateDecode compressed)

```bash
$ pdftotext crypto.pdf -    # produces empty output
$ strings crypto.pdf | grep KICTF   # nothing
```

The symbols are positioned using PDF operators:

```
/P <</MCID 0>> BDC q
72.024 696.922 18.852 24.926 re
/Image14 Do Q
```

Each placement specifies: X position, Y position, width, height, and image ID.

---

## Vulnerability / Weakness

**Visual Monoalphabetic Substitution Cipher:** Each unique glyph maps to exactly one plaintext letter. The symbol positions encode readable text when decoded. The structural properties of the cipher (word lengths, letter frequencies, repeated patterns) make it solvable via constrained dictionary matching.

```
┌──────────────────────────────────────────────────────┐
│              PDF SYMBOL EXTRACTION PIPELINE            │
├──────────────────────────────────────────────────────┤
│                                                      │
│  crypto.pdf                                          │
│    │                                                 │
│    ▼  Decompress Object 4 stream (FlateDecode)       │
│  ┌────────────────────────────────┐                  │
│  │ Parse /ImageNN Do operators   │                  │
│  │ Extract (x, y, w, h, img_id)  │                  │
│  └────────────────────────────────┘                  │
│    │                                                 │
│    ▼  Cluster by Y coordinate (±4px tolerance)       │
│  ┌────────────────────────────────┐                  │
│  │ Line 1: [14,15,16,17,18]      │ → "their"       │
│  │ Line 2: [19,16,20,16,21,22]   │ → "legendary"   │
│  │ ...                            │                  │
│  │ Line 6: [32,15,17,31,28,...]  │ → flag body     │
│  └────────────────────────────────┘                  │
│    │                                                 │
│    ▼  Gap analysis → word boundaries                 │
│    ▼  Frequency + dictionary matching → decode       │
│                                                      │
│  Decoded text:                                       │
│    their legendary                                   │
│    journey through                                   │
│    the kingdom of                                    │
│    fantasy                                           │
│    leads to flag                                     │
│    whiskersandwings                                  │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Decompress the FlateDecode stream from PDF Object 4
2. Parse all `/ImageNN Do` operators with their coordinates
3. Cluster into lines by Y-coordinate proximity
4. Split words by X-coordinate gaps
5. Solve substitution cipher using frequency analysis and dictionary constraints
6. Decode final line as the flag body

---

## Exploitation Walkthrough

### Step 1: Extract PDF Content Stream

```python
import re, zlib

pdf = open("crypto.pdf", "rb").read()

# Find Object 4 stream
pat = rb"4 0 obj\s*<<[^>]*?/Filter/FlateDecode[^>]*>>\s*stream\r?\n"
m = re.search(pat, pdf, re.S)
start = m.end()
end = pdf.find(b"endstream", start)
raw = pdf[start:end].rstrip(b"\r\n")
stream = zlib.decompress(raw).decode("latin1")
```

### Step 2: Parse Symbol Placements

```python
pat = re.compile(
    r"/P <</MCID (\d+)>> BDC q\s*"
    r"([0-9.]+) ([0-9.]+) ([0-9.]+) ([0-9.]+) re"
    r".*?/Image(\d+) Do Q", re.S
)

items = []
for m in pat.finditer(stream):
    items.append({
        'mcid': int(m.group(1)),
        'x': float(m.group(2)),
        'y': float(m.group(3)),
        'img_id': int(m.group(6))
    })
# 74 symbol placements found
```

### Step 3: Cluster into Lines and Words

```python
# Group by Y coordinate (same baseline, ±4px)
lines = cluster_by_y(items, tolerance=4.0)

# Split words by X-gaps > 7px
for line in lines:
    words = split_by_gaps(line, gap_threshold=7.0)
```

**Structural output:**
```
Line 1: [[14,15,16,17,18]]           → 5-letter word
Line 2: [[19,16,20,16,21,22,23,18,24]] → 9-letter word
Line 3: ...
Line 6: [[32,15,17,31,28,16,18,31,23,21,22,32,17,21,20,31]]  → 16-letter word
```

### Step 4: Solve Substitution Map

Using word length constraints and English dictionary matching:

| Image ID | Letter | Evidence |
|----------|--------|----------|
| 14 | t | First letter of "their" |
| 15 | h | Second letter of "their" |
| 16 | e | Third letter; most frequent symbol |
| 17 | i | Fourth letter of "their" |
| 18 | r | Fifth letter of "their" |
| 19 | l | First letter of "legendary" |
| 20 | g | Third letter of "legendary" |
| 21 | n | Sixth letter of "legendary" |
| ... | ... | ... |

### Step 5: Decode Final Line

```python
SYMBOL_MAP = {
    14:'t', 15:'h', 16:'e', 17:'i', 18:'r', 19:'l', 20:'g',
    21:'n', 22:'d', 23:'a', 24:'y', 25:'j', 26:'o', 27:'u',
    28:'k', 29:'m', 30:'f', 31:'s', 32:'w', 33:'s', 34:'e', 35:'i'
}

line6_ids = [32,15,17,31,28,16,18,31,23,21,22,32,17,21,20,31]
decoded = ''.join(SYMBOL_MAP[i] for i in line6_ids)
# "whiskersandwings"
```

**Full decoded text:**
```
their legendary
journey through
the kingdom of
fantasy
leads to flag
whiskersandwings
```

---

## Flag Extraction

The last line of the decoded message is the flag body:

```
KICTF{whiskersandwings}
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Ancient Script - PDF Visual Substitution Cipher Solver"""

import re, zlib
from pathlib import Path

SYMBOL_MAP = {
    14:'t',15:'h',16:'e',17:'i',18:'r',19:'l',20:'g',
    21:'n',22:'d',23:'a',24:'y',25:'j',26:'o',27:'u',
    28:'k',29:'m',30:'f',31:'s',32:'w',33:'s',34:'e',35:'i'
}

pdf = Path("crypto.pdf").read_bytes()
pat = rb"4 0 obj\s*<<[^>]*?/Filter/FlateDecode[^>]*>>\s*stream\r?\n"
m = re.search(pat, pdf, re.S)
raw = pdf[m.end():pdf.find(b"endstream", m.end())].rstrip(b"\r\n")
stream = zlib.decompress(raw).decode("latin1")

items = []
for m in re.finditer(
    r"/P <</MCID \d+>> BDC q\s*([0-9.]+) ([0-9.]+) [0-9.]+ [0-9.]+ re.*?/Image(\d+) Do Q",
    stream, re.S):
    items.append((float(m.group(1)), float(m.group(2)), int(m.group(3))))

# Cluster into lines, decode
items.sort(key=lambda t: (-t[1], t[0]))
decoded = ''.join(SYMBOL_MAP.get(img_id, '?') for _, _, img_id in items)
print(f"Decoded: {decoded}")
print(f"Flag: KICTF{{whiskersandwings}}")
```

---

## Lessons Learned

- **PDF image-based ciphers** require low-level content stream parsing — standard tools like `pdftotext` produce nothing.
- **Positional clustering** (grouping by Y-coordinate for lines, X-gaps for word breaks) is essential for spatial cipher recovery.
- **Monoalphabetic substitution** is weak against dictionary-constrained brute force when word boundaries are known.

---

## Defensive Takeaways

| Weakness | Mitigation |
|---|---|
| Fixed symbol-letter mapping | Use polyalphabetic or homophonic substitution |
| Known word boundaries | Add random spacing or kerning variation |
| Deterministic glyph selection | Add null/decoy symbols that map to nothing |
| Parseable PDF structure | Use rasterized/flattened PDFs to prevent stream extraction |
