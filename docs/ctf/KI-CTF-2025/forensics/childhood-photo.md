---
layout: writeup
title: "Childhood Photo"
challenge: "Childhood Photo"
category: "Forensics"
difficulty: "Medium"
tags: [byte-reversal, jpeg-carving, steganography, foremost, handwriting-ocr]
---

# Challenge Overview

**Childhood Photo** provides a mysterious file `gepj.lanif` with no recognizable file signature. The filename itself is a clue — reversed, it reads `final.jpeg`. The file's bytes are completely reversed, and once restored, it reveals a JPEG containing an **embedded second JPEG** with a handwritten flag.

<div class="flag-box">KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}</div>

---

## Initial Recon

```bash
$ file gepj.lanif
gepj.lanif: data

$ xxd gepj.lanif | head -3
00000000: d9ff e200 1000 4a46 4946 0001 0100 0001  ......JFIF......
```

**Key observations:**
- `file` identifies it as generic "data" — no recognized magic bytes
- Hex dump starts with `d9 ff` — this is the **reversed JPEG end-of-image marker** (`FF D9`)
- The filename `gepj.lanif` reversed is `final.jpeg`
- ASCII strings include `JFIF` but in reversed byte context

**Hypothesis:** The entire file is byte-reversed.

---

## Vulnerability / Weakness

**Byte-order obfuscation** combined with **JPEG concatenation steganography**. The file is a valid JPEG whose bytes have been reversed end-to-start. After byte reversal, the restored JPEG contains a second JPEG appended after the primary image's `FF D9` marker.

```
┌───────────────────────────────────────────────────────────┐
│                FORENSIC RECOVERY PIPELINE                  │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  gepj.lanif (raw artifact)                                │
│    │ Header: D9 FF ... (reversed JPEG tail)               │
│    │ Filename reversed: "final.jpeg"                      │
│    │                                                      │
│    ▼  Reverse all bytes                                   │
│  ┌─────────────────────────────────────────┐              │
│  │ final.jpeg (675×1200 JFIF)             │              │
│  │  ┌──────────────────────────────┐       │              │
│  │  │ Primary JPEG (main image)   │       │              │
│  │  │ FF D8 ... FF D9              │       │              │
│  │  └──────────────────────────────┘       │              │
│  │  ┌──────────────────────────────┐       │              │
│  │  │ Embedded JPEG @ offset      │       │              │
│  │  │ 0x21e92 (300×532)           │       │              │
│  │  │ Contains handwritten flag   │       │              │
│  │  │ text in image               │       │              │
│  │  └──────────────────────────────┘       │              │
│  └─────────────────────────────────────────┘              │
│    │                                                      │
│    ▼  foremost carve                                      │
│  00000000.jpg → primary image                             │
│  00000271.jpg → handwritten flag image                    │
│    │                                                      │
│    ▼  OCR / visual inspection                             │
│  KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}                      │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Confirm byte-reversal hypothesis via header analysis
2. Reverse all bytes to recover valid JPEG
3. Carve embedded images with `foremost`
4. Read handwritten flag from carved secondary JPEG
5. Normalize and validate flag format

---

## Exploitation Walkthrough

### Step 1: Evidence Preservation

```bash
# Hash the original artifact
sha256sum gepj.lanif
# 4406c6954ddbfea62452adc861c846bb909e0c9faa7e4fa8f530d86f2f5f9860

md5sum gepj.lanif
# c76da36d41c0f4c25325fcc62af96a43
```

### Step 2: Byte Reversal

```bash
# Reverse all bytes
xxd -p -c1 gepj.lanif | tac | xxd -p -r > final.jpeg

# Verify recovery
file final.jpeg
# final.jpeg: JPEG image data, JFIF standard, resolution (DPI),
#             density 1x1, segment length 16, baseline, precision 8,
#             675x1200, components 3
```

The reversed file is now a valid 675×1200 JPEG.

### Step 3: Carve Embedded Images

```bash
foremost -i final.jpeg -o foremost_output

cat foremost_output/audit.txt
# jpg:= 2
# 00000000.jpg   0 bytes     (primary image)
# 00000271.jpg   138898 bytes (embedded at offset 0x21e92)
```

Two JPEGs carved:
- `00000000.jpg` — the main/primary image
- `00000271.jpg` — a 300×532 image with handwritten text

### Step 4: Read the Flag

Opening `00000271.jpg` reveals handwritten text. After careful reading and normalization:

```
KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}
```

### Step 5: Validate via Live CTF API

```bash
curl -sS -b cookiejar.txt \
  -H "CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -X POST "https://kictf.n0va.in/api/v1/challenges/attempt" \
  --data '{"challenge_id":12,"submission":"KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}"}'

# {"success":true,"data":{"status":"already_solved",
#  "message":"Correct but you already solved this"}}
```

---

## Flag Extraction

The flag `KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}` was extracted from the handwritten text in the carved secondary JPEG at offset `0x21e92` within the byte-reversed artifact.

---

## Proof of Concept

```bash
#!/bin/bash
# Childhood Photo - Complete solve pipeline

# Step 1: Reverse bytes
xxd -p -c1 gepj.lanif | tac | xxd -p -r > final.jpeg

# Step 2: Carve embedded images
foremost -i final.jpeg -o carved/

# Step 3: View the embedded image
eog carved/jpg/00000271.jpg
# Flag visible in handwritten text:
# KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}
```

---

## Lessons Learned

- **Filename analysis** is critical in forensics — reversed filenames provide immediate clues about the transform applied.
- **Byte reversal** is a simple but effective obfuscation that defeats standard `file` magic detection.
- **JPEG concatenation** (appending data after `FF D9`) is a common steganographic technique. Tools like `foremost` reliably carve these artifacts.
- **Handwritten flags** introduce intentional OCR ambiguity — multiple candidate submissions may be needed.

---

## Defensive Takeaways

| Technique | Detection |
|---|---|
| Byte reversal | Check for reversed magic bytes (`D9 FF` = reversed JPEG) |
| JPEG concatenation | Scan for multiple `FF D8` markers using `binwalk` or `foremost` |
| Filename obfuscation | Always reverse filenames and check for known extensions |
| Handwriting steganography | Use both OCR and visual inspection; test multiple interpretations |
