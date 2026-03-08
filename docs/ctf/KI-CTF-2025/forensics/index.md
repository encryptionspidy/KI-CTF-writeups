---
layout: default
title: "Forensics Challenges"
---

# Forensics

*2 challenges solved — file format forensics, steganography, and multi-stage artifact chains.*

---

| Challenge | Technique | Difficulty |
|-----------|-----------|------------|
| [Childhood Photo](childhood-photo) | Byte Reversal + JPEG Carving + Handwriting OCR | Medium |
| [Corrupted Vision](corrupted-vision) | LSB Stego → Drive Pivot → PNG Repair → Font Matching | Hard |

---

### Techniques Covered

- **Byte-order analysis** — identifying reversed magic bytes for file recovery
- **JPEG carving** — extracting concatenated images with `foremost`
- **LSB steganography** — `zsteg` extraction of hidden payloads
- **PNG chunk repair** — fixing corrupted signatures, chunk types, and CRCs
- **Component-based OCR** — deterministic glyph matching with known fonts
- **Multi-artifact investigation chains** — systematic pivot from decoy to real evidence

<p style="text-align:center; margin-top: 2rem;"><a href="{{ site.baseurl }}/">← Back to Home</a></p>
