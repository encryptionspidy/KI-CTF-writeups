---
layout: default
title: "Reverse Engineering Challenges"
---

# Reverse Engineering

*2 challenges solved — multi-layer binary analysis, bytecode deobfuscation, and constraint solving.*

---

| Challenge | Technique | Difficulty |
|-----------|-----------|------------|
| [Shadow](shadow) | Binary Password Recovery → CRX Extraction → AES-CBC Decrypt | Hard |
| [tralalero_tralala](tralalero-tralala) | Pickle → Base85 → gzip → Marshal Bytecode → Constraint Solving | Hard |

---

### Techniques Covered

- **Arithmetic transform inversion** — reversing invertible byte-level password checks
- **Chrome Extension (CRX) analysis** — unpacking and analyzing browser extension payloads
- **AES-CBC with constrained IV** — brute-forcing small IV search space
- **Python pickle deserialization** — safe unpacking of potentially dangerous pickle files
- **Marshal bytecode analysis** — disassembling Python code objects
- **Decoy validator identification** — distinguishing real constraints from 115 fake ones
- **Multi-constraint solving** — CRC32 + MD5 + XOR + RC4 combined constraint satisfaction

<p style="text-align:center; margin-top: 2rem;"><a href="{{ site.baseurl }}/">← Back to Home</a></p>
