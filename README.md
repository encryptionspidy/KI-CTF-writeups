# KI-CTF 2025 — Writeup Repository

> **15 challenges solved** across 8 categories.  
> Live site: [https://encryptionspidy.github.io/KI-CTF-writeups/](https://encryptionspidy.github.io/KI-CTF-writeups/)

---

## Challenge Scoreboard

| # | Category | Challenge | Technique | Flag |
|---|----------|-----------|-----------|------|
| 1 | Web | Say My Name | ZIP Slip + OOB Read | `KICTF{stay_out_of_my_t3rr1t0ry}` |
| 2 | Web | In-Voice | SSRF + LFI Chain | `KICTF{ssrf_t3mplate_tr4v3rsal_ch41n}` |
| 3 | Web | Not So Smart | JWT Forgery + GraphQL + Proxy Bypass | `KICTF{sm4rt3rm41l_n0t_s0_sm4rt_4ft3r_4ll}` |
| 4 | Web | Swiss Cheese Filter | Blind Command Injection | `KICTF{CMD_1NJ3CTION}` |
| 5 | Web | Flag Shop | Decimal Truncation Bypass | `KICTF{d3c1m4l_tr1m_byp4ss_ftw}` |
| 6 | Crypto | Rick-ryption Protocol | Hénon Map Seed Leak + Reverse XOR | `KICTF{CH40S_1S_D3T3RM1N1ST1C_1N_F1N1T3_PR3C1S10N}` |
| 7 | Crypto | Ancient Script | PDF Cluster → Substitution Cipher | `KICTF{whiskersandwings}` |
| 8 | Forensics | Childhood Photo | Byte Reversal + JPEG Carving | `KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}` |
| 9 | Forensics | Corrupted Vision | Multi-Stage Steganography | `KICTF{y0u_f1nd_th3_c0rrupt3d_0n3}` |
| 10 | Rev Eng | Shadow | CRX + AES-CBC Decryption | `KICTF{_my_own_CHR0om_extention_}` |
| 11 | Rev Eng | Tralalero Tralala | Pickle Layers + Constraint Solving | `KICTF{H4v3_Y0u_3v3r_S0lv3d_4ll_0f_th3_KICTF_ch4ll3ng3s!!_}` |
| 12 | PWN | Hop Bob | JOP Chain Exploitation | `KICTF{n0_r0p_h3r3_j0p_0nly_1337}` |
| 13 | PWN | Ghost Stack | PIE Leak + Pointer Overwrite | `KICTF{gh0st_st4ck_d0p_m4st3r}` |
| 14 | AI | The Manchurian Candidate | Neural Backdoor Detection | `KICTF{silent_vector}` |
| 15 | Android | Ham44 | JADX + SQLite Asset Extraction | `KICTF{SqLIte_EdITor_67}` |
| 16 | Misc | QR | Image Reassembly + Base64 | `KICTF{hello_bro}` |

---

## Repository Structure

```
docs/
├── _config.yml                 # Jekyll configuration
├── _layouts/
│   ├── default.html            # Base layout with nav & search
│   └── writeup.html            # Challenge writeup layout
├── assets/css/style.scss       # Dark hacker theme
├── index.md                    # Homepage with challenge grid
└── ctf/KI-CTF-2025/
    ├── web/                    # 5 web writeups
    ├── crypto/                 # 2 cryptography writeups
    ├── forensics/              # 2 forensics writeups
    ├── rev/                    # 2 reverse engineering writeups
    ├── pwn/                    # 2 binary exploitation writeups
    ├── ai/                     # 1 AI/ML writeup
    ├── android/                # 1 Android writeup
    └── misc/                   # 1 miscellaneous writeup
```

---

## Local Development

```bash
# Prerequisites: Ruby ≥ 2.7, Bundler
cd docs
bundle init
bundle add github-pages
bundle exec jekyll serve
# → http://localhost:4000/KI-CTF-writeups/
```

---

## Deployment

GitHub Pages is configured to serve from the `docs/` folder on the `main` branch. Pushing to `main` triggers automatic deployment.

---

## Author

**encryptionspidy** — KI-CTF 2025
