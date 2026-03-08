---
layout: writeup
title: "Ham44"
challenge: "Ham44"
category: "Android"
difficulty: "Easy"
tags: [apk-reversing, jadx, asset-extraction, android, sqlite]
---

# Challenge Overview

**Ham44** (Hamilton44) is an Android reversing challenge. A clicker-style APK contains a hidden flag in its `assets/metadata.txt` file. Reverse engineering with JADX reveals that `ClickerActivity.getFlag()` reads this file when a counter reaches 67,676,767 — but directly extracting the asset bypasses the clicking entirely.

<div class="flag-box">KICTF{SqLIte_EdITor_67}</div>

---

## Initial Recon

```bash
$ file Hamilton44.apk
Hamilton44.apk: Zip archive data

$ unzip -l Hamilton44.apk | grep assets
assets/metadata.txt
assets/flag_data.dat
assets/flag_data.properties
```

Three interesting asset files. Let's decompile:

```bash
$ jadx -d decompiled/ Hamilton44.apk
```

---

## Vulnerability / Weakness

**Hardcoded flag in application assets (CWE-312):** The flag is stored in plaintext in `assets/metadata.txt`, accessible via simple APK extraction without running the application.

```
┌────────────────────────────────────────────────────────────┐
│                  APK ANALYSIS PIPELINE                      │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Hamilton44.apk (ZIP archive)                              │
│    │                                                       │
│    ├── JADX decompile → source code                        │
│    │   └── ClickerActivity.java                            │
│    │       └── getFlag() {                                 │
│    │             if (counter >= 67676767)                   │
│    │               read("assets/metadata.txt")             │
│    │           }                                           │
│    │                                                       │
│    ├── assets/metadata.txt                                 │
│    │   └── KICTF{SqLIte_EdITor_67}   ← direct access!    │
│    │                                                       │
│    ├── assets/flag_data.dat          ← red herring         │
│    └── assets/flag_data.properties   ← red herring         │
│                                                            │
│  Shortcut: unzip -p Hamilton44.apk assets/metadata.txt     │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Decompile APK with JADX
2. Identify flag-loading logic in `ClickerActivity`
3. Extract `assets/metadata.txt` directly from the APK
4. Investigate `flag_data.dat` and `flag_data.properties` (red herrings)

---

## Exploitation Walkthrough

### Step 1: JADX Decompilation

```java
// ClickerActivity.java (simplified)
public class ClickerActivity extends Activity {
    private int counter = 0;
    
    public void onClick(View v) {
        counter++;
        if (counter >= 67676767) {
            getFlag();
        }
    }
    
    private void getFlag() {
        InputStream is = getAssets().open("metadata.txt");
        // reads and displays flag
    }
}
```

The app requires 67,676,767 clicks to display the flag. But the asset file is accessible without running the app.

### Step 2: Direct Asset Extraction

```bash
$ unzip -p Hamilton44.apk assets/metadata.txt
KICTF{SqLIte_EdITor_67}
```

### Step 3: Investigate Red Herrings

```bash
$ unzip -p Hamilton44.apk assets/flag_data.properties
encoded_flag=<base64_data>
xor_key=<hex_key>

$ unzip -p Hamilton44.apk assets/flag_data.dat
<binary data>
```

Extensive transformation attempts (Base64, XOR, AES) on these files produced no additional valid flag. The `metadata.txt` flag was the accepted answer.

---

## Flag Extraction

```
KICTF{SqLIte_EdITor_67}
```

Extracted directly from `assets/metadata.txt` within the APK archive.

---

## Proof of Concept

```bash
#!/bin/bash
# Ham44 - One-liner solve
unzip -p Hamilton44.apk assets/metadata.txt
# KICTF{SqLIte_EdITor_67}
```

---

## Lessons Learned

- **APK files are ZIP archives** — all assets are directly extractable without running the application or emulator.
- **Game-gate mechanics** (click N times) provide zero security. The underlying data is always accessible via static analysis.
- **Red herring assets** (`flag_data.dat`, `flag_data.properties`) are designed to waste time. Check the simplest extraction path first.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Plaintext secrets in assets | Never store flags/secrets in APK assets; fetch from server |
| Client-side gate | Verify conditions server-side |
| Static asset extraction | Encrypt assets with server-derived keys |
| APK reverse engineering | Use code obfuscation (ProGuard/R8) and integrity checks |
