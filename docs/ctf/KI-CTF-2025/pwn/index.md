---
layout: default
title: "PWN Challenges"
---

# Binary Exploitation (PWN)

*2 challenges solved — jump-oriented programming and struct-based pointer hijacking.*

---

| Challenge | Technique | Difficulty |
|-----------|-----------|------------|
| [hop_bob](hop-bob) | JOP Chain on Static Non-PIE Binary → execve | Hard |
| [Ghost Stack](ghost-stack) | PIE Leak via Stack Dump + Function Pointer Overwrite | Hard |

---

### Techniques Covered

- **Jump-Oriented Programming (JOP)** — alternative to ROP using `jmp [reg]` dispatch
- **Stack buffer overflow** — controlling RIP via unprotected read operations
- **Uninitialized memory leaks** — extracting PIE base addresses from diagnostic dumps
- **Struct field overflow** — overflowing into adjacent function pointers via `strcpy`
- **Canary bypass** — exploiting struct layout rather than stack frames
- **syscall construction** — building `execve("/bin/sh", 0, 0)` from gadgets

<p style="text-align:center; margin-top: 2rem;"><a href="{{ site.baseurl }}/">← Back to Home</a></p>
