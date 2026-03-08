---
layout: default
title: "Web Challenges"
---

# Web Exploitation

*5 challenges solved — SSRF, injection, JWT forgery, logic bugs, and more.*

---

| Challenge | Technique | Difficulty |
|-----------|-----------|------------|
| [Say My Name](say-my-name) | ZIP Slip + OOB Memory Leak | Hard |
| [In-voice](in-voice) | SSRF Denylist Bypass + Path Traversal LFI | Medium |
| [Not So Smart](not-so-smart) | JWT Forgery + GraphQL + SSRF Proxy Chain | Hard |
| [The Swiss Cheese Filter](swiss-cheese-filter) | Blind OS Command Injection | Medium |
| [Flag Shop](flag-shop) | Decimal Truncation Logic Bug | Easy |

---

### Techniques Covered

- **Server-Side Request Forgery** — IP denylist bypass via alternate loopback representations
- **Path Traversal** — `str_replace` bypass with overlapping `....//` payloads
- **ZIP Slip** — archive path traversal for arbitrary file write
- **Command Injection** — newline/tab-based filter bypass for blind injection
- **JWT Forgery** — weak HS256 secret exploitation
- **GraphQL Introspection** — information disclosure via admin queries
- **Decimal Truncation** — floating-point arithmetic exploit in financial logic

<p style="text-align:center; margin-top: 2rem;"><a href="{{ site.baseurl }}/">← Back to Home</a></p>
