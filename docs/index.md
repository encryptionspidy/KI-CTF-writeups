---
layout: default
title: "KI CTF 2025 Writeups"
---

<div style="text-align: center; margin-bottom: 2rem;">

# KI CTF 2025 Writeups

<p style="color: var(--text-secondary); font-size: 1rem; max-width: 640px; margin: 0 auto;">
Competition-level CTF writeups — technically precise, reproducible, and educational.<br>
15 challenges solved across 8 categories.
</p>

</div>

---

<div class="stats-banner">
  <div class="stat-item">
    <span class="stat-number">15</span>
    <span class="stat-label">Solved</span>
  </div>
  <div class="stat-item">
    <span class="stat-number">8</span>
    <span class="stat-label">Categories</span>
  </div>
  <div class="stat-item">
    <span class="stat-number">5</span>
    <span class="stat-label">Web</span>
  </div>
  <div class="stat-item">
    <span class="stat-number">2</span>
    <span class="stat-label">Crypto</span>
  </div>
  <div class="stat-item">
    <span class="stat-number">2</span>
    <span class="stat-label">Forensics</span>
  </div>
  <div class="stat-item">
    <span class="stat-number">2</span>
    <span class="stat-label">PWN</span>
  </div>
</div>

---

## Search Writeups

<input type="text" class="search-box" placeholder="$ grep -i 'keyword' writeups/*" id="search">

## Filter by Category

<span class="tag" data-category="" onclick="filterAll()">All</span>
<span class="tag badge-web" data-category="web">Web</span>
<span class="tag badge-crypto" data-category="crypto">Crypto</span>
<span class="tag badge-forensics" data-category="forensics">Forensics</span>
<span class="tag badge-rev" data-category="rev">Rev</span>
<span class="tag badge-pwn" data-category="pwn">PWN</span>
<span class="tag badge-ai" data-category="ai">AI</span>
<span class="tag badge-android" data-category="android">Android</span>
<span class="tag badge-misc" data-category="misc">Misc</span>

---

## All Challenges

<div class="challenge-grid">

<div class="challenge-card" data-category="web">
  <span class="category-badge badge-web">Web</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/web/say-my-name">Say My Name</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">ZIP Slip + OOB memory leak to exfiltrate environment flag</p>
  <span class="tag">zip-slip</span> <span class="tag">oob-read</span> <span class="tag">flask</span>
</div>

<div class="challenge-card" data-category="web">
  <span class="category-badge badge-web">Web</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/web/in-voice">In-voice</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">SSRF denylist bypass + path traversal LFI chain</p>
  <span class="tag">ssrf</span> <span class="tag">lfi</span> <span class="tag">filter-bypass</span>
</div>

<div class="challenge-card" data-category="web">
  <span class="category-badge badge-web">Web</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/web/not-so-smart">Not So Smart</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">JWT forgery + GraphQL + SSRF proxy — 3-part flag reconstruction</p>
  <span class="tag">jwt</span> <span class="tag">graphql</span> <span class="tag">proxy-abuse</span>
</div>

<div class="challenge-card" data-category="web">
  <span class="category-badge badge-web">Web</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/web/swiss-cheese-filter">The Swiss Cheese Filter</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Blind OS command injection via newline + tab bypass</p>
  <span class="tag">command-injection</span> <span class="tag">blind</span> <span class="tag">filter-bypass</span>
</div>

<div class="challenge-card" data-category="web">
  <span class="category-badge badge-web">Web</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/web/flag-shop">Flag Shop</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Decimal truncation exploit in interactive currency shop</p>
  <span class="tag">logic-bug</span> <span class="tag">math-exploit</span> <span class="tag">truncation</span>
</div>

<div class="challenge-card" data-category="crypto">
  <span class="category-badge badge-crypto">Crypto</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/crypto/rick-ryption-protocol">Rick-ryption Protocol</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Hénon map chaos crypto broken via PNG metadata seed leak</p>
  <span class="tag">chaos-map</span> <span class="tag">seed-leak</span> <span class="tag">png-metadata</span>
</div>

<div class="challenge-card" data-category="crypto">
  <span class="category-badge badge-crypto">Crypto</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/crypto/ancient-script">Ancient Script</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">PDF visual substitution cipher — glyph extraction and decode</p>
  <span class="tag">substitution</span> <span class="tag">pdf-analysis</span> <span class="tag">frequency</span>
</div>

<div class="challenge-card" data-category="forensics">
  <span class="category-badge badge-forensics">Forensics</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/forensics/childhood-photo">Childhood Photo</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Byte-reversed JPEG with embedded handwritten flag image</p>
  <span class="tag">byte-reversal</span> <span class="tag">jpeg-carving</span> <span class="tag">foremost</span>
</div>

<div class="challenge-card" data-category="forensics">
  <span class="category-badge badge-forensics">Forensics</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/forensics/corrupted-vision">Corrupted Vision</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Multi-stage: LSB stego → Drive pivot → PNG repair → font matching</p>
  <span class="tag">lsb-stego</span> <span class="tag">png-repair</span> <span class="tag">multi-stage</span>
</div>

<div class="challenge-card" data-category="rev">
  <span class="category-badge badge-rev">Rev</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/rev/shadow">Shadow</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Binary → CRX extraction → AES-CBC decryption with IV brute-force</p>
  <span class="tag">binary-reversing</span> <span class="tag">chrome-ext</span> <span class="tag">aes-cbc</span>
</div>

<div class="challenge-card" data-category="rev">
  <span class="category-badge badge-rev">Rev</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/rev/tralalero-tralala">tralalero_tralala</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Pickle → Base85 → gzip → marshal bytecode → constraint solving</p>
  <span class="tag">pickle</span> <span class="tag">bytecode</span> <span class="tag">constraint-solving</span>
</div>

<div class="challenge-card" data-category="pwn">
  <span class="category-badge badge-pwn">PWN</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/pwn/hop-bob">hop_bob</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">JOP chain on static non-PIE binary — execve("/bin/sh")</p>
  <span class="tag">jop</span> <span class="tag">stack-overflow</span> <span class="tag">syscall</span>
</div>

<div class="challenge-card" data-category="pwn">
  <span class="category-badge badge-pwn">PWN</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/pwn/ghost-stack">Ghost Stack</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">PIE leak via stack dump + function pointer overwrite → win()</p>
  <span class="tag">pie-leak</span> <span class="tag">callback-overwrite</span> <span class="tag">struct-overflow</span>
</div>

<div class="challenge-card" data-category="ai">
  <span class="category-badge badge-ai">AI</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/ai/manchurian-candidate">The Manchurian Candidate</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">NLP backdoor trigger detection via corpus co-occurrence analysis</p>
  <span class="tag">data-poisoning</span> <span class="tag">nlp</span> <span class="tag">backdoor</span>
</div>

<div class="challenge-card" data-category="android">
  <span class="category-badge badge-android">Android</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/android/ham44">Ham44</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">APK decompilation + direct asset extraction</p>
  <span class="tag">apk</span> <span class="tag">jadx</span> <span class="tag">asset-extraction</span>
</div>

<div class="challenge-card" data-category="misc">
  <span class="category-badge badge-misc">Misc</span>
  <h3><a href="{{ site.baseurl }}/ctf/KI-CTF-2025/misc/qr">QR</a></h3>
  <p style="color: var(--text-secondary); font-size: 0.85rem;">Binary matrix → QR image reconstruction → base64 decode</p>
  <span class="tag">qr-code</span> <span class="tag">image-reconstruction</span> <span class="tag">base64</span>
</div>

</div>

---

## Solved Challenges Summary

| # | Category | Challenge | Technique | Flag |
|---|----------|-----------|-----------|------|
| 1 | Web | [Say My Name]({{ site.baseurl }}/ctf/KI-CTF-2025/web/say-my-name) | ZIP Slip + OOB Read | `KICTF{stay_out_of_my_t3rr1t0ry}` |
| 2 | Web | [In-voice]({{ site.baseurl }}/ctf/KI-CTF-2025/web/in-voice) | SSRF + LFI | `KICTF{ssrf_t3mplate_tr4v3rsal_ch41n}` |
| 3 | Web | [Not So Smart]({{ site.baseurl }}/ctf/KI-CTF-2025/web/not-so-smart) | JWT + GraphQL + Proxy | `KICTF{sm4rt3rm41l_n0t_s0_sm4rt_4ft3r_4ll}` |
| 4 | Web | [Swiss Cheese Filter]({{ site.baseurl }}/ctf/KI-CTF-2025/web/swiss-cheese-filter) | Blind Cmd Injection | `KICTF{CMD_1NJ3CTION}` |
| 5 | Web | [Flag Shop]({{ site.baseurl }}/ctf/KI-CTF-2025/web/flag-shop) | Decimal Truncation | `KICTF{d3c1m4l_tr1m_byp4ss_ftw}` |
| 6 | Crypto | [Rick-ryption Protocol]({{ site.baseurl }}/ctf/KI-CTF-2025/crypto/rick-ryption-protocol) | Chaos Map Seed Leak | `KICTF{CH40S_1S_D3T3RM1N1ST1C_...}` |
| 7 | Crypto | [Ancient Script]({{ site.baseurl }}/ctf/KI-CTF-2025/crypto/ancient-script) | PDF Substitution Cipher | `KICTF{whiskersandwings}` |
| 8 | Forensics | [Childhood Photo]({{ site.baseurl }}/ctf/KI-CTF-2025/forensics/childhood-photo) | Byte Reversal + Carving | `KICTF{r3v3rs3d_jp3g_h34d3r_f1x3d}` |
| 9 | Forensics | [Corrupted Vision]({{ site.baseurl }}/ctf/KI-CTF-2025/forensics/corrupted-vision) | Multi-stage Stego Chain | `KICTF{y0u_f1nd_th3_c0rrupt3d_0n3}` |
| 10 | Rev | [Shadow]({{ site.baseurl }}/ctf/KI-CTF-2025/rev/shadow) | Binary + CRX + AES | `KICTF{_my_own_CHR0om_extention_}` |
| 11 | Rev | [tralalero_tralala]({{ site.baseurl }}/ctf/KI-CTF-2025/rev/tralalero-tralala) | Pickle + Constraint Solve | `KICTF{H4v3_Y0u_3v3r_S0lv3d_...}` |
| 12 | PWN | [hop_bob]({{ site.baseurl }}/ctf/KI-CTF-2025/pwn/hop-bob) | JOP Chain | `KICTF{n0_r0p_h3r3_j0p_0nly_1337}` |
| 13 | PWN | [Ghost Stack]({{ site.baseurl }}/ctf/KI-CTF-2025/pwn/ghost-stack) | PIE Leak + Ptr Overwrite | `KICTF{gh0st_st4ck_d0p_m4st3r}` |
| 14 | AI | [Manchurian Candidate]({{ site.baseurl }}/ctf/KI-CTF-2025/ai/manchurian-candidate) | Backdoor Trigger Detection | `KICTF{silent_vector}` |
| 15 | Android | [Ham44]({{ site.baseurl }}/ctf/KI-CTF-2025/android/ham44) | APK Asset Extraction | `KICTF{SqLIte_EdITor_67}` |
| 16 | Misc | [QR]({{ site.baseurl }}/ctf/KI-CTF-2025/misc/qr) | QR Reconstruction | `KICTF{hello_bro}` |

---

<p style="text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 3rem;">
  Built for the KI CTF 2025 Writeup Prize &bull; <a href="https://github.com/encryptionspidy/KI-CTF-writeups">Source</a>
</p>

<script>
document.addEventListener('DOMContentLoaded', function() {
  const search = document.getElementById('search');
  const cards = document.querySelectorAll('.challenge-card');
  
  if (search) {
    search.addEventListener('input', function() {
      const q = this.value.toLowerCase();
      cards.forEach(c => {
        c.style.display = c.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
});

function filterAll() {
  document.querySelectorAll('.challenge-card').forEach(c => c.style.display = '');
}

document.querySelectorAll('.tag[data-category]').forEach(tag => {
  tag.addEventListener('click', function() {
    const cat = this.dataset.category;
    if (!cat) { filterAll(); return; }
    document.querySelectorAll('.challenge-card').forEach(c => {
      c.style.display = c.dataset.category === cat ? '' : 'none';
    });
  });
});
</script>
