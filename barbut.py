#!/usr/bin/env python3
# ============================================================================
# CTF: barbut — joc de zaruri (nu corupere de memorie)
# Vulnerabilitate: logica de joc / PRNG previzibil. Trebuie sa castigi 25 de
#   runde ca sa afle flag-ul; main face srand(time())+rand(), iar random_choice
#   reseteaza seed-ul, asa ca alegand mereu acelasi numar ("18") castigi toate
#   rundele determinist. Exploit: trimite 18 + "yes" de ~27 ori, apoi citeste flag.
# Binar: ELF 32-bit (i386), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - Protectiile nu conteaza aici: nu se exploateaza stiva, doar logica jocului.
# ============================================================================
import sys, re
from pwn import *

context.binary = elf = ELF('./barbut')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    # remote doar daca ai dat HOST + PORT numeric; altfel proces local
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./barbut')

p = connect()

p.recvuntil(b"If you beat me 25 times in dice game (10 dices) I will tell you my flag")

for _ in range(27):
    p.recvuntil(b"Choose your lucky number")
    p.sendline(b'18')
    p.recvuntil(b"Ready?")
    p.sendline(b'yes')

out = p.recvall(timeout=2)
# cauta un flag care incepe cu CTF, SI sau FLAG; daca nu-l gaseste, arata output-ul brut
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)
print(flag.group().decode() if flag else out)
