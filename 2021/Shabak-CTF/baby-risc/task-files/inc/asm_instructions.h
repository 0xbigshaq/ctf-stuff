#pragma once
#ifndef __ASM_INSTRUCTIONS_H
#define __ASM_INSTRUCTIONS_H

#include <stdio.h>
#include "asm_types.h"

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

typedef int (*instruction_definition_t)(FILE * fp);
extern instruction_definition_t asm_instruction_definitions[MAX_ASM_OPCODE_VAL];

#endif /* __ASM_INSTRUCTIONS_H */
