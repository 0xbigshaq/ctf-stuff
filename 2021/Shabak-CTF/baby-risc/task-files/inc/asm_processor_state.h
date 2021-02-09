
#pragma once
#ifndef __ASM_PROCESSOR_STATE_H
#define __ASM_PROCESSOR_STATE_H

#include "asm_types.h"
#include "common.h"

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

void initialize_context(void);
int read_reg(asm_register_t reg, reg_value_t * reg_out);
int write_reg(asm_register_t reg, reg_value_t value);

#endif /* __ASM_PROCESSOR_STATE_H */
