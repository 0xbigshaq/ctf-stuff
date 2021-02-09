#include <string.h>
#include "asm_processor_state.h"

// The actual stack & registers of the processor
uint8_t asm_stack[ASM_STACK_SIZE] = { 0 };
reg_value_t registers[ASM_REGISTER_END - ASM_REGISTER_START] = { 0 };

void initialize_context(void)
{
    memset(registers, 0, sizeof(registers));
    memset(asm_stack, 0, sizeof(asm_stack));
}

int read_reg(asm_register_t reg, reg_value_t * reg_out)
{
    if (reg < 0 || reg >= sizeof(registers) / sizeof(reg_value_t))
    {
        return E_R_INVLD_REG;
    }

    *reg_out = registers[reg];
    return E_SUCCESS;
}

int write_reg(asm_register_t reg, reg_value_t value)
{
    if (reg < 0 || reg >= sizeof(registers) / sizeof(reg_value_t))
    {
        return E_W_INVLD_REG;
    }
    else if (reg == ASM_REGISTER_ZERO)
    {
        return E_W2ZERO;
    }

    registers[reg] = value;
    return E_SUCCESS;
}
