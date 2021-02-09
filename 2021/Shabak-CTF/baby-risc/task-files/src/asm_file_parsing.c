#include "asm_file_parsing.h"
#include "asm_instructions.h"

int file_parse_imm32(FILE * fp, int32_t * imm32_out)
{
    int ret = E_SUCCESS;
    int32_t imm32;
    if (fread(&imm32, sizeof(imm32), 1, fp) != 1)
    {
        ret = E_READ_IMM32;
        goto cleanup;
    }

    *imm32_out = imm32;

cleanup:
    return ret;
}

int file_parse_reg(FILE * fp, asm_register_t * reg_out)
{
    int ret = E_SUCCESS;
    reg_t reg;
    if (fread(&reg, sizeof(reg), 1, fp) != 1)
    {
        ret = E_READ_REG;
        goto cleanup;
    }

    *reg_out = (asm_register_t)reg;

cleanup:
    return ret;
}

int file_parse_opcode(FILE * fp, asm_opcode_t * opcode_out)
{
    int ret = E_SUCCESS;
    opcode_t opcode;
    if (fread(&opcode, sizeof(opcode), 1, fp) != 1)
    {
        ret = E_READ_OPCODE;
        goto cleanup;
    }

    *opcode_out = (asm_opcode_t)opcode;

cleanup:
    return ret;
}
