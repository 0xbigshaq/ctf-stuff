#include <stdio.h>
#include "asm_file_generation.h"
#include "asm_types.h"
#include "common.h"

static int file_write_reg(FILE * fp, asm_register_t reg)
{
    int ret = E_SUCCESS;
    if (fwrite(&reg, sizeof(reg_t), 1, fp) != 1)
    {
        ret = E_FWRITE;
        goto cleanup;
    }

cleanup:
    return ret;
}

int file_write_opcode(FILE * fp, asm_opcode_t opcode)
{
    int ret = E_SUCCESS;
    if (fwrite(&opcode, sizeof(opcode_t), 1, fp) != 1)
    {
        ret = E_FWRITE;
        goto cleanup;
    }

cleanup:
    return ret;
}

int file_write_opcode1(FILE * fp, asm_opcode_t opcode, asm_register_t reg0)
{
    int ret = E_SUCCESS;

    ret = file_write_opcode(fp, opcode);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    ret = file_write_reg(fp, reg0);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

int file_write_opcode2(FILE * fp, asm_opcode_t opcode, asm_register_t reg0, asm_register_t reg1)
{
    int ret = E_SUCCESS;

    ret = file_write_opcode1(fp, opcode, reg0);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    ret = file_write_reg(fp, reg1);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

int file_write_opcode3(FILE * fp, asm_opcode_t opcode, asm_register_t reg0, asm_register_t reg1, asm_register_t reg2)
{
    int ret = E_SUCCESS;

    ret = file_write_opcode2(fp, opcode, reg0, reg1);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    ret = file_write_reg(fp, reg2);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

int file_write_opcode_imm32(FILE * fp, asm_opcode_t opcode, asm_register_t reg0, asm_register_t reg1, int32_t imm2)
{
    int ret = E_SUCCESS;

    ret = file_write_opcode2(fp, opcode, reg0, reg1);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (fwrite(&imm2, sizeof(int32_t), 1, fp) != 1)
    {
        ret = E_FWRITE;
        goto cleanup;
    }

cleanup:
    return ret;
}
