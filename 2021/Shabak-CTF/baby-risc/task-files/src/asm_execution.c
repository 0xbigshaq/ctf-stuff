#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "asm_types.h"
#include "asm_execution.h"
#include "asm_processor_state.h"
#include "asm_file_parsing.h"
#include "asm_instructions.h"
#include "common.h"
#include "prompt.h"

static int parse_exec_asm_file(FILE * fp, int * count_out)
{
    int ret = E_SUCCESS;
    if (fp == NULL)
    {
        ret = E_FOPEN;
        goto cleanup;
    }

    // Init context
    initialize_context();

    // Fetch-decode-execute instructions loop
    asm_opcode_t opcode;
    int inst_count = 0;
    while (!feof(fp))
    {
        ret = file_parse_opcode(fp, &opcode);
        if (ret != E_SUCCESS)
        {
            break;
        }
        inst_count++;

        if (opcode >= MAX_ASM_OPCODE_VAL || opcode < 0)
        {
            ret = E_INVLD_OPCODE;
            break;
        }

        ret = asm_instruction_definitions[opcode](fp);
        if (ret != E_SUCCESS)
        {
            break;
        }
    }

    // If we exited the loop because RET/RETNZ instruction, we want to report success
    if (ret == E_RETURN)
    {
        ret = E_SUCCESS;
    }

cleanup:
    if (count_out)
    {
        *count_out = inst_count;
    }
    return ret;
}

int execute_asm_file(FILE * fp)
{
    int ret = E_SUCCESS;
    int count = 0;

    ret = parse_exec_asm_file(fp, &count);
    PROMPT_PRINTF("executed 0x%X instructions\n\n", count);
    return ret;
}

int execute_asm_memory(void * asm_bytes, size_t len)
{
    int ret = E_SUCCESS;
    FILE * fp = NULL;
    fp = fmemopen(asm_bytes, len, "r");
    if (fp == NULL)
    {
        ret = -1;
        goto cleanup;
    }

    ret = execute_asm_file(fp);

cleanup:
    if (fp != NULL)
    {
        fclose(fp);
    }
    return ret;
}
