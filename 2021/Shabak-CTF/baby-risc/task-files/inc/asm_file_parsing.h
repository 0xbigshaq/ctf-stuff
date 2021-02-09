#pragma once
#ifndef __ASM_FILE_PARSING_H
#define __ASM_FILE_PARSING_H

#include "asm_processor_state.h"
#include "asm_types.h"
#include "asm_instructions.h"
#include "common.h"

int file_parse_imm32(FILE * fp, int32_t * imm32_out);
int file_parse_reg(FILE * fp, asm_register_t * reg_out);
int file_parse_opcode(FILE * fp, asm_opcode_t * opcode_out);

#endif /* __ASM_FILE_PARSING_H */
