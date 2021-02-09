#pragma once
#ifndef __ASM_FILE_GENERATION_H
#define __ASM_FILE_GENERATION_H

#include "asm_types.h"
#include "asm_processor_state.h"
#include "asm_instructions.h"
#include "common.h"

int file_write_opcode(FILE * fp, asm_opcode_t opcode);
int file_write_opcode1(FILE * fp, asm_opcode_t opcode, asm_register_t reg0);
int file_write_opcode2(FILE * fp, asm_opcode_t opcode, asm_register_t reg0, asm_register_t reg1);
int file_write_opcode3(FILE * fp, asm_opcode_t opcode, asm_register_t reg0, asm_register_t reg1, asm_register_t reg2);
int file_write_opcode_imm32(FILE * fp, asm_opcode_t opcode, asm_register_t reg0, asm_register_t reg1, int32_t imm2);

#endif /* __ASM_FILE_GENERATION_H */
