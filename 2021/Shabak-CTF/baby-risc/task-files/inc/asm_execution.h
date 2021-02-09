#pragma once
#ifndef __ASM_EXECUTION_H
#define __ASM_EXECUTION_H

#include "asm_types.h"

int execute_asm_file(FILE * fp);
int execute_asm_memory(void * asm_bytes, size_t len);

#endif /* __ASM_EXECUTION_H */
