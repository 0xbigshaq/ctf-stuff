#pragma once
#ifndef __COMMON_H
#define __COMMON_H

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

typedef enum error_code_e
{
    E_SUCCESS = 0,
    E_IVLD_ARGS,
    E_INVLD_OPCODE,
    E_DIV_ZERO,
    E_W2ZERO,
    E_FOPEN,
    E_FREAD,
    E_FWRITE,
    E_FTELL,
    E_NOMEM,
    E_READ_IMM32,
    E_READ_REG,
    E_READ_OPCODE,
    E_FD_ZERO,
    E_NOT_IMPL_INSTR,
    E_R_INVLD_REG,
    E_W_INVLD_REG,
    E_STACK_VIOLATION,
    E_EOF,
    E_RETURN,
    E_ADMIN_CODE_ERR,
} error_code_t;

#endif /* __COMMON_H */
