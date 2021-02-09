#include "asm_instructions.h"
#include "asm_processor_state.h"
#include "asm_file_parsing.h"
#include "string.h"

#define _rotl(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define _rotr(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

// The INSTRUCTION_DEFINE_BINARY_* macros below allow you to quickly define binary operations without
// implementing any code yourself. Just pass the "operator" to be applied.

// Define binary operation (which is: "reg0 = reg1 (op) reg2")
// Here just pass the 'operator' as the (op) being made
#define INSTRUCTION_DEFINE_BINARY_OP(opcode, operator)                                                                 \
    INSTRUCTION_DEFINE_OP3(opcode)                                                                                     \
    {                                                                                                                  \
        int ret = E_SUCCESS;                                                                                           \
        reg_value_t value1 = 0;                                                                                        \
        reg_value_t value2 = 0;                                                                                        \
        ret = read_reg(reg1, &value1);                                                                                 \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
                                                                                                                       \
        ret = read_reg(reg2, &value2);                                                                                 \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
                                                                                                                       \
        value1 = (value1) operator(value2);                                                                            \
                                                                                                                       \
        ret = write_reg(reg0, value1);                                                                                 \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
                                                                                                                       \
    cleanup:                                                                                                           \
        return ret;                                                                                                    \
    }

// Define binary 32-bit immediate operation (which is: "reg0 = reg1 (op) imm32")
// Here just pass the 'operator' as the (op) being made
#define INSTRUCTION_DEFINE_BINARY_IMM32_OP(opcode, operator)                                                           \
    INSTRUCTION_DEFINE_OP_IMM32(opcode)                                                                                \
    {                                                                                                                  \
        int ret = E_SUCCESS;                                                                                           \
        reg_value_t value = 0;                                                                                         \
        ret = read_reg(reg1, &value);                                                                                  \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
                                                                                                                       \
        value = (value) operator(imm32);                                                                               \
                                                                                                                       \
        ret = write_reg(reg0, value);                                                                                  \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
                                                                                                                       \
    cleanup:                                                                                                           \
        return ret;                                                                                                    \
    }

// Each of the INSTRUCTION_DEFINE_OP* macros below allow you to define new instructions.
// The effect of using these macros is generating a new symbol "__INSTRUCTION_DEFINE_(opcode)", which contains
// the implementation for the opcode itself. The code you will write after the invocation will be the
// "__INSTRUCTION_IMPL_(opcode)" symbol, which gets as parameters the registers / immediate of the instruction.

// Define instruction with no operands
#define INSTRUCTION_DEFINE_OP0(opcode)                                                                                 \
    static int __INSTRUCTION_IMPL_##opcode(void);                                                                      \
    static int __INSTRUCTION_DEFINE_##opcode(FILE * fp)                                                                \
    {                                                                                                                  \
        (void)fp;                                                                                                      \
        int ret = E_SUCCESS;                                                                                           \
        ret = __INSTRUCTION_IMPL_##opcode();                                                                           \
        return ret;                                                                                                    \
    }                                                                                                                  \
    static int __INSTRUCTION_IMPL_##opcode(void)

// Define instruction with a single register operand
#define INSTRUCTION_DEFINE_OP1(opcode)                                                                                 \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0);                                                       \
    static int __INSTRUCTION_DEFINE_##opcode(FILE * fp)                                                                \
    {                                                                                                                  \
        int ret = E_SUCCESS;                                                                                           \
        asm_register_t reg0;                                                                                           \
        ret = file_parse_reg(fp, &reg0);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = __INSTRUCTION_IMPL_##opcode(reg0);                                                                       \
    cleanup:                                                                                                           \
        return ret;                                                                                                    \
    }                                                                                                                  \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0)

// Define instruction with two registers operand
#define INSTRUCTION_DEFINE_OP2(opcode)                                                                                 \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0, asm_register_t reg1);                                  \
    static int __INSTRUCTION_DEFINE_##opcode(FILE * fp)                                                                \
    {                                                                                                                  \
        int ret = E_SUCCESS;                                                                                           \
        asm_register_t reg0;                                                                                           \
        asm_register_t reg1;                                                                                           \
        ret = file_parse_reg(fp, &reg0);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = file_parse_reg(fp, &reg1);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = __INSTRUCTION_IMPL_##opcode(reg0, reg1);                                                                 \
    cleanup:                                                                                                           \
        return ret;                                                                                                    \
    }                                                                                                                  \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0, asm_register_t reg1)

// Define instruction with three registers operand
#define INSTRUCTION_DEFINE_OP3(opcode)                                                                                 \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0, asm_register_t reg1, asm_register_t reg2);             \
    static int __INSTRUCTION_DEFINE_##opcode(FILE * fp)                                                                \
    {                                                                                                                  \
        int ret = E_SUCCESS;                                                                                           \
        asm_register_t reg0;                                                                                           \
        asm_register_t reg1;                                                                                           \
        asm_register_t reg2;                                                                                           \
        ret = file_parse_reg(fp, &reg0);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = file_parse_reg(fp, &reg1);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = file_parse_reg(fp, &reg2);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = __INSTRUCTION_IMPL_##opcode(reg0, reg1, reg2);                                                           \
    cleanup:                                                                                                           \
        return ret;                                                                                                    \
    }                                                                                                                  \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0, asm_register_t reg1, asm_register_t reg2)

// Define instruction with two registers operands and a single 32-bit immediate
#define INSTRUCTION_DEFINE_OP_IMM32(opcode)                                                                            \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0, asm_register_t reg1, int32_t imm32);                   \
    static int __INSTRUCTION_DEFINE_##opcode(FILE * fp)                                                                \
    {                                                                                                                  \
        int ret = E_SUCCESS;                                                                                           \
        asm_register_t reg0;                                                                                           \
        asm_register_t reg1;                                                                                           \
        int32_t imm32;                                                                                                 \
        ret = file_parse_reg(fp, &reg0);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = file_parse_reg(fp, &reg1);                                                                               \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = file_parse_imm32(fp, &imm32);                                                                            \
        if (ret != E_SUCCESS)                                                                                          \
        {                                                                                                              \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        ret = __INSTRUCTION_IMPL_##opcode(reg0, reg1, imm32);                                                          \
    cleanup:                                                                                                           \
        return ret;                                                                                                    \
    }                                                                                                                  \
    static int __INSTRUCTION_IMPL_##opcode(asm_register_t reg0, asm_register_t reg1, int32_t imm32)

// Actually define all the binary operations
INSTRUCTION_DEFINE_BINARY_OP(AND, &)
INSTRUCTION_DEFINE_BINARY_OP(ADD, +)
INSTRUCTION_DEFINE_BINARY_OP(XOR, ^)
INSTRUCTION_DEFINE_BINARY_OP(SUB, -)
INSTRUCTION_DEFINE_BINARY_OP(MUL, *)
INSTRUCTION_DEFINE_BINARY_OP(OR, |)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(ANDI, &)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(ADDI, +)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(XORI, ^)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(SUBI, -)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(MULI, *)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(ORI, |)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(SHR, >>)
INSTRUCTION_DEFINE_BINARY_IMM32_OP(SHL, <<)

// Actually define all other instructions

INSTRUCTION_DEFINE_OP0(PRINTNL)
{
    printf("\n");
    return E_SUCCESS;
}

INSTRUCTION_DEFINE_OP1(PRINTDX)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg0, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    printf("%x", value);

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP1(PRINTDD)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg0, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    printf("%d", value);

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP1(PRINTC)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg0, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    printf("%c", value & 0xff);

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP0(RET)
{
    return E_RETURN;
}

INSTRUCTION_DEFINE_OP1(RETNZ)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg0, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (value != 0)
    {
        ret = E_RETURN;
    }

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP1(RETZ)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg0, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (value == 0)
    {
        ret = E_RETURN;
    }

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP1(PUSH)
{
    int ret = E_SUCCESS;
    reg_value_t reg_val = 0;
    reg_value_t sp_val = 0;
    ret = read_reg(reg0, &reg_val);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    ret = read_reg(ASM_REGISTER_SP, &sp_val);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (sp_val < (reg_value_t)0 || sp_val > (reg_value_t)(ASM_STACK_SIZE - sizeof(reg_val)))
    {
        ret = E_STACK_VIOLATION;
        goto cleanup;
    }
    memcpy(&asm_stack[sp_val], &reg_val, sizeof(reg_val));
    ret = write_reg(ASM_REGISTER_SP, sp_val + sizeof(reg_val));

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP1(POP)
{
    int ret = E_SUCCESS;
    reg_value_t reg_val = 0;
    reg_value_t sp_val = 0;

    ret = read_reg(ASM_REGISTER_SP, &sp_val);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (sp_val < (reg_value_t)sizeof(reg_val) || sp_val > (reg_value_t)ASM_STACK_SIZE)
    {
        ret = E_STACK_VIOLATION;
        goto cleanup;
    }

    sp_val -= sizeof(reg_val);
    memcpy(&reg_val, &asm_stack[sp_val], sizeof(reg_val));

    ret = write_reg(reg0, reg_val);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    ret = write_reg(ASM_REGISTER_SP, sp_val);

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP0(PUSHCTX)
{
    int ret = E_SUCCESS;
    reg_value_t sp_val = 0;

    ret = read_reg(ASM_REGISTER_SP, &sp_val);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (sp_val < (reg_value_t)0 || sp_val > (reg_value_t)(ASM_STACK_SIZE - sizeof(registers)))
    {
        ret = E_STACK_VIOLATION;
        goto cleanup;
    }
    memcpy(&asm_stack[sp_val], registers, sizeof(registers));
    ret = write_reg(ASM_REGISTER_SP, sp_val + sizeof(registers));

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP0(POPCTX)
{
    int ret = E_SUCCESS;
    reg_value_t sp_val = 0;

    ret = read_reg(ASM_REGISTER_SP, &sp_val);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (sp_val < (reg_value_t)sizeof(registers) || sp_val > (reg_value_t)ASM_STACK_SIZE)
    {
        ret = E_STACK_VIOLATION;
        goto cleanup;
    }

    sp_val -= sizeof(registers);
    memcpy(registers, &asm_stack[sp_val], sizeof(registers));

cleanup:
    return ret;
}

// We must implement division fully in-order to handle division-by-zero.
INSTRUCTION_DEFINE_OP3(DIV)
{
    int ret = E_SUCCESS;
    reg_value_t value1 = 0;
    reg_value_t value2 = 0;
    ret = read_reg(reg1, &value1);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    ret = read_reg(reg2, &value2);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (value2 == 0)
    {
        ret = E_DIV_ZERO;
        goto cleanup;
    }

    value1 = value1 / value2;

    ret = write_reg(reg0, value1);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

// We must implement division fully in-order to handle division-by-zero.
INSTRUCTION_DEFINE_OP_IMM32(DIVI)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg1, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    if (imm32 == 0)
    {
        ret = E_DIV_ZERO;
        goto cleanup;
    }

    value = value / imm32;

    ret = write_reg(reg0, value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP_IMM32(ROL)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg1, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    value = _rotl(value, imm32);

    ret = write_reg(reg0, value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

INSTRUCTION_DEFINE_OP_IMM32(ROR)
{
    int ret = E_SUCCESS;
    reg_value_t value = 0;
    ret = read_reg(reg1, &value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

    value = _rotr(value, imm32);

    ret = write_reg(reg0, value);
    if (ret != E_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

// This is the table containing the function pointers for the instructions implementations.
// If you add an instruction, add the INSTRUCTION_SYMBOL entry to this table with the opcode value.

#define INSTRUCTION_SYMBOL(opcode) [opcode] = __INSTRUCTION_DEFINE_##opcode
instruction_definition_t asm_instruction_definitions[MAX_ASM_OPCODE_VAL] = {
    INSTRUCTION_SYMBOL(ADD),     INSTRUCTION_SYMBOL(ADDI),    INSTRUCTION_SYMBOL(AND),    INSTRUCTION_SYMBOL(ANDI),
    INSTRUCTION_SYMBOL(DIV),     INSTRUCTION_SYMBOL(DIVI),    INSTRUCTION_SYMBOL(MUL),    INSTRUCTION_SYMBOL(MULI),
    INSTRUCTION_SYMBOL(OR),      INSTRUCTION_SYMBOL(ORI),     INSTRUCTION_SYMBOL(PRINTC), INSTRUCTION_SYMBOL(PRINTDD),
    INSTRUCTION_SYMBOL(PRINTDX), INSTRUCTION_SYMBOL(PRINTNL), INSTRUCTION_SYMBOL(RET),    INSTRUCTION_SYMBOL(RETNZ),
    INSTRUCTION_SYMBOL(RETZ),    INSTRUCTION_SYMBOL(ROL),     INSTRUCTION_SYMBOL(ROR),    INSTRUCTION_SYMBOL(SHL),
    INSTRUCTION_SYMBOL(SHR),     INSTRUCTION_SYMBOL(SUB),     INSTRUCTION_SYMBOL(SUBI),   INSTRUCTION_SYMBOL(XOR),
    INSTRUCTION_SYMBOL(XORI),    INSTRUCTION_SYMBOL(PUSH),    INSTRUCTION_SYMBOL(POP),    INSTRUCTION_SYMBOL(PUSHCTX),
    INSTRUCTION_SYMBOL(POPCTX),
};
