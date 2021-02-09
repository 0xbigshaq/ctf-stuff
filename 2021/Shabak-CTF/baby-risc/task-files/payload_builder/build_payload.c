/* This project is an example project that can be used in order to generate payloads for BabyRISC.
 * Just edit the opcode insertion and run the output binary.
 * The payload will be written to a file named "payload.bin".
 */
#include <stdio.h>
#include "asm_file_generation.h"
#include "common.h"

#define TERMINATE_MARKER_UINT32 (0xfffffffful)

int main(void)
{
    int ret = E_SUCCESS;
    FILE * payload_fp = NULL;

    payload_fp = fopen("payload.bin", "w");
    if (payload_fp == NULL)
    {
        ret = E_FOPEN;
        goto cleanup;
    }

    // Fill some registers and return
    // (Because E_SUCCESS == 0, we just OR all the return values, to check for error when we finish).
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R0, ASM_REGISTER_ZERO, 0x0);
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R1, ASM_REGISTER_ZERO, 0x11);
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R2, ASM_REGISTER_ZERO, 0x22);
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R3, ASM_REGISTER_ZERO, 0x33);
    ret |= file_write_opcode(payload_fp, RET);

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
    printf("Written %ld bytes to 'payload.bin'.\n", offset);

cleanup:
    if (payload_fp != NULL)
    {
        fclose(payload_fp);
    }
    return ret;
}
