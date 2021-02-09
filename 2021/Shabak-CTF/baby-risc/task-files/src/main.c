#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "prompt.h"
#include "common.h"
#include "asm_types.h"
#include "asm_file_generation.h"
#include "asm_execution.h"

#define MAX_FLAG_SIZE (256)
#define FLAG_FILE_PATH "flag"
#define MAX_ADMIN_PAYLOAD_SIZE (1024)
#define MAX_USER_PAYLOAD_SIZE (4096)
#define TERMINATE_MARKER_UINT32 (0xfffffffful)

static void disable_io_buffering(void)
{
    // disable buffering
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

// Reads the flag from the flag file into the buffer.
// The flag is written null-terminated (and the rest of the buffer is padded with nulls).
// Return 0 on success, otherwise - error.
static int read_flag(char * buffer, size_t buffer_len)
{
    int ret = E_SUCCESS;
    FILE * flag_fp = NULL;

    memset(buffer, 0, buffer_len);

    flag_fp = fopen(FLAG_FILE_PATH, "r");
    if (flag_fp == NULL)
    {
        ret = E_FOPEN;
        goto cleanup;
    }

    // Read entire flag from file
    size_t bytes_read = fread(buffer, 1, buffer_len - 1, flag_fp);
    if ((bytes_read == 0) || !feof(flag_fp))
    {
        // Read error
        ret = E_FREAD;
        goto cleanup;
    }

    // Success
    ret = E_SUCCESS;

cleanup:
    if (flag_fp != NULL)
    {
        fclose(flag_fp);
    }
    return ret;
}

// Writes the admin shellcode to the 'payload' buffer.
// Writes the actual size of the payload to 'payload_size_out'.
static int generate_admin_code(uint8_t * payload, size_t max_size, size_t * payload_size_out)
{
    int ret = E_SUCCESS;
    char flag_string[MAX_FLAG_SIZE] = { 0 };
    FILE * payload_fp = NULL;

    ret = read_flag(flag_string, sizeof(flag_string));
    if (ret != E_SUCCESS)
    {
        printf("Failed to read flag.\n");
        goto cleanup;
    }

    payload_fp = fmemopen(payload, max_size, "w");
    if (payload_fp == NULL)
    {
        ret = E_FOPEN;
        goto cleanup;
    }

    // Write admin shellcode to payload buffer
    // (Because E_SUCCESS == 0, we just OR all the return values, to check for error when we finish).
    ret = E_SUCCESS;

    // Pad out with newlines
    for (size_t i = 0; i < 8; ++i)
    {
        ret |= file_write_opcode(payload_fp, PRINTNL);
    }

    // If the user sets R0 so (R0 * 42) == 1 (impossible!), she deserves to read the flag
    ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R1, ASM_REGISTER_ZERO, 42);
    ret |= file_write_opcode3(payload_fp, MUL, ASM_REGISTER_R2, ASM_REGISTER_R0, ASM_REGISTER_R1);
    ret |= file_write_opcode_imm32(payload_fp, SUBI, ASM_REGISTER_R2, ASM_REGISTER_R2, 1);
    ret |= file_write_opcode1(payload_fp, RETNZ, ASM_REGISTER_R2);

    // Print each 4-bytes of the flag as 4-characters
    // (We might print some trailing null-characters if the flag length is not divisible by 4)
    int32_t * flag_start = (int32_t *)flag_string;
    int32_t * flag_end = (int32_t *)((char *)flag_string + strlen(flag_string));
    for (int32_t * p = flag_start; p <= flag_end; ++p)
    {
        int32_t dword = *p;

        ret |= file_write_opcode_imm32(payload_fp, ADDI, ASM_REGISTER_R1, ASM_REGISTER_ZERO, dword);
        for (size_t j = 0; j < 4; j++)
        {
            ret |= file_write_opcode1(payload_fp, PRINTC, ASM_REGISTER_R1);
            ret |= file_write_opcode_imm32(payload_fp, ROR, ASM_REGISTER_R1, ASM_REGISTER_R1, 8);
        }
    }

    ret |= file_write_opcode(payload_fp, PRINTNL);
    ret |= file_write_opcode(payload_fp, RET);

    // Check if some error (other than E_SUCCESS) was recieved during the admin code generation
    if (ret != E_SUCCESS)
    {
        ret = E_ADMIN_CODE_ERR;
        goto cleanup;
    }

    // Success
    long offset = ftell(payload_fp);
    if (offset == -1)
    {
        ret = E_FTELL;
        goto cleanup;
    }
    *payload_size_out = (size_t)offset;

cleanup:
    if (payload_fp != NULL)
    {
        fclose(payload_fp);
    }
    return ret;
}

// Read the user code from 'stdin'. The code must be terminated with 4 0xff bytes (0xffffffff).
// The code maximum size is 'max_size'.
static int read_user_code(uint8_t * payload, size_t max_size, size_t * payload_size_out)
{
    int ret = E_FREAD;
    size_t bytes_read = 0;
    size_t current_offset = 0;
    uint32_t terminate_marker = TERMINATE_MARKER_UINT32;
    size_t marker_size = sizeof(terminate_marker);

    while (current_offset < max_size)
    {
        // Read byte from 'stdin'
        bytes_read = fread(payload + current_offset, 1, 1, stdin);
        if (bytes_read == 0)
        {
            goto cleanup;
        }
        current_offset += bytes_read;

        // Check if terminator marker is here
        if (current_offset >= marker_size &&
            (memcmp(&terminate_marker, &payload[current_offset - marker_size], marker_size) == 0))
        {
            // Success
            *payload_size_out = current_offset - marker_size;
            ret = E_SUCCESS;
            break;
        }
    }

cleanup:
    return ret;
}

int main(void)
{
    int ret = E_SUCCESS;
    disable_io_buffering();
    uint8_t admin_payload[MAX_ADMIN_PAYLOAD_SIZE] = { 0 };
    size_t admin_payload_size = 0;
    uint8_t user_payload[MAX_USER_PAYLOAD_SIZE] = { 0 };
    size_t user_payload_size = 0;
    uint8_t * combined_payload = NULL;
    size_t combined_payload_size = 0;

    ret = generate_admin_code(admin_payload, sizeof(admin_payload), &admin_payload_size);
    if (ret != E_SUCCESS)
    {
        printf("Failed to generate admin code\n");
        goto cleanup;
    }

    ret = read_user_code(user_payload, sizeof(user_payload), &user_payload_size);
    if (ret != E_SUCCESS)
    {
        printf("Failed to read code from user (stdin).\n");
        goto cleanup;
    }
    printf("User payload size: %ld\n", user_payload_size);

    // Combine the payloads
    combined_payload_size = user_payload_size + admin_payload_size;
    combined_payload = malloc(combined_payload_size);
    if (combined_payload == NULL)
    {
        ret = E_NOMEM;
        goto cleanup;
    }
    memcpy(combined_payload, user_payload, user_payload_size);
    memcpy(&combined_payload[user_payload_size], admin_payload, admin_payload_size);

    // Execute the code!
    PROMPT_PRINTF_COLOR(GRN, "Executing code!\n");
    ret = execute_asm_memory(combined_payload, combined_payload_size);

cleanup:
    return ret;
}
