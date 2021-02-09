#include <stdio.h>
#include "prompt.h"

void print_prompt(void)
{
    // Print the prompt in color
    printf(KCYN);
    printf(">>> ");
    printf(KNRM);
}
