#pragma once
#ifndef __PROMPT_H
#define __PROMPT_H

// Color codes for terminal color printing
// Print some color to make prints in this color from now onwards.
// Print KNRM in order to reset to the normal color.
#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMAG "\x1B[35m"
#define KCYN "\x1B[36m"
#define KWHT "\x1B[37m"

#define PROMPT_PRINTF(f_, ...)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        print_prompt();                                                                                                \
        printf((f_), ##__VA_ARGS__);                                                                                   \
    } while (0)

#define PROMPT_PRINTF_COLOR(color, f_, ...)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        print_prompt();                                                                                                \
        printf(K##color);                                                                                              \
        printf((f_), ##__VA_ARGS__);                                                                                   \
        printf(KNRM);                                                                                                  \
    } while (0)

void print_prompt(void);

#endif /* __PROMPT_H */
