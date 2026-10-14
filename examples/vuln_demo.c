/*
 * vuln_demo.c — intentionally unsafe sample for testing Pwnariadne.
 *
 * This file exists only so the analyser has something to find. It is NOT an
 * exploit and contains no payload; it simply calls several memory-unsafe libc
 * functions that Pwnariadne should flag. Compile with the provided Makefile.
 *
 * Author: HaiND from the Post and Telecommunication Institute of Technology
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void echo_name(void) {
    char buf[64];
    printf("name> ");
    gets(buf);          /* sink: unbounded read -> stack overflow */
    printf(buf);        /* sink: format string (user-controlled)  */
}

void copy_input(const char *src) {
    char dst[32];
    strcpy(dst, src);   /* sink: unbounded copy -> stack overflow  */
    puts(dst);
}

int main(int argc, char **argv) {
    echo_name();
    if (argc > 1) {
        copy_input(argv[1]);
    }
    return 0;
}
