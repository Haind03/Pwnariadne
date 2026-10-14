/*
 * heap_demo.c: intentionally unsafe heap sample for testing Pwnariadne.
 *
 * Exists only so the heap paths of the analyser have something to flag. It is
 * NOT an exploit and contains no payload. It just allocates, frees, and then
 * touches freed memory so that malloc / free call sites are present and a
 * use after free pattern exists for the heap aware GDB dump to observe.
 *
 * Author: HaiND, Post and Telecommunication Institute of Technology
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct note {
    char body[32];
};

int main(void) {
    struct note *a = malloc(sizeof(*a));   /* sink: malloc */
    struct note *b = malloc(sizeof(*b));   /* sink: malloc */

    strcpy(a->body, "first note");         /* sink: strcpy */
    free(a);                               /* sink: free   */

    /* use after free: a was freed above but is read here */
    printf("stale read: %s\n", a->body);

    free(b);
    free(b);                               /* double free pattern */

    return 0;
}
