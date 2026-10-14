/*
 * win_demo.c: classic ret2win layout for testing.
 * win() is never called from main; an overflow in vuln() must redirect to it.
 * Not an exploit; no payload. Author: HaiND, PTIT.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("you reached win()");
    system("/bin/sh");
}

void vuln(void) {
    char buf[64];
    read(0, buf, 200);   /* overflow */
}

int main(void) {
    vuln();
    return 0;
}
