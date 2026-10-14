/*
 * seccomp_demo.c: sample that installs a seccomp filter, for testing.
 * Not an exploit; it just calls prctl so Pwnariadne's seccomp heuristic fires
 * and recommends an ORW chain. No payload.
 * Author: HaiND, Post and Telecommunication Institute of Technology
 */
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

int main(void) {
    char buf[64];
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);  /* install seccomp */
    gets(buf);                                   /* sink */
    return 0;
}
