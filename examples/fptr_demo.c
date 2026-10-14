/*
 * fptr_demo.c: sample with an indirect call for testing Pwnariadne.
 *
 * It calls through a function pointer, which compiles to an indirect call
 * (call <reg> on x86-64). Not an exploit; it just exercises the indirect
 * dispatch detector. No payload.
 *
 * Author: HaiND, Post and Telecommunication Institute of Technology
 */
#include <stdio.h>
#include <string.h>

static void say_hi(const char *who) { printf("hi %s\n", who); }
static void say_bye(const char *who) { printf("bye %s\n", who); }

int main(int argc, char **argv) {
    void (*action)(const char *) = say_hi;
    if (argc > 1 && strcmp(argv[1], "bye") == 0) {
        action = say_bye;
    }
    action(argv[0]);   /* indirect call through a function pointer */
    return 0;
}
