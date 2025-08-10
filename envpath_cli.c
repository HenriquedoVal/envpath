#include <assert.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "envpath.h"

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [-v|-h] <cmd> [args]\n"
            "    -v:        Verbose\n"
            "    -h:        Print this help and quit\n"
            "\n"
            "    cmd:       {diag|add|rem}\n"
            "\n"
            "    diag:      Diagnoses Path variable construction.\n"
            "               Takes no args. Dumps info on stderr and\n"
            "               the sanitized updated Path on stdout\n"
            "\n"
            "    add|rem:   -u[ser]|-m[achine] <path> [-e]\n"
            "               Adds or removes <path> to/from given target\n"
            "               registry. `-e` for exact but case-insensitive\n"
            "               match, that is, do not resolve <path>\n",
            program);
}

#define ERROR_OUT(program, ...) do {   \
    fprintf(stderr, __VA_ARGS__);      \
    print_usage(program);              \
    return 1;                          \
} while (0)

typedef enum {
    DIAG,
    ADD,
    REM
} Command;

int main(int argc, char **argv)
{
    int cursor = 0;
    bool verbose = false;
    bool exact = false;
    Command command = -1;
    Target target = -1;

    char *program = argv[cursor]; cursor++;
    if (cursor == argc)
        ERROR_OUT(program, "Error: No command is provided\n");

    char *cmd_or_opt = argv[cursor]; cursor++;
    if (*cmd_or_opt == '-') {
        char *opt = cmd_or_opt;
        if        (strcmp("-v", opt) == 0) {
            verbose = true;

        } else if (strcmp("-h", opt) == 0) {
            print_usage(program);
            return 1;

        } else {
            ERROR_OUT(program, "Error: Unknown option `%s`\n", opt);
        }
    } else {
        char *cmd = cmd_or_opt;
        if        (strcmp("diag", cmd) == 0) {
            command = DIAG;

        } else if (strcmp("add", cmd) == 0) {
            command = ADD;

        } else if (strcmp("rem", cmd) == 0) {
            command = REM;

        } else {
            ERROR_OUT(program, "Error: Unknown command `%s`\n", cmd);
        }
    }

    if (command == DIAG) goto process;

    if (command == -1) {
        if (cursor == argc)
            ERROR_OUT(program, "Error: No command is provided\n");

        char *cmd = argv[cursor]; cursor++;
        if        (strcmp("diag", cmd) == 0) {
            command = DIAG;

        } else if (strcmp("add", cmd) == 0) {
            command = ADD;

        } else if (strcmp("rem", cmd) == 0) {
            command = REM;

        } else {
            ERROR_OUT(program, "Error: Unknown command `%s`\n", cmd);
        }
    }

    if (command == DIAG) goto process;

    if (cursor == argc)
        ERROR_OUT(program, "Error: No required option is provided\n");

    char *opt = argv[cursor]; cursor++;
    if        (strcmp("-u", opt) == 0 || strcmp("-user", opt) == 0) {
        target = USER;

    } else if (strcmp("-m", opt) == 0 || strcmp("-machine", opt) == 0) {
        target = MACHINE;

    } else {
        ERROR_OUT(program, "Error: Unknown option `%s`\n", opt);
    }

    if (cursor == argc)
        ERROR_OUT(program, "Error: No required path is provided\n");
    char *path = argv[cursor]; cursor++;

    if (cursor < argc) {
        char *exact_arg = argv[cursor];
        if (strcmp("-e", exact_arg) == 0) {
            exact = true;
            cursor++;
        }
    }

process:
    if (cursor < argc)
        fprintf(stderr,
                "Warning: Unused arguments starting on `%s`\n",
                argv[cursor]);

    set_std_outputs();

    bool success = false;
    switch (command) {
        case DIAG:
            success = diagnose(verbose);
            break;

        case ADD:
            success = add_path(target, path, verbose, exact);
            break;

        case REM:
            success = remove_path(target, path, verbose, exact);
            break;

        default:
            fprintf(stderr, "Unreachable\n");
            return 2;
    }

    return success ? 0 : 1;
}
