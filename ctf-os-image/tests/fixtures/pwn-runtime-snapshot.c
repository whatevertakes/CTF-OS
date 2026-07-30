#define _GNU_SOURCE

#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned char clone_stack[65536];

static int clone_return(void *unused) {
    (void)unused;
    return 0;
}

int main(int argc, char **argv) {
    unsigned char value = 0;
    ssize_t count;

    if (argc != 1) {
        return 70;
    }
    count = read(STDIN_FILENO, &value, 1);
    if (count != 1) {
        return 71;
    }
    if (value == 'S') {
        raise(SIGSEGV);
        return 72;
    }
    if (value == 'D') {
        pid_t child = fork();

        if (child < 0) {
            return 73;
        }
        if (child == 0) {
            for (;;) {
                pause();
            }
        }
        raise(SIGSEGV);
        return 74;
    }
    if (value == 'V') {
        int status = 0;
        pid_t child = clone(
            clone_return,
            clone_stack + sizeof(clone_stack),
            CLONE_VM | SIGCHLD,
            NULL
        );

        if (child < 0) {
            return 75;
        }
        if (waitpid(child, &status, 0) != child) {
            return 76;
        }
        raise(SIGSEGV);
        return 77;
    }
    if (value == 'X') {
        execl("/proc/self/exe", argv[0], (char *)NULL);
        return 78;
    }
    return 79;
}
