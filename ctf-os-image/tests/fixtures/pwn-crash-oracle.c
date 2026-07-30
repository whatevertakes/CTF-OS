#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned char clone_stack[65536];

static void caught_fault(int signal_number) {
    (void)signal_number;
}

static void *thread_fault(void *unused) {
    volatile int *invalid = (volatile int *)0;

    (void)unused;
    *invalid = 1;
    return NULL;
}

static void *thread_return(void *unused) {
    (void)unused;
    return NULL;
}

static int clone_return(void *unused) {
    (void)unused;
    return 0;
}

int main(void) {
    unsigned char value = 0;
    ssize_t count = read(STDIN_FILENO, &value, 1);

    if (count == 1 && value == 'X') {
        raise(SIGSEGV);
    }
    if (count == 1 && value == 'E') {
        return 139;
    }
    if (count == 1 && value == 'C') {
        struct sigaction action = {0};

        action.sa_handler = caught_fault;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGSEGV, &action, NULL) != 0) {
            return 80;
        }
        raise(SIGSEGV);
        return 81;
    }
    if (count == 1 && value == 'H') {
        pthread_t thread;

        if (pthread_create(&thread, NULL, thread_fault, NULL) != 0) {
            return 82;
        }
        if (pthread_join(thread, NULL) != 0) {
            return 83;
        }
        return 84;
    }
    if (count == 1 && value == 'K') {
        int status = 0;
        pid_t child = fork();

        if (child < 0) {
            return 85;
        }
        if (child == 0) {
            raise(SIGSEGV);
            _exit(86);
        }
        if (waitpid(child, &status, 0) != child) {
            return 87;
        }
        return WIFSIGNALED(status) ? 0 : 88;
    }
    if (count == 1 && value == 'P') {
        pthread_t thread;

        if (pthread_create(&thread, NULL, thread_return, NULL) != 0) {
            return 89;
        }
        return pthread_join(thread, NULL) == 0 ? 0 : 90;
    }
    if (count == 1 && value == 'U') {
        pid_t child;

        errno = 0;
        child = clone(
            clone_return,
            clone_stack + sizeof(clone_stack),
            CLONE_UNTRACED | SIGCHLD,
            NULL
        );
        if (child < 0) {
            return errno == EPERM ? 0 : 91;
        }
        if (waitpid(child, NULL, 0) != child) {
            return 92;
        }
        return 93;
    }
    return 0;
}
