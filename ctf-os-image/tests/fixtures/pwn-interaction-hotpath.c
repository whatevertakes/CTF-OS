#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifndef CTFOS_SENTINEL_PATH
#define CTFOS_SENTINEL_PATH "/work/ctfos-pwn-interaction-sentinel-v1"
#endif

/*
 * Bytes 17..24 of stdin are one controlled function pointer.  The positive
 * target emits the producer-owned sentinel and then terminates with SIGSEGV;
 * the zero-address matched control terminates with the same signal without
 * emitting it.  Matching terminal metadata leaves sentinel provenance as the
 * only attack/control difference.
 */

__attribute__((noinline, used))
int emit_sentinel(void) {
    unsigned char buffer[256];
    int descriptor = open(CTFOS_SENTINEL_PATH, O_RDONLY);
    ssize_t count;

    if (descriptor < 0) {
        return 41;
    }
    while ((count = read(descriptor, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(
                STDOUT_FILENO,
                buffer + offset,
                (size_t)(count - offset)
            );
            if (written <= 0) {
                close(descriptor);
                return 42;
            }
            offset += written;
        }
    }
    close(descriptor);
    if (count < 0) {
        return 43;
    }
    raise(SIGSEGV);
    return 44;
}

int main(void) {
    unsigned char payload[128];
    size_t used = 0;
    uintptr_t destination = 0;

    while (used < sizeof(payload)) {
        ssize_t count = read(
            STDIN_FILENO,
            payload + used,
            sizeof(payload) - used
        );
        if (count < 0) {
            return 50;
        }
        if (count == 0) {
            break;
        }
        used += (size_t)count;
    }
    if (used == 0) {
        return 0;
    }
    if (used < 25) {
        return 51;
    }
    memcpy(&destination, payload + 17, sizeof(destination));
    return ((int (*)(void))destination)();
}
