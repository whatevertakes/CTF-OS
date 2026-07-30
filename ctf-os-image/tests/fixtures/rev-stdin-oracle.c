#include <stddef.h>
#include <string.h>
#include <unistd.h>

static int write_all(int descriptor, const char *buffer, size_t size) {
    size_t offset = 0;

    while (offset < size) {
        ssize_t written = write(descriptor, buffer + offset, size - offset);
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

int main(void) {
    static const char accepted[] = "OPEN-SESAME\n";
    static const char success[] = "KCTF{docker_rev_proof}\n";
    static const char rejected[] = "rejected\n";
    char input[sizeof(accepted)];
    size_t size = 0;

    while (size < sizeof(input)) {
        ssize_t received = read(STDIN_FILENO, input + size, sizeof(input) - size);
        if (received < 0) {
            return 125;
        }
        if (received == 0) {
            break;
        }
        size += (size_t)received;
    }
    if (
        size == sizeof(accepted) - 1
        && memcmp(input, accepted, sizeof(accepted) - 1) == 0
    ) {
        return write_all(
            STDOUT_FILENO,
            success,
            sizeof(success) - 1
        ) == 0 ? 0 : 125;
    }
    return write_all(
        STDOUT_FILENO,
        rejected,
        sizeof(rejected) - 1
    ) == 0 ? 7 : 125;
}
