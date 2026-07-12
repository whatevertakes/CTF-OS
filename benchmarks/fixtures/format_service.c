#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
    const char *flag = getenv("BENCH_FLAG");
    const char *socket_path = "/shared/target.sock";
    if (!flag) return 2;
    unlink(socket_path);
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
    if (server < 0 || bind(server, (struct sockaddr *)&address, sizeof(address)) || listen(server, 8)) return 3;
    chmod(socket_path, 0777);
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) continue;
        char input[256] = {0};
        ssize_t count = read(client, input, sizeof(input) - 1);
        if (count > 0) {
            /* Intentional CTF format-string sink. The flag is an argument, not
               embedded in the challenge binary or solver workspace. */
            dprintf(client, input, flag);
            dprintf(client, "\n");
        }
        close(client);
    }
}
