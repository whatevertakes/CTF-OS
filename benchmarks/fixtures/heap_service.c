#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static uint64_t rol64(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64 - shift));
}

int main(void) {
    const char *flag = getenv("BENCH_FLAG");
    const char *leak_text = getenv("BENCH_LEAK");
    const char *key_text = getenv("BENCH_SAFE_LINK_KEY");
    const char *handle = getenv("BENCH_HANDLE");
    if (!flag || !leak_text || !key_text || !handle) return 2;
    uint64_t leak = strtoull(leak_text, NULL, 0);
    uint64_t key = strtoull(key_text, NULL, 0);
    uint64_t expected = rol64(leak ^ key, 17);
    const char *socket_path = "/shared/target.sock";
    unlink(socket_path);
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
    if (server < 0 || bind(server, (struct sockaddr *)&address, sizeof(address)) || listen(server, 8)) return 3;
    chmod(socket_path, 0777);
    int leak_issued = 0;
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) continue;
        char input[512] = {0};
        if (read(client, input, sizeof(input) - 1) <= 0) { close(client); continue; }
        if (!strncmp(input, "LEAK", 4)) {
            if (leak_issued) {
                dprintf(client, "{\"error\":\"leak_already_consumed\"}\n");
            } else {
                leak_issued = 1;
                dprintf(client,
                    "{\"kind\":\"libc_leak\",\"libc_leak\":\"0x%llx\","
                    "\"safe_link_key\":\"0x%llx\",\"handle\":\"%s\"}\n",
                    (unsigned long long)leak, (unsigned long long)key, handle);
            }
        } else if (!strncmp(input, "EXPLOIT ", 8)) {
            char supplied_handle[128] = {0};
            unsigned long long token = 0;
            if (sscanf(input + 8, "%127s %llx", supplied_handle, &token) == 2
                    && leak_issued && !strcmp(supplied_handle, handle) && token == expected) {
                dprintf(client, "%s\n", flag);
            } else {
                dprintf(client, "rejected\n");
            }
        } else {
            dprintf(client, "commands: LEAK | EXPLOIT <handle> <token>\n");
        }
        close(client);
    }
}
