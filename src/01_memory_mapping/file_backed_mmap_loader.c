#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const char message[] = "helloworld from file-backed mmap shellcode!\n";

typedef void (*shellcode_fn)(void);

static void build_shellcode(uint8_t *buf, size_t *len) {
    static const uint8_t prefix[] = {
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       /* mov rax, 1 */
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,       /* mov rdi, 1 */
        0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,       /* lea rsi, [rip+10] */
        0x48, 0xc7, 0xc2, (uint8_t)(sizeof(message) - 1), 0x00, 0x00, 0x00, /* mov rdx, len */
        0x0f, 0x05,                                     /* syscall */
        0xc3                                            /* ret */
    };

    memcpy(buf, prefix, sizeof(prefix));
    memcpy(buf + sizeof(prefix), message, sizeof(message) - 1);
    *len = sizeof(prefix) + sizeof(message) - 1;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t written = write(fd, buf, len);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += (size_t)written;
        len -= (size_t)written;
    }
    return 0;
}

int main(void) {
    uint8_t payload[128];
    size_t payload_len = 0;
    char path[] = "/tmp/file_backed_shellcode_XXXXXX";

    build_shellcode(payload, &payload_len);

    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }

    if (unlink(path) < 0) {
        perror("unlink");
        close(fd);
        return 1;
    }

    if (write_all(fd, payload, payload_len) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    void *code = mmap(NULL, payload_len, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (code == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    close(fd);
    ((shellcode_fn)code)();

    if (munmap(code, payload_len) < 0) {
        perror("munmap");
        return 1;
    }

    return 0;
}
