#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

static const unsigned char shellcode[] = {
    0xb8, 0x01, 0x00, 0x00, 0x00,             /* mov eax, SYS_write */
    0xbf, 0x01, 0x00, 0x00, 0x00,             /* mov edi, STDOUT_FILENO */
    0x48, 0x8d, 0x35, 0x08, 0x00, 0x00, 0x00, /* lea rsi, [rip + msg] */
    0xba, 0x29, 0x00, 0x00, 0x00,             /* mov edx, msg_len */
    0x0f, 0x05,                               /* syscall */
    0xc3,                                     /* ret */
    'h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd', ' ', 'f', 'r', 'o', 'm', ' ',
    'p', 'r', 'o', 'c', ' ', 's', 'e', 'l', 'f', ' ', 'm', 'e', 'm', ' ',
    's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '!', '\n'
};

typedef void (*shellcode_fn)(void);

static void die(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

static void pwrite_all(int fd, const void *buf, size_t len, off_t offset)
{
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = pwrite(fd, p, len, offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("pwrite /proc/self/mem");
        }
        p += (size_t)n;
        len -= (size_t)n;
        offset += n;
    }
}

int main(void)
{
    void *buf = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        die("mmap");
    }

    int memfd = open("/proc/self/mem", O_RDWR);
    if (memfd < 0) {
        die("open /proc/self/mem");
    }

    pwrite_all(memfd, shellcode, sizeof(shellcode), (off_t)(uintptr_t)buf);
    if (close(memfd) != 0) {
        die("close /proc/self/mem");
    }

    if (mprotect(buf, sizeof(shellcode), PROT_READ | PROT_EXEC) != 0) {
        die("mprotect");
    }

    ((shellcode_fn)buf)();

    if (munmap(buf, sizeof(shellcode)) != 0) {
        die("munmap");
    }
    return EXIT_SUCCESS;
}
