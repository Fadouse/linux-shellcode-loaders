#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const char message[] = "helloworld from SIGSEGV lazy-page shellcode!\n";
static void *fault_page;
static size_t page_size;

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

static void segv_handler(int sig, siginfo_t *info, void *context) {
    (void)context;

    uintptr_t fault = (uintptr_t)info->si_addr;
    uintptr_t start = (uintptr_t)fault_page;
    uintptr_t end = start + page_size;

    if (sig == SIGSEGV && fault >= start && fault < end) {
        uint8_t payload[128];
        size_t payload_len = 0;

        build_shellcode(payload, &payload_len);
        if (mprotect(fault_page, page_size, PROT_READ | PROT_WRITE) == 0) {
            memcpy(fault_page, payload, payload_len);
            if (mprotect(fault_page, page_size, PROT_READ | PROT_EXEC) == 0) {
                return;
            }
        }
    }

    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

int main(void) {
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == (size_t)-1) {
        perror("sysconf");
        return 1;
    }

    fault_page = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fault_page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("sigaction");
        munmap(fault_page, page_size);
        return 1;
    }

    ((shellcode_fn)fault_page)();

    if (munmap(fault_page, page_size) < 0) {
        perror("munmap");
        return 1;
    }

    return 0;
}
