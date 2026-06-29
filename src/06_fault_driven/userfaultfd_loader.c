#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char message[] = "helloworld from userfaultfd shellcode!\n";

typedef void (*shellcode_fn)(void);

struct handler_args {
    int uffd;
    void *page;
    size_t page_size;
};

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

static void *fault_handler_thread(void *arg) {
    struct handler_args *args = arg;
    struct uffd_msg msg;

    for (;;) {
        ssize_t nread = read(args->uffd, &msg, sizeof(msg));
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read userfaultfd");
            return (void *)1;
        }
        if ((size_t)nread != sizeof(msg)) {
            fprintf(stderr, "short read from userfaultfd\n");
            return (void *)1;
        }
        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "unexpected userfaultfd event: %u\n", msg.event);
            return (void *)1;
        }

        uintptr_t fault_addr = (uintptr_t)msg.arg.pagefault.address;
        uintptr_t start = (uintptr_t)args->page;
        uintptr_t end = start + args->page_size;
        if (fault_addr < start || fault_addr >= end) {
            fprintf(stderr, "page fault outside registered page: 0x%" PRIxPTR "\n", fault_addr);
            return (void *)1;
        }

        void *copy_page = mmap(NULL, args->page_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (copy_page == MAP_FAILED) {
            perror("mmap copy page");
            return (void *)1;
        }

        uint8_t payload[128];
        size_t payload_len = 0;
        build_shellcode(payload, &payload_len);
        memcpy(copy_page, payload, payload_len);

        struct uffdio_copy copy;
        memset(&copy, 0, sizeof(copy));
        copy.dst = (unsigned long)args->page;
        copy.src = (unsigned long)copy_page;
        copy.len = (unsigned long)args->page_size;
        copy.mode = 0;

        if (ioctl(args->uffd, UFFDIO_COPY, &copy) < 0) {
            perror("ioctl UFFDIO_COPY");
            munmap(copy_page, args->page_size);
            return (void *)1;
        }

        if (munmap(copy_page, args->page_size) < 0) {
            perror("munmap copy page");
            return (void *)1;
        }

        return NULL;
    }
}

static int setup_userfaultfd(void *page, size_t page_size) {
    int uffd = (int)syscall(__NR_userfaultfd, O_CLOEXEC);
    if (uffd < 0) {
        fprintf(stderr, "userfaultfd unavailable: %s\n", strerror(errno));
        fprintf(stderr, "This kernel may block unprivileged userfaultfd via vm.unprivileged_userfaultfd.\n");
        return -1;
    }

    struct uffdio_api api;
    memset(&api, 0, sizeof(api));
    api.api = UFFD_API;
    api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &api) < 0) {
        fprintf(stderr, "ioctl UFFDIO_API failed: %s\n", strerror(errno));
        close(uffd);
        return -1;
    }

    struct uffdio_register reg;
    memset(&reg, 0, sizeof(reg));
    reg.range.start = (unsigned long)page;
    reg.range.len = (unsigned long)page_size;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
        fprintf(stderr, "ioctl UFFDIO_REGISTER failed: %s\n", strerror(errno));
        close(uffd);
        return -1;
    }

    return uffd;
}

int main(void) {
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == (size_t)-1) {
        perror("sysconf");
        return 1;
    }

    void *page = mmap(NULL, page_size, PROT_READ | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    int uffd = setup_userfaultfd(page, page_size);
    if (uffd < 0) {
        munmap(page, page_size);
        return 1;
    }

    struct handler_args args = {
        .uffd = uffd,
        .page = page,
        .page_size = page_size,
    };

    pthread_t thread;
    int rc = pthread_create(&thread, NULL, fault_handler_thread, &args);
    if (rc != 0) {
        fprintf(stderr, "pthread_create failed: %s\n", strerror(rc));
        close(uffd);
        munmap(page, page_size);
        return 1;
    }

    ((shellcode_fn)page)();

    void *thread_result = NULL;
    rc = pthread_join(thread, &thread_result);
    if (rc != 0) {
        fprintf(stderr, "pthread_join failed: %s\n", strerror(rc));
        close(uffd);
        munmap(page, page_size);
        return 1;
    }

    struct uffdio_range range;
    memset(&range, 0, sizeof(range));
    range.start = (unsigned long)page;
    range.len = (unsigned long)page_size;
    if (ioctl(uffd, UFFDIO_UNREGISTER, &range) < 0) {
        perror("ioctl UFFDIO_UNREGISTER");
        close(uffd);
        munmap(page, page_size);
        return 1;
    }

    close(uffd);
    if (munmap(page, page_size) < 0) {
        perror("munmap");
        return 1;
    }

    return thread_result == NULL ? 0 : 1;
}
