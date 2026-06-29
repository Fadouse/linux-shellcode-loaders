#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

static int make_memfd(const char *name, unsigned int flags)
{
#if defined(__linux__) && defined(SYS_memfd_create)
    int fd = memfd_create(name, flags);
    if (fd >= 0 || errno != ENOSYS) {
        return fd;
    }

    return (int)syscall(SYS_memfd_create, name, flags);
#else
    (void)name;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

static int copy_all(int out_fd, int in_fd)
{
    unsigned char buf[4096];

    for (;;) {
        ssize_t nread = read(in_fd, buf, sizeof(buf));
        if (nread == 0) {
            return 0;
        }
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        for (ssize_t off = 0; off < nread;) {
            ssize_t nwritten = write(out_fd, buf + off, (size_t)(nread - off));
            if (nwritten < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            off += nwritten;
        }
    }
}

int main(int argc, char **argv)
{
    const char *payload_path = (argc > 1) ? argv[1] : "./build/fixtures/memfd_payload";
    int in_fd = open(payload_path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        perror("open payload");
        return 1;
    }

    int mem_fd = make_memfd("shellcode_learn_memfd_payload", 0);
    if (mem_fd < 0) {
        perror("memfd_create");
        (void)close(in_fd);
        return 1;
    }

    if (copy_all(mem_fd, in_fd) < 0) {
        perror("copy payload into memfd");
        (void)close(in_fd);
        (void)close(mem_fd);
        return 1;
    }
    (void)close(in_fd);

    if (fchmod(mem_fd, 0700) < 0) {
        perror("fchmod memfd");
        (void)close(mem_fd);
        return 1;
    }

    char *exec_argv[] = { (char *)payload_path, NULL };
    fexecve(mem_fd, exec_argv, environ);

    perror("fexecve");
    (void)close(mem_fd);
    return 1;
}
