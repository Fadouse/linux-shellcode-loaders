#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int create_memfd(const char *name, unsigned int flags) {
#ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, name, flags);
#else
    (void)name;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

static int copy_to_fd(int input_fd, int output_fd) {
    char buffer[8192];

    for (;;) {
        ssize_t got = read(input_fd, buffer, sizeof(buffer));
        if (got == 0) {
            return 0;
        }
        if (got < 0) {
            return -1;
        }

        char *cursor = buffer;
        ssize_t remaining = got;
        while (remaining > 0) {
            ssize_t wrote = write(output_fd, cursor, (size_t)remaining);
            if (wrote <= 0) {
                return -1;
            }
            cursor += wrote;
            remaining -= wrote;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <plugin.so>\n", argv[0]);
        return 1;
    }

    int input_fd = open(argv[1], O_RDONLY);
    if (input_fd < 0) {
        perror("open");
        return 1;
    }

    int memfd = create_memfd("shellcode-style-plugin", MFD_CLOEXEC);
    if (memfd < 0) {
        perror("memfd_create");
        close(input_fd);
        return 1;
    }

    if (copy_to_fd(input_fd, memfd) != 0) {
        perror("copy plugin to memfd");
        close(memfd);
        close(input_fd);
        return 1;
    }
    close(input_fd);

    char fd_path[64];
    int path_len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", memfd);
    if (path_len < 0 || (size_t)path_len >= sizeof(fd_path)) {
        fprintf(stderr, "memfd path truncated\n");
        close(memfd);
        return 1;
    }

    void *handle = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen(%s): %s\n", fd_path, dlerror());
        close(memfd);
        return 1;
    }

    dlerror();
    void (*run_memfd_payload)(void) = (void (*)(void))dlsym(handle, "run_memfd_payload");
    const char *error = dlerror();
    if (error != NULL) {
        dlerror();
        run_memfd_payload = (void (*)(void))dlsym(handle, "run_payload");
        error = dlerror();
    }
    if (error != NULL) {
        fprintf(stderr, "dlsym(run_memfd_payload/run_payload): %s\n", error);
        dlclose(handle);
        close(memfd);
        return 1;
    }

    run_memfd_payload();
    dlclose(handle);
    close(memfd);
    return 0;
}
