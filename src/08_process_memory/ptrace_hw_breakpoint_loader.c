#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned char shellcode[] = {
    0x31, 0xc0, 0xb0, 0x01, 0x31, 0xff, 0xff, 0xc7, 0x48, 0x8d, 0x35, 0x0e,
    0x00, 0x00, 0x00, 0x31, 0xd2, 0xb2, 0x36, 0x0f, 0x05, 0x31, 0xc0, 0xb0,
    0x3c, 0x31, 0xff, 0x0f, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x6f,
    0x72, 0x6c, 0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x70, 0x74, 0x72,
    0x61, 0x63, 0x65, 0x20, 0x68, 0x61, 0x72, 0x64, 0x77, 0x61, 0x72, 0x65,
    0x20, 0x62, 0x72, 0x65, 0x61, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x20,
    0x73, 0x68, 0x65, 0x6c, 0x6c, 0x63, 0x6f, 0x64, 0x65, 0x21, 0x0a
};

struct child_addresses {
    uintptr_t trigger_function;
    uintptr_t shellcode_buffer;
};

__attribute__((noinline))
static void trigger_function(void) {
    __asm__ volatile("" ::: "memory");
}

static int write_exact(int fd, const void *buf, size_t len) {
    const unsigned char *cursor = buf;
    while (len > 0) {
        ssize_t written = write(fd, cursor, len);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += written;
        len -= (size_t)written;
    }
    return 0;
}

static int read_exact(int fd, void *buf, size_t len) {
    unsigned char *cursor = buf;
    while (len > 0) {
        ssize_t nread = read(fd, cursor, len);
        if (nread == 0) {
            return -1;
        }
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += nread;
        len -= (size_t)nread;
    }
    return 0;
}

static void child_process(int pipe_fd) {
    size_t len = sizeof(shellcode);
    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        _exit(1);
    }

    memcpy(mem, shellcode, len);
    if (mprotect(mem, len, PROT_READ | PROT_EXEC) != 0) {
        _exit(1);
    }

    struct child_addresses addresses = {
        .trigger_function = (uintptr_t)&trigger_function,
        .shellcode_buffer = (uintptr_t)mem,
    };
    if (write_exact(pipe_fd, &addresses, sizeof(addresses)) != 0) {
        _exit(1);
    }
    close(pipe_fd);

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
        _exit(1);
    }
    raise(SIGSTOP);

    trigger_function();
    _exit(0);
}

static int poke_debug_register(pid_t pid, int index, unsigned long value) {
    long offset = (long)offsetof(struct user, u_debugreg[index]);
    if (ptrace(PTRACE_POKEUSER, pid, (void *)offset, (void *)value) != 0) {
        return -1;
    }
    return 0;
}

int main(void) {
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        perror("pipe");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return 1;
    }

    if (child == 0) {
        close(pipe_fds[0]);
        child_process(pipe_fds[1]);
    }

    close(pipe_fds[1]);

    struct child_addresses addresses;
    if (read_exact(pipe_fds[0], &addresses, sizeof(addresses)) != 0) {
        perror("read child addresses");
        close(pipe_fds[0]);
        return 1;
    }
    close(pipe_fds[0]);

    int status;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid initial stop");
        return 1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child did not stop for tracing\n");
        return 1;
    }

    if (poke_debug_register(child, 0, (unsigned long)addresses.trigger_function) != 0 ||
        poke_debug_register(child, 6, 0) != 0 ||
        poke_debug_register(child, 7, 1UL) != 0) {
        perror("PTRACE_POKEUSER debug register");
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        return 1;
    }

    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        perror("PTRACE_CONT to hardware breakpoint");
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        return 1;
    }

    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid hardware breakpoint");
        return 1;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "expected SIGTRAP from hardware breakpoint\n");
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        return 1;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
        perror("PTRACE_GETREGS");
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        return 1;
    }

#if defined(__x86_64__)
    regs.rip = addresses.shellcode_buffer;
#else
#error "This demo is x86_64-specific."
#endif

    if (poke_debug_register(child, 7, 0) != 0 ||
        poke_debug_register(child, 6, 0) != 0) {
        perror("clear debug registers");
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        return 1;
    }

    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) != 0) {
        perror("PTRACE_SETREGS");
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        return 1;
    }

    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        perror("PTRACE_CONT shellcode");
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        return 1;
    }

    for (;;) {
        if (waitpid(child, &status, 0) < 0) {
            perror("waitpid final");
            return 1;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "child terminated by signal %d\n", WTERMSIG(status));
            return 1;
        }
        if (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_CONT, child, NULL, (void *)(long)WSTOPSIG(status)) != 0) {
                perror("PTRACE_CONT final");
                return 1;
            }
        }
    }
}
