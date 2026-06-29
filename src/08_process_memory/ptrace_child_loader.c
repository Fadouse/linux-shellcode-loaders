#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static const unsigned char shellcode[] = {
    0xb8, 0x01, 0x00, 0x00, 0x00,             /* mov eax, SYS_write */
    0xbf, 0x01, 0x00, 0x00, 0x00,             /* mov edi, STDOUT_FILENO */
    0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, /* lea rsi, [rip + msg] */
    0xba, 0x33, 0x00, 0x00, 0x00,             /* mov edx, msg_len */
    0x0f, 0x05,                               /* syscall */
    0xb8, 0x3c, 0x00, 0x00, 0x00,             /* mov eax, SYS_exit */
    0x31, 0xff,                               /* xor edi, edi */
    0x0f, 0x05,                               /* syscall */
    'h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd', ' ', 'f', 'r', 'o', 'm', ' ',
    'p', 't', 'r', 'a', 'c', 'e', ' ', 'c', 'o', 'n', 't', 'r', 'o', 'l', 'l', 'e', 'd', ' ',
    'c', 'h', 'i', 'l', 'd', ' ', 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '!', '\n'
};

static void die(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

static void write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("write");
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static void read_all(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("read");
        }
        if (n == 0) {
            fprintf(stderr, "unexpected EOF\n");
            exit(EXIT_FAILURE);
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static void ptrace_write(pid_t pid, uintptr_t remote_addr, const unsigned char *buf, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        long word = 0;
        size_t chunk = sizeof(word);
        if (chunk > len - offset) {
            chunk = len - offset;
        }
        memcpy(&word, buf + offset, chunk);
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(remote_addr + offset), (void *)(uintptr_t)word) == -1 && errno != 0) {
            die("ptrace POKEDATA");
        }
        offset += sizeof(word);
    }
}

int main(void)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        die("pipe");
    }

    pid_t child = fork();
    if (child < 0) {
        die("fork");
    }

    if (child == 0) {
        close(pipefd[0]);
        void *buf = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) {
            die("mmap");
        }
        uintptr_t addr = (uintptr_t)buf;
        write_all(pipefd[1], &addr, sizeof(addr));
        close(pipefd[1]);

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            die("ptrace TRACEME");
        }
        raise(SIGSTOP);

        for (;;) {
            pause();
        }
    }

    close(pipefd[1]);
    uintptr_t remote_addr = 0;
    read_all(pipefd[0], &remote_addr, sizeof(remote_addr));
    close(pipefd[0]);

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        die("waitpid stop");
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child did not stop as expected\n");
        return EXIT_FAILURE;
    }

    ptrace_write(child, remote_addr, shellcode, sizeof(shellcode));

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
        die("ptrace GETREGS");
    }
    regs.rip = remote_addr;
    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) != 0) {
        die("ptrace SETREGS");
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        die("ptrace CONT");
    }

    if (waitpid(child, &status, 0) < 0) {
        die("waitpid exit");
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
