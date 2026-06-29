#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MESSAGE "helloworld from sigaltstack shellcode!\n"

static const unsigned char shellcode[] =
    "\xb8\x01\x00\x00\x00"             /* mov eax, 1 (sys_write) */
    "\xbf\x01\x00\x00\x00"             /* mov edi, 1 (stdout) */
    "\x48\x8d\x35\x08\x00\x00\x00"     /* lea rsi, [rip + 8] */
    "\xba\x27\x00\x00\x00"             /* mov edx, 39 */
    "\x0f\x05"                         /* syscall */
    "\xc3"                             /* ret */
    MESSAGE;

int main(void)
{
    void *code = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("mmap code");
        return EXIT_FAILURE;
    }

    memcpy(code, shellcode, sizeof(shellcode));

    if (mprotect(code, sizeof(shellcode), PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    void *alt_stack_mem = mmap(NULL, SIGSTKSZ, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (alt_stack_mem == MAP_FAILED) {
        perror("mmap alt stack");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    stack_t alt_stack;
    memset(&alt_stack, 0, sizeof(alt_stack));
    alt_stack.ss_sp = alt_stack_mem;
    alt_stack.ss_size = SIGSTKSZ;

    if (sigaltstack(&alt_stack, NULL) != 0) {
        perror("sigaltstack");
        (void)munmap(alt_stack_mem, SIGSTKSZ);
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = (void (*)(int))code;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        (void)munmap(alt_stack_mem, SIGSTKSZ);
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    if (raise(SIGUSR1) != 0) {
        perror("raise");
        (void)munmap(alt_stack_mem, SIGSTKSZ);
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    stack_t disabled_stack;
    memset(&disabled_stack, 0, sizeof(disabled_stack));
    disabled_stack.ss_flags = SS_DISABLE;
    (void)sigaltstack(&disabled_stack, NULL);

    (void)munmap(alt_stack_mem, SIGSTKSZ);
    (void)munmap(code, sizeof(shellcode));
    return EXIT_SUCCESS;
}
