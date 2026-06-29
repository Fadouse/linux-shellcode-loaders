#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MESSAGE "helloworld from sigaction direct shellcode!\n"

static const unsigned char shellcode[] =
    "\xb8\x01\x00\x00\x00"             /* mov eax, 1 (sys_write) */
    "\xbf\x01\x00\x00\x00"             /* mov edi, 1 (stdout) */
    "\x48\x8d\x35\x08\x00\x00\x00"     /* lea rsi, [rip + 8] */
    "\xba\x2c\x00\x00\x00"             /* mov edx, 44 */
    "\x0f\x05"                         /* syscall */
    "\xc3"                             /* ret */
    MESSAGE;

int main(void)
{
    void *code = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    memcpy(code, shellcode, sizeof(shellcode));

    if (mprotect(code, sizeof(shellcode), PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = (void (*)(int))code;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    if (raise(SIGUSR1) != 0) {
        perror("raise");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    (void)munmap(code, sizeof(shellcode));
    return EXIT_SUCCESS;
}
