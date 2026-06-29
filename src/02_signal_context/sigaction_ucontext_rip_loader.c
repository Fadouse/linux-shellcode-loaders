#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define MESSAGE "helloworld from sigaction ucontext RIP shellcode!\n"

static void *g_shellcode_page;
static void *g_resume_address;

static const unsigned char shellcode[] =
    "\xb8\x01\x00\x00\x00"             /* mov eax, 1 (sys_write) */
    "\xbf\x01\x00\x00\x00"             /* mov edi, 1 (stdout) */
    "\x48\x8d\x35\x08\x00\x00\x00"     /* lea rsi, [rip + 8] */
    "\xba\x32\x00\x00\x00"             /* mov edx, 50 */
    "\x0f\x05"                         /* syscall */
    "\xc3"                             /* ret */
    MESSAGE;

static void redirect_rip_handler(int signo, siginfo_t *info, void *context)
{
    (void)signo;
    (void)info;

    ucontext_t *uc = context;
    greg_t rsp = uc->uc_mcontext.gregs[REG_RSP] - (greg_t)sizeof(void *);
    void **return_slot = (void **)(uintptr_t)rsp;

    *return_slot = g_resume_address;
    uc->uc_mcontext.gregs[REG_RSP] = rsp;
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)g_shellcode_page;
}

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
    sa.sa_sigaction = redirect_rip_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    g_shellcode_page = code;
    g_resume_address = &&after_shellcode;

    long syscall_number = SYS_kill;
    long syscall_result;

    __asm__ volatile (
        "syscall"
        : "+a" (syscall_number)
        : "D" ((long)getpid()), "S" ((long)SIGUSR1)
        : "rcx", "r11", "memory");
    syscall_result = syscall_number;

    if (syscall_result != 0) {
        errno = (int)-syscall_result;
        perror("kill syscall");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

after_shellcode:
    (void)munmap(code, sizeof(shellcode));
    return EXIT_SUCCESS;
}
