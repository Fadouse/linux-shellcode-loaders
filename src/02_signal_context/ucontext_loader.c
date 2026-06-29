#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#define MESSAGE "helloworld from ucontext shellcode!\n"
#define CONTEXT_STACK_SIZE (64U * 1024U)

typedef void (*shellcode_func_t)(void);

static shellcode_func_t g_shellcode_func;

static const unsigned char shellcode[] =
    "\xb8\x01\x00\x00\x00"             /* mov eax, 1 (sys_write) */
    "\xbf\x01\x00\x00\x00"             /* mov edi, 1 (stdout) */
    "\x48\x8d\x35\x08\x00\x00\x00"     /* lea rsi, [rip + 8] */
    "\xba\x24\x00\x00\x00"             /* mov edx, 36 */
    "\x0f\x05"                         /* syscall */
    "\xc3"                             /* ret */
    MESSAGE;

static void shellcode_trampoline(void)
{
    g_shellcode_func();
}

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

    void *context_stack = mmap(NULL, CONTEXT_STACK_SIZE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (context_stack == MAP_FAILED) {
        perror("mmap context stack");
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    ucontext_t main_context;
    ucontext_t shellcode_context;

    if (getcontext(&shellcode_context) != 0) {
        perror("getcontext");
        (void)munmap(context_stack, CONTEXT_STACK_SIZE);
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    shellcode_context.uc_stack.ss_sp = context_stack;
    shellcode_context.uc_stack.ss_size = CONTEXT_STACK_SIZE;
    shellcode_context.uc_link = &main_context;

    g_shellcode_func = (shellcode_func_t)code;
    makecontext(&shellcode_context, shellcode_trampoline, 0);

    if (swapcontext(&main_context, &shellcode_context) != 0) {
        perror("swapcontext");
        (void)munmap(context_stack, CONTEXT_STACK_SIZE);
        (void)munmap(code, sizeof(shellcode));
        return EXIT_FAILURE;
    }

    (void)munmap(context_stack, CONTEXT_STACK_SIZE);
    (void)munmap(code, sizeof(shellcode));
    return EXIT_SUCCESS;
}
