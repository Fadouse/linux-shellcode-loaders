static unsigned char shellcode[] = {
    0x31, 0xc0, 0xb0, 0x01, 0x31, 0xff, 0xff, 0xc7, 0x48, 0x8d, 0x35, 0x07,
    0x00, 0x00, 0x00, 0x31, 0xd2, 0xb2, 0x2d, 0x0f, 0x05, 0xc3, 0x68, 0x65,
    0x6c, 0x6c, 0x6f, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x20, 0x66, 0x72, 0x6f,
    0x6d, 0x20, 0x63, 0x6c, 0x6f, 0x6e, 0x65, 0x2f, 0x72, 0x61, 0x77, 0x20,
    0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x20, 0x73, 0x68, 0x65, 0x6c,
    0x6c, 0x63, 0x6f, 0x64, 0x65, 0x21, 0x0a
};

#define SYS_MMAP      9L
#define SYS_MPROTECT  10L
#define SYS_CLONE     56L
#define SYS_WAIT4     61L
#define SYS_EXIT      60L

#define PROT_READ     0x1L
#define PROT_WRITE    0x2L
#define PROT_EXEC     0x4L
#define MAP_PRIVATE   0x02L
#define MAP_ANONYMOUS 0x20L
#define SIGCHLD       17L

static long raw_syscall6(long nr, long a1, long a2, long a3,
                         long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;

    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");

    return ret;
}

__attribute__((noreturn))
static void raw_exit(long code) {
    raw_syscall6(SYS_EXIT, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void copy_bytes(unsigned char *dst, const unsigned char *src, unsigned long len) {
    for (unsigned long i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

void _start(void) {
    unsigned long len = sizeof(shellcode);

    long mem_ret = raw_syscall6(SYS_MMAP, 0, (long)len,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS,
                                -1, 0);
    if (mem_ret < 0) {
        raw_exit(1);
    }

    unsigned char *mem = (unsigned char *)mem_ret;
    copy_bytes(mem, shellcode, len);

    if (raw_syscall6(SYS_MPROTECT, (long)mem, (long)len,
                     PROT_READ | PROT_EXEC, 0, 0, 0) < 0) {
        raw_exit(1);
    }

    long pid = raw_syscall6(SYS_CLONE, SIGCHLD, 0, 0, 0, 0, 0);
    if (pid == 0) {
        ((void (*)(void))mem)();
        raw_exit(0);
    }

    if (pid > 0) {
        raw_syscall6(SYS_WAIT4, pid, 0, 0, 0, 0, 0);
        raw_exit(0);
    }

    raw_exit(1);
}
