#include <unistd.h>

__attribute__((constructor))
static void preload_message(void) {
    static const char message[] = "helloworld from LD_PRELOAD shellcode-style hook!\n";
    const char *cursor = message;
    unsigned long remaining = sizeof(message) - 1U;

    while (remaining > 0) {
        ssize_t written = write(STDOUT_FILENO, cursor, remaining);
        if (written <= 0) {
            return;
        }
        cursor += written;
        remaining -= (unsigned long)written;
    }
}
