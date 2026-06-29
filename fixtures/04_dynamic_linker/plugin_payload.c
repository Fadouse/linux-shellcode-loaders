#include <unistd.h>

static void write_all(const char *message, unsigned long length) {
    while (length > 0) {
        ssize_t written = write(STDOUT_FILENO, message, length);
        if (written <= 0) {
            return;
        }
        message += written;
        length -= (unsigned long)written;
    }
}

void run_payload(void) {
    static const char message[] = "helloworld from dlopen shellcode-style plugin!\n";
    write_all(message, sizeof(message) - 1U);
}

void run_memfd_payload(void) {
    static const char message[] = "helloworld from memfd dlopen shellcode-style plugin!\n";
    write_all(message, sizeof(message) - 1U);
}
