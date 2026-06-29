#include <unistd.h>

int main(void) {
    static const char message[] = "helloworld from shm_open fexecve shellcode-style ELF!\n";
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1U);
    return 0;
}
