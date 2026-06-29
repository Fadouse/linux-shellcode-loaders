#include <unistd.h>

__attribute__((constructor))
static void dt_needed_constructor(void) {
    static const char message[] = "helloworld from DT_NEEDED shellcode-style dependency!\n";
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1U);
}

void dt_needed_payload_anchor(void) {
}
