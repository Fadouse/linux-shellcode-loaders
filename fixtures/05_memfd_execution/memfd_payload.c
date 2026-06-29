#include <unistd.h>

int main(void)
{
    static const char msg[] = "helloworld from memfd fexecve shellcode-style ELF!\n";
    (void)write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    return 0;
}
