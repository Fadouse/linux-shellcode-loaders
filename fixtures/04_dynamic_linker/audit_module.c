#define _GNU_SOURCE

#include <link.h>
#include <unistd.h>

unsigned int la_version(unsigned int version)
{
    static const char msg[] = "helloworld from LD_AUDIT shellcode-style audit!\n";
    (void)version;
    (void)write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    return LAV_CURRENT;
}
