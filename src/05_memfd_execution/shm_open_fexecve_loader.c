#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

static int copy_all(int out_fd, int in_fd) {
    unsigned char buffer[8192];

    for (;;) {
        ssize_t nread = read(in_fd, buffer, sizeof(buffer));
        if (nread == 0) {
            return 0;
        }
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        for (ssize_t offset = 0; offset < nread;) {
            ssize_t nwritten = write(out_fd, buffer + offset, (size_t)(nread - offset));
            if (nwritten < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            offset += nwritten;
        }
    }
}

int main(int argc, char **argv) {
    const char *payload_path = (argc > 1) ? argv[1] : "./build/fixtures/shm_payload";

    char shm_name[128];
    int name_len = snprintf(shm_name, sizeof(shm_name), "/shellcode_learn_%ld", (long)getpid());
    if (name_len < 0 || (size_t)name_len >= sizeof(shm_name)) {
        fprintf(stderr, "shm name truncated\n");
        return 1;
    }

    int in_fd = open(payload_path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        perror("open payload");
        return 1;
    }

    struct stat st;
    if (fstat(in_fd, &st) != 0) {
        perror("fstat payload");
        close(in_fd);
        return 1;
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "payload is empty\n");
        close(in_fd);
        return 1;
    }

    int write_fd = shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, 0700);
    if (write_fd < 0) {
        perror("shm_open write fd");
        close(in_fd);
        return 1;
    }

    if (ftruncate(write_fd, st.st_size) != 0) {
        perror("ftruncate shm");
        shm_unlink(shm_name);
        close(write_fd);
        close(in_fd);
        return 1;
    }

    if (copy_all(write_fd, in_fd) != 0) {
        perror("copy payload to shm");
        shm_unlink(shm_name);
        close(write_fd);
        close(in_fd);
        return 1;
    }
    close(in_fd);

    if (fchmod(write_fd, 0700) != 0) {
        perror("fchmod shm");
        shm_unlink(shm_name);
        close(write_fd);
        return 1;
    }

    int exec_fd = shm_open(shm_name, O_RDONLY, 0);
    if (exec_fd < 0) {
        perror("shm_open exec fd");
        shm_unlink(shm_name);
        close(write_fd);
        return 1;
    }

    /* Keep only the executable read-only fd; remove the visible /dev/shm name. */
    if (shm_unlink(shm_name) != 0) {
        perror("shm_unlink");
        close(exec_fd);
        close(write_fd);
        return 1;
    }
    close(write_fd);

    char *exec_argv[] = { (char *)payload_path, NULL };
    fexecve(exec_fd, exec_argv, environ);

    perror("fexecve shm");
    close(exec_fd);
    return 1;
}
