#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    const char *plugin_path = (argc > 1) ? argv[1] : "./build/fixtures/plugin_payload.so";

    void *handle = dlopen(plugin_path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen(%s): %s\n", plugin_path, dlerror());
        return 1;
    }

    dlerror();
    void (*run_payload)(void) = (void (*)(void))dlsym(handle, "run_payload");
    const char *error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "dlsym(run_payload): %s\n", error);
        dlclose(handle);
        return 1;
    }

    run_payload();
    dlclose(handle);
    return 0;
}
