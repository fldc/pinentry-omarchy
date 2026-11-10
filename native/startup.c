// Loaded by the dynamic linker before Quickshell main and QML initialization.
// execve resets dumpability, so the parent's hardening alone is insufficient.
// The loader interval before this constructor still requires OS ptrace policy.
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

static int hardened;

int pinentry_startup_ready(void) {
    return hardened;
}

__attribute__((constructor)) static void pinentry_harden_startup(void) {
    const struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) != 0 ||
        prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
        _exit(125);
    }
    hardened = 1;
}
