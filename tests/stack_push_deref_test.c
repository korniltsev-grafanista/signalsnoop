#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096
#define DEFAULT_OFFSET 128

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    printf("SIGSEGV handler called!\n");
    printf("  Signal: %d\n", sig);
    printf("  Faulting address: %p\n", info->si_addr);
    exit(0);
}

int main(int argc, char *argv[]) {
    long offset = DEFAULT_OFFSET;

    if (argc > 1) {
        offset = strtol(argv[1], NULL, 0);
    }
    struct sigaction sa;

    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("sigaction");
        return 1;
    }

    void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("SIGSEGV handler installed, mmapped RW page at %p\n", page);
    printf("Setting RSP to page+%ld, pushing 0xcafebabe, then dereferencing 0xdead000...\n", offset);

    __asm__ volatile (
        "mov %0, %%rsp\n\t"
        "add %1, %%rsp\n\t"
        "mov $0xcafebabe, %%rcx\n\t"
        "push %%rcx\n\t"
        "mov $0xdead000, %%rax\n\t"
        "mov (%%rax), %%rbx\n\t"
        "push %%rbx\n\t"
        :
        : "r"(page), "r"(offset)
        : "memory", "rax", "rbx", "rcx"
    );

    printf("Should not reach here\n");
    return 1;
}
