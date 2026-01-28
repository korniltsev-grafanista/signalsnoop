#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    printf("SIGSEGV handler called!\n");
    printf("  Signal: %d\n", sig);
    printf("  Faulting address: %p\n", info->si_addr);
    exit(0);
}

int main(void) {
    struct sigaction sa;

    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("sigaction");
        return 1;
    }

    printf("SIGSEGV handler installed, setting RSP to 0xdead000 and pushing...\n");

    __asm__ volatile (
        "mov $0xdead000, %%rsp\n\t"
        "push %%rax\n\t"
        :
        :
        : "memory"
    );

    printf("Should not reach here\n");
    return 1;
}
