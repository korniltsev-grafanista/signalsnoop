#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>

static volatile int handler_called = 0;

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    printf("SIGSEGV handler called!\n");
    printf("  Signal: %d\n", sig);
    printf("  Faulting address: %p\n", info->si_addr);
    handler_called = 1;
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

    printf("SIGSEGV handler installed, dereferencing 0xcafebabe...\n");

    volatile int *bad_ptr = (volatile int *)0xcafebabe;
    int value = *bad_ptr;

    (void)value;
    printf("Should not reach here\n");
    return 1;
}
