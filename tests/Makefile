CC = gcc
CFLAGS = -Wall -Wextra -g

all: sigsegv_test bad_stack_test stack_push_deref_test

sigsegv_test: sigsegv_test.c
	$(CC) $(CFLAGS) -o $@ $<

bad_stack_test: bad_stack_test.c
	$(CC) $(CFLAGS) -o $@ $<

stack_push_deref_test: stack_push_deref_test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sigsegv_test bad_stack_test stack_push_deref_test

.PHONY: all clean
