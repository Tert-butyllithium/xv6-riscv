#include "user/thread.h"
#include "user/user.h"
#include "kernel/riscv.h"
// #include "kernel/types.h"
// #include "kernel/defs.h"
// #include "kernel/proc.h"

int thread_create(void *(start_routine)(void*), void *arg) {
	// Allocate stack for thread

	void *stack_base = (void*)malloc(PGSIZE)+PGSIZE-1;

	// Create thread
	int pid = clone(stack_base);

	if (pid < 0) {
		// Fail
		return -1;
	} else if (pid == 0) {
		// Child thread
		start_routine(arg);
		exit(0);
	} else {
		// Parent thread
		return 0;
	}
}

void lock_init(struct lock_t* lock) {
	lock = (struct lock_t*)malloc(sizeof(struct lock_t));
	lock->locked = 0;
}

void lock_acquire(struct lock_t* lock) {
	while (__sync_lock_test_and_set(&lock->locked, 1));
	__sync_synchronize();
}

void lock_release(struct lock_t* lock) {
	__sync_lock_release(&lock->locked);
	__sync_synchronize();
}

