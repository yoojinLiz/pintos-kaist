#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdio.h>
#include <syscall-nr.h>

struct values{
    uint64_t syscall_number;
    uint64_t rdi, rsi, rdx ,r10, r8, r9;
};

struct syscall_func {
	int syscall_number;
	void (*function) (struct values *values);
};

void syscall_init (void);

void sysall_read();
void syscall_write(struct values *values);
void syscall_exit(struct values *values);

#endif /* userprog/syscall.h */
