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
bool sys_create (const char *file, unsigned initial_size);
void syscall_read (int fd, void *buffer, unsigned size);
void syscall_write (int fd, const void *buffer, unsigned size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int syscall_filesize (int fd);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);
void sysall_read();
void syscall_write(struct values *values);
void syscall_exit(struct values *values);

#endif /* userprog/syscall.h */
