#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "include/threads/interrupt.h"
#include "lib/kernel/list.h"

typedef int pid_t;

struct syscall_func {
	int syscall_number;
	void (*function) (struct intr_frame *f);
};
void syscall_init (void);

struct lock filesys_lock;

// syscall function

void syscall_halt(void);
void syscall_exit(struct intr_frame *f);
// fork func parameter : const char *thread_name
pid_t syscall_fork (struct intr_frame *f);
// exec func parameter : const char *cmd_line
// int syscall_exec (const char *cmd_line);
int syscall_exec (struct intr_frame *f);
// wait func parameter : pid_t pid
int syscall_wait (struct intr_frame *f);
bool syscall_create (struct intr_frame *f);
// remove func parameter : chonst char *file
bool syscall_remove (struct intr_frame *f);
// open func parameter : const char *file
int syscall_open (struct intr_frame *f);
// filesize func parameter : int fd
int syscall_filesize (struct intr_frame *f);
// read func parameter : int fd, void *buffer, unsigned size
int syscall_read (struct intr_frame *f);
// write func parameter : int fd, const void *buffer, unsigned size
void syscall_write(struct intr_frame *f);
// seek func parameter : int fd, unsigned position
void syscall_seek (struct intr_frame *f);
// tell func parameter : int fd
unsigned syscall_tell (struct intr_frame *f);
// close func larameter : int fd
void syscall_close (struct intr_frame *f);

// 공용 함수

void syscall_abnormal_exit(short exit_code);
// f의 값 출력 type 0 : d 출력, 1 : s 출력, 2 : 둘다 출력
void print_values(struct intr_frame *f,int type);

bool check_ptr_address(struct intr_frame *f);

void check_addr(void * addr); // 할당받는 유저 메모리 영역인지 확인 후, 아니라면 exit(-1)을 실행하는 함수입니다. (유진 추가)

struct list_elem* find_elem_match_fd_value(int fd_value);
void clear_fd_list();

//struct fd * find_matched_fd(int fd_value);



void file_lock_acquire();
void file_lock_release();
#endif /* userprog/syscall.h */
