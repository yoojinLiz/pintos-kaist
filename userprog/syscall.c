/*
* 유저 프로세스가 일부 커널 기능에 접근하려고 할때마다 시스템 콜이 호출되는게시스템 콜 핸들러의 기본 구조입니다. 
* 현재 상태에서는 이때 단지 메세지를 출력하고 유저 프로세스를 종료시키게 되어있습니다. 
* (2주차) 이번 프로젝트의 part2에서 시스템 콜이 필요로 하는 다른 일을 수행하는 코드를 수행하게 될 겁니다.

* 여러분이 구현하는 시스템 콜 핸들러는 시스템 콜 번호를 받아오고, 
* 어떤 시스템 콜 인자라도 받아온 후 알맞은 액션을 취해야 합니다.

*/

#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "../include/filesys/file.h"
#include "filesys/inode.h"
#include "../include/userprog/process.h"

#include "userprog/process.h"



void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. 
 * 
 * x86-64에서는 syscall 으로 시스템 콜을 요청하는 방법이 제공되고, syscall 인스트럭션은 MSR로 부터 값을 읽어옴으로써 동작한다 */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */

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

struct list_elem* find_elem_match_fd_value(int fd_value);

struct syscall_func syscall_func[] = {
	{SYS_HALT,syscall_halt},
	{SYS_EXIT,syscall_exit},
	{SYS_FORK,syscall_fork},
	{SYS_EXEC,syscall_exec},
	{SYS_WAIT,syscall_wait},
	{SYS_CREATE,syscall_create},
	{SYS_REMOVE,syscall_remove},
	{SYS_OPEN,syscall_open},
	{SYS_FILESIZE,syscall_filesize},
	{SYS_READ,syscall_read},
	{SYS_WRITE,syscall_write},
	{SYS_SEEK,syscall_seek},
	{SYS_TELL,syscall_tell},
	{SYS_CLOSE,syscall_close},
};



/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.

	// !전체 시스템 콜에 영향을 주는 곳입니다. 최대한 작성을 지양 해주세요

	// print_values(f,0);

	struct syscall_func call = syscall_func[f->R.rax];
	call.function (f);

}

// syscall function

void syscall_halt(void){
	//핀토스 전체를 종료.
	power_off();	
}


void syscall_exit(struct intr_frame *f){
	thread_current()->exit_code = f->R.rdi;
	thread_exit();
}


// fork func parameter : const char *thread_name
pid_t syscall_fork (struct intr_frame *f){



	char * thread_name = f->R.rdi;

	int return_value;
	return_value = process_fork(thread_name, f);

	f->R.rax = return_value;

}


// exec func parameter : const char *cmd_line
// int syscall_exec (const char *cmd_line){
int syscall_exec (struct intr_frame *f){

}


// wait func parameter : pid_t pid
int syscall_wait (struct intr_frame *f){

}


bool syscall_create (struct intr_frame *f){
	char * file = f->R.rdi;
	int size = f->R.rsi;
	// printf("rax %d!!!, rdi %s!!!, rsi %d!!!\n",f->R.rax, f->R.rdi, f->R.rsi);
	if (filesys_create(file, size)){
		return true;
	}else{
		return false;
	}
	
}


// remove func parameter : chonst char *file
bool syscall_remove (struct intr_frame *f){
	print_values(f,2);
	
}


// open func parameter : const char *file
int syscall_open (struct intr_frame *f){

}


// filesize func parameter : int fd
int syscall_filesize (struct intr_frame *f){

}


// read func parameter : int fd, void *buffer, unsigned size
int syscall_read (struct intr_frame *f){

}


// write func parameter : int fd, const void *buffer, unsigned size
void syscall_write(struct intr_frame *f){
	check_addr(f->R.rsi);

	int fd_value = f->R.rdi;
	char *buf = f->R.rsi;
	int size = f->R.rdx;

	if (fd_value == 1){ //fd는 0은 입력, 1은 출력으로 정해짐
		putbuf(buf, size); //putbuf는 buf에 들어있는 값을 size만큼 출력
	}
	return size;

}


// seek func parameter : int fd, unsigned position
void syscall_seek (struct intr_frame *f){

}


// tell func parameter : int fd
unsigned syscall_tell (struct intr_frame *f){

}


// close func larameter : int fd
void syscall_close (struct intr_frame *f){

}

// 공용 함수

void syscall_abnormal_exit(short exit_code){
	thread_current()->exit_code = exit_code;
	thread_exit();
}

// f의 값 출력 type 0 : d 출력, 1 : s 출력, 2 : 둘다 출력
void print_values(struct intr_frame *f,int type){

	printf("call_num   %d\n",f->R.rax);
	printf("rdi        %d\n",f->R.rdi);
	if(type == 0){
		printf("rsi        %d\n",f->R.rsi);
	}else if(type == 1){
		if(f->R.rsi == 0){
			printf("rsi        %s\n",f->R.rsi);
		}else{
			printf("rsi        %s",f->R.rsi);
		}
	}else if(type == 2){
		printf("rsi        %d\n",f->R.rsi);
		if(f->R.rsi == 0){
			printf("rsi        %s\n",f->R.rsi);
		}else{
			printf("rsi        %s",f->R.rsi);
		}
	}
	printf("rdx        %d\n",f->R.rdx);
	printf("r10        %d\n",f->R.r10);
	printf("r8         %d\n",f->R.r8);
	printf("r9         %d\n",f->R.r9);
}

bool check_ptr_address(struct intr_frame *f){
	bool success = false;
	if (f->rsp < f->R.rdi && f->rsp + (1<<12) <f->R.rdi){
		success = true;
	}
	return success;
}

/*주소 값이 유저 영역에서 사용하는 주소 값인지 확인하는 함수. 유저영역이 아니면 -1 반환*/
void check_addr(void * addr) {
	struct thread *t = thread_current();
	if(is_kernel_vaddr(addr) || pml4_get_page(t->pml4, addr)== NULL ){
	/* pml4_get_page(t->pml4, addr) : pml4_get_page()는 두번째 인자로 들어온 유저 가상 주소와 대응하는 물리주소를 찾는다. 
	   해당 물리 주소와 연결된 커널 가상 주소를 반환하거나 만약 해당 물리 주소가 가상 주소와 매핑되지 않은 영역이면 NULL을 반환한다.
	   따라서 따라서 NULL인지 체크함으로서 포인터가 가리키는 주소가 유저 영역 내에 있지만 자신의 페이지로 할당하지 않은 영역인지 확인해야 한다 */
	   syscall_abnormal_exit(-1); 
	}
}

struct list_elem*
find_elem_match_fd_value(int fd_value){

	struct list *fd_list = &thread_current()->fd_list;
	struct list_elem * cur;

	if(list_empty(fd_list)){
		return NULL;
	}

	cur = list_begin(fd_list);
	while (cur != list_end(fd_list))
	{
		struct fd *find_fd = list_entry(cur, struct fd, elem);
		if(find_fd->value == fd_value){
			return cur;
		}
		cur = list_next(cur);
	}
	return NULL;
}



