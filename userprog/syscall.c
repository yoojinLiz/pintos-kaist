/*
* 유저 프로세스가 일부 커널 기능에 접근하려고 할때마다 시스템 콜이 호출되는게시스템 콜 핸들러의 기본 구조입니다. 
* 현재 상태에서는 이때 단지 메세지를 출력하고 유저 프로세스를 종료시키게 되어있습니다. 
* (2주차) 이번 프로젝트의 part2에서 시스템 콜이 필요로 하는 다른 일을 수행하는 코드를 수행하게 될 겁니다.

* 여러분이 구현하는 시스템 콜 핸들러는 시스템 콜 번호를 받아오고, 
* 어떤 시스템 콜 인자라도 받아온 후 알맞은 액션을 취해야 합니다.

*/

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

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

void syscall_exit(struct values *values);
void syscall_write(struct values *values);


struct syscall_func syscall_func[] = {
	{SYS_HALT,syscall_exit},
	{SYS_EXIT,syscall_exit},
	{SYS_FORK,syscall_exit},
	{SYS_EXEC,syscall_exit},
	{SYS_WAIT,syscall_exit},
	{SYS_CREATE,syscall_exit},
	{SYS_REMOVE,syscall_exit},
	{SYS_OPEN,syscall_exit},
	{SYS_FILESIZE,syscall_exit},
	{SYS_READ,syscall_exit},
	{SYS_WRITE,syscall_write},
	{SYS_SEEK,syscall_exit},
	{SYS_WRITE,syscall_exit},
	{SYS_TELL,syscall_exit},
	{SYS_CLOSE,syscall_exit},
};


/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {

	// TODO: Your implementation goes here.
	struct values values;
	values.syscall_number = f->R.rax;
	values.rdi = f->R.rdi;
	values.rsi = f->R.rsi;
	values.rdx = f->R.rdx;
	values.r10 = f->R.r10;
	values.r8 = f->R.r8;
	values.r9 = f->R.r9;

	struct syscall_func call = syscall_func[values.syscall_number];
	call.function (&values);
}


void syscall_write(struct values *values){
	printf("%s",values->rsi);
}
void syscall_exit(struct values *values){
	thread_exit();
}