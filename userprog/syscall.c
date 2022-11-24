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
#include "threads/malloc.h"
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
int syscall_wait (pid_t pid);
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
	power_off();	
}


void syscall_exit(struct intr_frame *f){
	thread_current()->exit_code = f->R.rdi;
	thread_exit();
}


// fork func parameter : const char *thread_name
pid_t syscall_fork (struct intr_frame *f){


	char *file_name = f->R.rdi;
	// print_values(f,1);
	return process_fork(file_name, f);
}


// exec func parameter : const char *cmd_line
// int syscall_exec (const char *cmd_line){
int syscall_exec (struct intr_frame *f){

	char *file_name = f->R.rdi;
	// char *fn_copy;
	// printf("파일 이름 %s\n", file_name);
	print_values(f,0);
	printf("%s\n",f->R.rdi);
	process_exec(file_name);

	/*
	* 현재의 프로세스가 cmd_line에서 이름이 주어지는 실행가능한 프로세스로 변경됩니다. 
	* 이때 주어진 인자들을 전달합니다. 성공적으로 진행된다면 어떤 것도 반환하지 않습니다. 
	* 만약 프로그램이 이 프로세스를 로드하지 못하거나 다른 이유로 돌리지 못하게 되면 
	* exit state -1을 반환하며 프로세스가 종료됩니다. 
	* 이 함수는 exec 함수를 호출한 쓰레드의 이름은 바꾸지 않습니다. 
	* file descriptor는 exec 함수 호출 시에 열린 상태로 있다는 것을 알아두세요.
	*/
		
	/* Make a copy of FILE_NAME. Otherwise there's a race between the caller and load(). */
	// check_addr(file_name);
	// fn_copy = palloc_get_page (0);
	// if (fn_copy == NULL)
	// {
	// 	syscall_abnormal_exit(-1);
	// 	return -1;
	// }
	// strlcpy (fn_copy, file_name, PGSIZE); // filename을 fn_copy로 복사 
	// if (process_exec (fn_copy) < 0) {
	// 	syscall_abnormal_exit(-1);
	// }
    return 0;

}

// wait func parameter : pid_t pid
int syscall_wait (pid_t pid){
	// thread_set_priority(thread_current()->priority -1);
	// printf("syscall_wait before current tid = %d\n",thread_current()->tid);
	// process_wait(pid);
	// printf("syscall_wait after current tid = %d\n",thread_current()->tid);
	return 0;
}


bool syscall_create (struct intr_frame *f){
	bool success;

	check_addr(f->R.rdi);

	if(f->R.rdi == NULL){
		syscall_abnormal_exit(-1);
	}
	success = filesys_create(f->R.rdi,f->R.rsi);
	f->R.rax = success;
	return success;
}


// remove func parameter : chonst char *file
bool syscall_remove (struct intr_frame *f){
	bool success ; 
	char* file = f->R.rdi ; // rdi : 파일 이름   
	check_addr(file); 
	success = filesys_remove(file);
	f->R.rax = success; 
	return success;
}


// open func parameter : const char *file
int syscall_open (struct intr_frame *f){

	struct file *open_file;
	struct list * fd_list;
	struct ELF64_hdr ehdr;

	fd_list = &thread_current()->fd_list;
	check_addr(f->R.rdi);
	
	open_file = filesys_open(f->R.rdi);
	if(open_file == NULL){
		f->R.rax = -1;
		return -1;
	}
	
	struct fd *fd = (struct fd*)malloc(sizeof(struct fd));

	fd->value = thread_current()->fd_count + 1;
	fd->file = open_file;
	list_push_back(fd_list,&fd->elem);
	thread_current()->fd_count +=1;

	// open 시 해더파일을 읽어서 excutable 한 파일인지 확인
	if(!(file_read (fd->file, &ehdr, sizeof ehdr) != sizeof ehdr
		|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
		|| ehdr.e_type != 2
		|| ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1
		|| ehdr.e_phentsize != sizeof (struct ELF64_PHDR)
		|| ehdr.e_phnum > 1024)){
			file_deny_write(fd->file);
		}
	open_file->pos=0;
	f->R.rax = fd->value;
	return fd->value;
}


// filesize func parameter : int fd
int syscall_filesize (struct intr_frame *f){

	int fd_value = f->R.rdi;
	struct list_elem * find_elem;
	struct fd *find_fd;

	find_elem = find_elem_match_fd_value(fd_value);
	if(find_elem == NULL){
		f->R.rax = -1;
		return -1;
	}
	find_fd = list_entry(find_elem, struct fd, elem);

	struct inode * find_inode = file_get_inode(find_fd->file);
	
	int size = inode_length(find_inode);
	f->R.rax = size;
	return size;
}


// read func parameter : int fd, void *buffer, unsigned size
int syscall_read (struct intr_frame *f){

	check_addr(f->R.rsi);
	int fd_value, size;
	fd_value = f->R.rdi;
	char* buf = f->R.rsi;
	size = f->R.rdx;

	int return_value;
	struct list_elem * read_elem;
	struct fd * read_fd;
	struct ELF64_hdr ehdr;

	read_elem = find_elem_match_fd_value(fd_value);

	if(read_elem == NULL){
		f->R.rax = -1;
		return -1;
	}

	read_fd = list_entry(read_elem, struct fd, elem);
	if(read_fd == NULL){
		return;
	}

	struct inode * find_inode = file_get_inode(read_fd->file);
	int filesize = inode_length(find_inode);

	
	return_value = file_read(read_fd->file,buf,size);

	f->R.rax = return_value;
	return return_value;
}


// write func parameter : int fd, const void *buffer, unsigned size
void syscall_write(struct intr_frame *f){
	check_addr(f->R.rsi);

	int fd_value = f->R.rdi;
	char *buf = f->R.rsi;
	int size = f->R.rdx;
	if(fd_value == 1){
		putbuf(buf,size);
		return;
	}

	int return_value;
	struct list_elem * write_elem;
	struct fd * write_fd;
	struct file *file;

	write_elem = find_elem_match_fd_value(fd_value);

	if(write_elem == NULL){
		f->R.rax = -1;
		return -1;
	}

	write_fd = list_entry(write_elem, struct fd, elem);
	if(write_fd == NULL){
		return;
	}

	if(write_fd->file->deny_write){
		f->R.rax = 0;
		return;
	}
	struct inode * find_inode = file_get_inode(write_fd->file);
	int filesize = inode_length(find_inode);

	return_value = file_write(write_fd->file,buf,size);

	f->R.rax = return_value;
	return return_value;
}


// seek func parameter : int fd, unsigned position
void syscall_seek (struct intr_frame *f){

	int fd_value = f->R.rdi;
	unsigned int offset = f->R.rsi;
	
	struct list *fd_list = &thread_current()->fd_list;
	struct list_elem * find_elem;

	find_elem = find_elem_match_fd_value(fd_value);
	if(find_elem == NULL){
		syscall_abnormal_exit(-1);
	}

	fd_list = list_entry(find_elem, struct fd, elem);
	struct fd *find_fd = list_entry(find_elem, struct fd, elem);

	file_seek(find_fd->file,offset);
}


// tell func parameter : int fd
unsigned syscall_tell (struct intr_frame *f){
	int fd_value = f->R.rdi;
	struct list *fd_list = &thread_current()->fd_list;
	struct list_elem * find_elem;

	find_elem = find_elem_match_fd_value(fd_value);
	if(find_elem == NULL){
		syscall_abnormal_exit(-1);
	}

	fd_list = list_entry(find_elem, struct fd, elem);
	struct fd *find_fd = list_entry(find_elem, struct fd, elem);

	unsigned int position = file_tell(find_fd->file);

	f->R.rax = position;
	return position;
}


// close func larameter : int fd
void syscall_close (struct intr_frame *f){

	int fd_value = f->R.rdi;
	struct list *fd_list = &thread_current()->fd_list;
	struct list_elem * find_elem;


	find_elem = find_elem_match_fd_value(fd_value);
	if(find_elem == NULL){
		syscall_abnormal_exit(-1);
	}

	fd_list = list_entry(find_elem, struct fd, elem);
	struct fd *find_fd = list_entry(find_elem, struct fd, elem);

	file_close(find_fd->file);
	list_remove(find_elem);
	free(find_fd);
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



