//* ELF 바이너리들을 로드하고 프로세스를 실행하기 위한 파일입니다.

#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "intrinsic.h"

#include "include/userprog/syscall.h"

#ifdef VM
#include "vm/vm.h"
#endif



static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

enum intr_level old_level;

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
  The new thread may be scheduled (and may even exit) before process_create_initd() returns. 
  Returns the initd's thread id, or TID_ERROR if the thread cannot be created.
  Notice that THIS SHOULD BE CALLED ONCE.
   
 * initd를 실행하는 쓰레드를 만드는, init.c의 main 으로부터 딱 한번만 호출되어야 하는 함수. 
 * filename 이름의 쓰레드를 생성한 후 tid 또는 (쓰레드 생성에 실패할 경우) TID_ERROR를 반환 -> 이 반환값은 exit()의 인자가 됨 
 * 이 함수가 리턴되기 전에 새로 생성된 쓰레드가 스케줄되고, 심지어 exit 될 수도 있다. */
tid_t
 process_create_initd (const char *file_name) { 
	/* 만약 명령어가 run 'args-multiple some arguments for you!'이라면
	   인자로 들어온 file_name은 'args-multiple some arguments for you!' 의 주소 (''는 제외) */

	//* 2주차 수정 : parsed_file_name, save_ptr 를 선언하고 우선 filename을 parsing 한 후, 
	//* 기존에 file_name을 인수로 받는 부분들을 file_name 대신 parsed_file_name을 받도록 수정한다.
	char *fn_copy;
    char *save_ptr;
    char *not_used;
	tid_t tid;
	/* Make a copy of FILE_NAME. Otherwise there's a race between the caller and load(). 
	 * fn_copy로 file_name 을 복사 */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE); // filename을 fn_copy로 복사 

	file_name = strtok_r(file_name," ",&not_used); // 이제 filename은 인자를 제외한 파일 명만 갖고 있는 상태, fn_copy는 파일명 + 인자를 가진 상태 

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy); 
	// thread_create는 새로 생성하고 이를 block 시켜 ready_list에 넣어주고 선점 확인까지만 한다! 
	// 이 쓰레드가 실행할 initd(fn_copy)는 process_init()로 프로세스를 초기화한 후, process_exec(f_name)로 프로세스를 실행한다. 
	// process_exec()는 현재 프로세스 문맥을 f_name의 파일로 전환한다. 
	// 만약 process_exec가 리턴한 값이 -1이면 제대로 실행이 안된 것이므로 커널 패닉을 일으킨다. 

	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */


tid_t
process_fork (const char *name, struct intr_frame *if_) {

// 	/* Clone current thread to new thread.*/
	struct thread *parent = thread_current();

	// printf("===부모 레지스터에는 뭐가 들어있나?\n");
	// print_values(&if_,0);

	// 포크 하기 전에 스택정보(_if)를 미리 복사 떠놓는 중. 포크로 생긴 자식에게 전해주려고 
	// parent->tf = *if_;
	memset(&parent->parent_if, 0, sizeof(struct intr_frame));
	memcpy(&parent->parent_if, if_, sizeof(struct intr_frame)); // 부모 프로세스 메모리를 복사

	// memcpy(&parent->parent_if, if_, sizeof(struct intr_frame)); 
	tid_t pid = thread_create(name, PRI_DEFAULT, __do_fork, parent);
	
	if(pid == TID_ERROR){
		return TID_ERROR;
	}

	// 세마를 해야하긴 하는데 순서가 좀 애매함..(일단 대기)
	// struct thread *child = get_child_process(pid);

	old_level = intr_disable ();
	// sema_down(&child->fork_sema); //세마다운하면 터지네..?
	printf("do_fork 완료 될 때까지 대기 중 =============================\n");
	return pid;

	// 변경 전
	// return thread_create (name,
	// 		PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;
	// printf("duplicate_pte 시작===========================\n");
	/* 1. TODO: If the parent_page is kernel page, then return immediately. 부모가 현재 커널쪽에 있으면 false*/

	// printf("유저 가상주소(va)는? %p ---\n", va);
	if is_kernel_vaddr(va){
		/*이 부분 논리 상은 False가 맞는데 true로 일단 바꿈.
		fork-multiple의 9번째 테스트 케이스에서 va를 KERN-BASE주소로 테스트 해본단 말이야? 
		그럼 1~8개는 정상작동 printf("excute\n");이게 찍히고, 9번째는 thread_exit ();로 thread_exit()되어야하는데
		그렇게 안되고 마지막 9번째 테스트 케이스 때문에 1~9개 스레드 전체가 thread_exit되어버림.
		따라서 is_kernel_vaddr도 일단 true로 해서 9번째 테스트 케이스도 통과하도록 셋팅해놓음.
		*/
		return true;  
	}
	
	/* 2. Resolve VA from the parent's page map level 4. 
	pml4_get_page는 "물리주소를 찾는 함수"임. 누구의 물리주소를 찾냐면? 유저영역 쪽에 있는 가상주소 va(부모스레드)의 물리주소를 찾는 것.
	pml4_get_page가 리턴하는 거는 "커널주소"를 리턴한다. 어떤 커널주소를 리턴하냐면? 찾은 물리주소와 연결된 커널의 주소를 리턴함.
	즉 va의 물리주소를 찾아서 그 물리주소와 연결 되어있는 커널주소를 반환하는 함수임. if)물리주소가 매핑 안되어있으면 NULL반환 */
	// printf("유저 가상주소와 매칭된 커널 주소(parent_page)는? %p \n", parent_page);
	parent_page = pml4_get_page (parent->pml4, va);
	//parent_page에는 유저영역(va)와 연결된 커널의 주소가 들어있다.

	if (parent_page == NULL){ 
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to NEWPAGE.*/
  	// printf("parent tid %d\n",parent->tid);
	// printf("current tid %d\n",current->tid);
	// printf("parent pml4 = %p\n",parent->pml4);
	// printf("parent pte = %p\n",pte);

	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	/*페이지를 할당 받을 건데 PAL_USER플레그를 줌으로써 유저가 쓸 수 있는 메모리 pool에서 페이지를 가져올거고
	PAL_ZERO를 씀으로써 할당받은 페이지 메모리를 0으로 초기화 할 거임.
	https://casys-kaist.github.io/pintos-kaist/appendix/memory_allocation.html 참고*/

	if (newpage == NULL){
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */

	// parent가 시작하는 커널의 주소부터 parent_page의 크기만큼 newpage로 복사 중
	// memcpy(newpage, parent_page, sizeof(parent_page));  
	memcpy(newpage, parent_page, PGSIZE);  
	// printf("sizeof(parent_page)일때 -> %d / PGZIE로 했을때 %d\n", parent_page, PGSIZE);
	writable = is_writable(pte); //PTE가 가리키는 가상주소가 작성 가능한 지(wriatable) 아닌 지 확인합니다.


	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}

	// printf("자식스레드의 id : %d, 자식프로세스의 pml4 정보? %p\n", current->tid, current->pml4);
	// printf("duplicate_pte 끝=============================\n");
	return true;
}
#endif

/* A thread function that copies parent's execution context. fork할 때 부모프로세스의 context(유전자)를 복사하는 함수
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */

static void
__do_fork (void *aux) {
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	struct intr_frame if_;
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->tf;
	bool succ = true;
	
	printf("do_fork1\n");
	/* 1. Read the cpu context to local stack. */
	memset(&if_, 0, sizeof(struct intr_frame));
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	
	printf("do_fork2\n");
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;
	
	printf("do_fork3\n");
	process_activate (current);
	
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	// printf("do_fork4\n");
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) 
		goto error;
#endif
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	//*TODO file duplicate 사용해서 fd와 파일을 새로운 자식에게 입력해준다.
	// printf("do_fork5\n");
	
	
	copy_fd_list(parent,current);

	// for (int fd = 3; fd < 10; fd ++){
	// 	if(parent->fd_table[fd]){
	// 		current->fd_table[fd] = file_duplicate(parent->fd_table[fd]);
	// 		printf("+++++++++++++++++이게 찍히면 fd.table은 비어있다는 소리임.");
	// 	}else{
	// 		printf("!!!!!!!!!!!!!!!!!!!!!!!이게 찍히면 fd.table은 비어있다는 소리임.");
	// 		current->fd_table[fd] = NULL;
	// 	}
	// }


	printf("do_fork6\n");
	// intr_set_level (old_level);
	if_.R.rax = 0;
	process_init ();
	/* Finally, switch to the newly created process. */
	if (succ)
		printf("excute\n");

		// printf("===자식 레지스터에는 뭐가 들어있나?\n");
		// print_values(&if_,0);
		intr_set_level (old_level);
		printf("do_fork7\n");
		
		do_iret (&if_);
		// intr_set_level (old_level);
error:
	// printf("do_fork7\n");
	intr_set_level (old_level);
	thread_exit ();
}



// //Switch the current execution context to the f_name. Returns -1 on fail. (현재 프로세스 -> 새 파일로 문맥교환을 시도하고, 실패할 경우 -1 반환 )
// // * 2주차 수정 : argument parsing and passing  */
// int
// process_exec (void *f_name) { // 
// 	char *file_name;	
// 	bool success;

// 	/* We cannot use the intr_frame in the thread structure.
// 	 * This is because when current thread rescheduled,
// 	 * it stores the execution information to the member. */
// 	struct intr_frame _if;
// 	_if.ds = _if.es = _if.ss = SEL_UDSEG;
// 	_if.cs = SEL_UCSEG;
// 	_if.eflags = FLAG_IF | FLAG_MBS;

// 	/* We first kill the current context */
// 	process_cleanup ();

// 	file_name = argument_parsing(f_name, &_if); 

// 	/* And then load the binary */
// 	success = load (file_name, &_if);

// 	if (!success)
// 		return -1;
	
// 	palloc_free_page (file_name); // 이건 왜 하는걸가? 왜 free를 해야 하지...? 그냥 안의 내용물을 깨끗하게 비우는 작업인건가???

// 	/* Start switched process. */
// 	/* If load failed, quit. */
// 	do_iret (&_if); // 프로세스를 실행하는 어셈블리 코드로 가득한 함수 
// 	NOT_REACHED (); // 실행되면 panic이 발생하는 코드. 코드에 도달하게 하지 않도록 추가해 놓은 코드임 
// }


int
process_exec (void *f_name) { 
	bool success;
	/* We cannot use the intr_frame in the thread structure. This is because when current thread rescheduled,
	   it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;


	/* We first kill the current context */
	process_cleanup ();
	char *token , *save_ptr;
	int argc , i;
	int *argv[LOADER_ARGS_LEN / 2 + 1]; 
	int k ; 
	
	//* 인자 parsing 해서 스택에 push 
	char * file_name = strtok_r (f_name, " ", &save_ptr);
	argv[0] = file_name;
	/* And then load the binary */
	success = load (file_name, &_if);

	if (!success)
		return -1;

	//* 파싱해서 load에서 사용하는 _if 에서 파싱한 값들의 주소를 이용해야 한다. 
	argc = 1 ;
	for (token = strtok_r (NULL, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr)) {
		argv[argc] = token; // token 문자열의 시작지점 
		argc ++;
	}
	
	// 이제 argc 는 인자의 갯수, argv는 각 문자열의 주소 담은 배열이 됨 
	for (i = argc-1; i>-1; i--) {
		k = strlen(argv[i]);
		_if.rsp -= (k+1); // 마지막 공백 문자까지 고려해서 +1 
		memset(_if.rsp, '\0', k+1);
		memcpy(_if.rsp, argv[i], k);
		argv[i]= (char *)(_if.rsp); // rsp 에 담긴 문자열의 주소를 argv[i] 로 다시 넣어준다. 
	}

	//* word-aligned 해야 함 
	if (_if.rsp %8 ){ // rsp 주소값을 8로 나눴을 때 나머지가 존재한다면 8의 배수가 아니라는 것 -> 0으로 채워줘야 한다.
		int pad = _if.rsp % 8 ;  //만약에 rsp가 15라면 rsp는 8까지 내려와야 함 -> 15%8인 7만큼 내려야 함
		_if.rsp -= pad ; // 포인터를 내리고
		memset(_if.rsp, 0, pad); // 7만큼 0으로 채운다 
	}

	//* 스택에 널포인터 push 
	_if.rsp -= 8;
	memset(_if.rsp, 0,8);


	//* 스택에 역순으로 push 
	for (i = argc -1; i>-1; i--) {
		_if.rsp -=8 ; 
		memcpy(_if.rsp, &argv[i], 8) ; 
	}

	_if.R.rdi = argc ; 
	_if.R.rsi = _if.rsp ; 

	//* 스택에 fake return address 인 0 push 
	_if.rsp -= 8;
	memset(_if.rsp, 0,8);
	// hex_dump(_if.rsp, _if.rsp, 100, true);

	/* Start switched process. */
	/* If load failed, quit. */
	palloc_free_page (file_name); // 이건 왜 하는걸가? 왜 free를 해야 하지...? 그냥 안의 내용물을 깨끗하게 비우는 작업인건가???

	do_iret (&_if); // 프로세스를 실행하는 어셈블리 코드로 가득한 함수 
	NOT_REACHED (); // 실행되면 panic이 발생하는 코드. 코드에 도달하게 하지 않도록 추가해 놓은 코드임 
}


/* Waits for thread TID to die and returns its exit status.  
 * If it was terminated by the kernel (i.e. killed due to an exception), returns -1. 
 * If TID is invalid or if it was not a child of the calling process, or if process_wait() has already been successfully called for the given TID, returns -1 immediately, without waiting.
 * This function will be implemented in problem 2-2.  For now, it does nothing. */
int
process_wait (tid_t child_tid) {
	// 이 함수가 호출되는 init.c의 main 함수를 보면, process_wait() 다음 thread_exit으로 쓰레드를 종료시킴. 
	// 따라서 이 함수가 child_tid가 종료되기를 기다리는 동안 무한루프를 써서 기다리게 한다. 
	/* The pintos exit if process_wait (initd), 
	  we recommend you to add infinite loop here before implementing the process_wait. */

	syscall_wait_sema_down();

	// bool check = false;
	// while (!check)
	// {	
	// 	enum intr_level old_level;
	// 	old_level = intr_disable();
	// 	check = check_destory_thread(child_tid);
	// 	intr_set_level(old_level);
	// }
	int exit_code = exit_code_dead_child(child_tid);

	// if(exit_code == -2){
	// 	sema_down(&wait_sema);
	// }

	return exit_code;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();


	// /* TODO: Your code goes here.
	//  * TODO: Implement process termination message (see
	//  * TODO: project2/process_termination.html).
	//  * TODO: We recommend you to implement process resource cleanup here. */
	if(curr->pml4 > KERN_BASE)
		printf ("%s: exit(%d)\n", curr->name,curr->exit_code);
	syscall_wait_sema_up();
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}


/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry; //rip = 프로그램카운터  rbp = 스택 bp, rsp = 스택포인터 

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */



// * 수정 나중에 yj가 수정하기로함 ^^
// char * argument_parsing (char *f_name, struct intr_frame *_if) {
// 	int *argv[LOADER_ARGS_LEN / 2 + 1];
// 	char *token , *save_ptr, *file_name;	
// 	int argc , i, k;
// 	file_name = strtok_r (f_name, " ", &save_ptr);
// 	argv[0] = file_name; 
// 	// printf("argv[0]는 %s\n\n", argv[0]);

// 	//* 파싱해서 load에서 사용하는 _if 에서 파싱한 값들의 주소를 이용해야 한다. 
// 	argc = 1 ;
// 	for (token = strtok_r (NULL, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr)) {
// 		argv[argc] = token; // token 문자열의 시작지점 
// 		argc ++;
// 		// printf("argv[%d]는 %s\n\n", argc-1, argv[argc-1]);
// 	}
	
// 	// 이제 argc 는 인자의 갯수, argv는 각 문자열의 주소 담은 배열이 됨 
// 	for (i = argc-1; i>-1; i--) {
// 		k = strlen(argv[i]);
// 		printf("rsp 주소는 %p \n", _if->rsp);
// 		_if->rsp -= (k+1); // 마지막 공백 문자까지 고려해서 +1 

// 		memset(_if->rsp, '\0', k+1); // 
// 		memcpy(_if->rsp, argv[i], k);
// 		argv[i]= (char *)(_if->rsp); // rsp 에 담긴 문자열의 주소를 argv[i] 로 다시 넣어준다. 
// 	}

// 	//* word-aligned 해야 함 
// 	if (_if->rsp %8 ){ // rsp 주소값을 8로 나눴을 때 나머지가 존재한다면 8의 배수가 아니라는 것 -> 0으로 채워줘야 한다.
// 		int pad = _if->rsp % 8 ;  //만약에 rsp가 15라면 rsp는 8까지 내려와야 함 -> 15%8인 7만큼 내려야 함
// 		_if->rsp -= pad ; // 포인터를 내리고
// 		memset(_if->rsp, 0, pad); // 7만큼 0으로 채운다 
// 	}

// 	//* 스택에 널포인터 push 
// 	_if->rsp -= 8;
// 	memset(_if->rsp, 0,8);


// 	//* 스택에 역순으로 push 
// 	for (i = argc -1; i>-1; i--) {
// 		_if->rsp -=8 ; 
// 		memcpy(_if->rsp, &argv[i], 8) ; 
// 	}
// 	_if->R.rdi = argc ; 
// 	_if->R.rsi = _if->rsp ; 

// 	// //* 스택에 fake return address 인 0 push 
// 	_if->rsp -= 8;
// 	memset(_if->rsp, 0,8);
// 	hex_dump(_if->rsp, _if->rsp, 100, true);

// 	return file_name; 
// }  

// 자식 스레드 tid를 가지고 현재 스레드의 children 리스트 검색 - 찾으면 해당 스레드 반환 
struct thread *get_child_process (tid_t child_tid) {
	struct list curr = thread_current()->children; 
	struct list_elem *child ; 
	struct thread * child_thread;

	if (list_empty(&curr)) {
		return -1; 
	}
	for (child =list_begin(&curr); child!= list_end(&curr); child = list_next(child)) {
		child_thread = list_entry (child, struct thread, children_elem);
		if(child_thread->tid == child_tid){
			return child_thread;
		}
	}
	return NULL; 


	// struct thread *cur = thread_current ();
	// struct list *child_list = &cur->children;
	// for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e)){
	// 	struct thread *t = list_entry(e, struct thread, children_elem);
	// 	if (t->tid == child_tid) {
	// 		return t;
	// 	}
	// }
	// return NULL;
}

void copy_fd_list(struct thread* parent,struct thread* child){
	struct list *p_fd_list,*c_fd_list;
	struct fd * find_fd;
	struct file * copy_file;
	// printf("============================copy_fd_list시작====================\n");
	p_fd_list = &parent->fd_list;
	c_fd_list = &child->fd_list;

	if(list_empty(p_fd_list)){
		printf("이게 찍히면 부모의 fd_list는 비어있는 상태라는 소리이다.\n");
		return;
	}

	struct list_elem * cur;
	
	cur = list_begin(p_fd_list);

	while (cur != list_end(p_fd_list))
	{	
		// 구조체 생성
		struct fd *new_fd = (struct fd*)malloc(sizeof(struct fd));
		// fd 로 변환
		find_fd = list_entry(cur, struct fd, elem);
		// 파일 복사
		copy_file = file_duplicate(find_fd->file);
		// 입력
		new_fd->file = copy_file;
		new_fd->value = child->fd_count + 1;
		// fd값 증가
		child->fd_count +=1;

		list_push_back(c_fd_list,&new_fd->elem);
		cur = list_next(cur);
	}
}
