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

struct fork_info
{
	struct thread *parent_t;
	struct intr_frame *if_;
};

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

/* General process initializer for initd and other process. */
static void
process_init(void)
{
	struct thread *current = thread_current();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
  The new thread may be scheduled (and may even exit) before process_create_initd() returns.
  Returns the initd's thread id, or TID_ERROR if the thread cannot be created.
  Notice that THIS SHOULD BE CALLED ONCE.

 initd를 실행하는 쓰레드를 만드는, init.c의 main 으로부터 딱 한번만 호출되어야 하는 함수.
 filename 이름의 쓰레드를 생성한 후 tid 또는 (쓰레드 생성에 실패할 경우) TID_ERROR를 반환 -> 이 반환값은 exit()의 인자가 됨
 이 함수가 리턴되기 전에 새로 생성된 쓰레드가 스케줄되고, 심지어 exit 될 수도 있다. */
tid_t process_create_initd(const char *file_name)
{
	/* 만약 명령어가 run 'args-multiple some arguments for you!'이라면
	   인자로 들어온 file_name은 'args-multiple some arguments for you!' 의 주소 (''는 제외) */
	// 2주차 수정 : parsed_file_name, save_ptr 를 선언하고 우선 filename을 parsing 한 후,
	// 기존에 file_name을 인수로 받는 부분들을 file_name 대신 parsed_file_name을 받도록 수정한다.
	char *fn_copy;
	char *save_ptr;
	char *not_used;
	tid_t tid;
	/* fn_copy로 file_name 을 복사 */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE); // filename을 fn_copy로 복사

	file_name = strtok_r(file_name, " ", &not_used); // 이제 filename은 인자를 제외한 파일 명만 갖고 있는 상태, fn_copy는 파일명 + 인자를 가진 상태

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
	// thread_create는 새로 생성하고 이를 block 시켜 ready_list에 넣어주고 선점 확인까지만 한다!
	// 이 쓰레드가 실행할 initd(fn_copy)는 process_init()로 프로세스를 초기화한 후, process_exec(f_name)로 프로세스를 실행한다.
	// process_exec()는 현재 프로세스 문맥을 f_name의 파일로 전환한다.
	// 만약 process_exec가 리턴한 값이 -1이면 제대로 실행이 안된 것이므로 커널 패닉을 일으킨다.

	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */

tid_t process_fork(const char *name, struct intr_frame *if_)
{
	// 	/* Clone current thread to new thread.*/
	struct fork_info *fork_info = (struct fork_info *)malloc(sizeof(struct fork_info));
	fork_info->parent_t = thread_current();
	fork_info->if_ = if_;

	tid_t pid = thread_create(name, PRI_DEFAULT, __do_fork, fork_info);
	process_fork_sema_down();

	if (!thread_current()->make_child_success)
	{
		return -1;
	}
	return pid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct fork_info *fork_info = (struct fork_info *)aux;
	struct thread *parent = fork_info->parent_t;

	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately.*/
	if is_kernel_vaddr (va)
	{
		return true;
	}

	/* 2. Resolve VA from the parent's page map level 4.
	pml4_get_page는 "물리주소를 찾는 함수"임. 누구의 물리주소를 찾냐면? 유저영역 쪽에 있는 가상주소 va(부모스레드)의 물리주소를 찾는 것.
	pml4_get_page가 리턴하는 거는 "커널주소"를 리턴한다. 어떤 커널주소를 리턴하냐면? 찾은 물리주소와 연결된 커널의 주소를 리턴함.
	즉 va의 물리주소를 찾아서 그 물리주소와 연결 되어있는 커널주소를 반환하는 함수임. if)물리주소가 매핑 안되어있으면 NULL반환 */
	parent_page = pml4_get_page(parent->pml4, va);
	if (parent_page == NULL)
	{
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to NEWPAGE.*/

	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)
	{
		palloc_free_page(newpage);
		return false;
	}

	/*페이지를 할당 받을 건데 PAL_USER플레그를 줌으로써 유저가 쓸 수 있는 메모리 pool에서 페이지를 가져올거고
	PAL_ZERO를 씀으로써 할당받은 페이지 메모리를 0으로 초기화 할 거임.
	https://casys-kaist.github.io/pintos-kaist/appendix/memory_allocation.html 참고*/

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */

	if (!pml4_set_page(current->pml4, va, newpage, writable))
	{
		/* 6. TODO: if fail to insert page, do error handling. */

		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context. fork할 때 부모프로세스의 context(유전자)를 복사하는 함수
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */

static void

__do_fork(void *aux)
{
	struct intr_frame if_;
	struct fork_info *fork_info = (struct fork_info *)aux;
	struct thread *parent = fork_info->parent_t;
	struct thread *current = thread_current();

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */

	struct intr_frame *syscall_if;
	syscall_if = fork_info->if_;

	// struct intr_frame *parent_if = &parent->tf;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */

	memcpy(&if_, syscall_if, sizeof(struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);

#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else

	if (!pml4_for_each(parent->pml4, duplicate_pte, fork_info))
	{
		goto error;
	}
#endif

	copy_fd_list(parent, current);
	process_init();
	/* Finally, switch to the newly created process. */

	if (succ)
	{
		parent->make_child_success = true;
		free(fork_info);
		if_.R.rax = 0;
		process_fork_sema_up();

		thread_yield();
		do_iret(&if_);
	}
error:
	parent->make_child_success = false;
	free(fork_info);
	thread_current()->exit_code = -1;
	del_child_info();
	process_fork_sema_up();
	thread_exit();
}

void passing_argument(char *f_name, struct intr_frame *_if)
{
	char *token, *save_ptr;
	int *argv[LOADER_ARGS_LEN / 2 + 1];
	int argc, i;
	int k;
	bool success;

	// 인자 parsing 해서 스택에 push
	char *file_name = strtok_r(f_name, " ", &save_ptr);
	argv[0] = file_name;

	// 파싱해서 load에서 사용하는 _if 에서 파싱한 값들의 주소를 이용해야 한다.
	argc = 1;
	for (token = strtok_r(NULL, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
	{
		argv[argc] = token; // token 문자열의 시작지점
		argc++;
	}

	// 이제 argc 는 인자의 갯수, argv는 각 문자열의 주소 담은 배열
	for (i = argc - 1; i > -1; i--)
	{
		k = strlen(argv[i]);
		_if->rsp -= (k + 1); // 마지막 공백 문자까지 고려해서 +1
		memset(_if->rsp, '\0', k + 1);
		memcpy(_if->rsp, argv[i], k);
		argv[i] = (char *)(_if->rsp); // rsp 에 담긴 문자열의 주소를 argv[i] 로 다시 넣어준다.
	}

	// word-aligned
	if (_if->rsp % 8)
	{							  // rsp 주소값을 8로 나눴을 때 나머지가 존재한다면 8의 배수가 아니라는 것 -> 0으로 채워줘야 한다.
		int pad = _if->rsp % 8;	  //만약에 rsp가 15라면 rsp는 8까지 내려와야 함 -> 15%8인 7만큼 내려야 함
		_if->rsp -= pad;		  // 포인터를 내리고
		memset(_if->rsp, 0, pad); // 7만큼 0으로 채운다
	}

	// 스택에 널포인터 push
	_if->rsp -= 8;
	memset(_if->rsp, 0, 8);

	// 스택에 역순으로 push
	for (i = argc - 1; i > -1; i--)
	{
		_if->rsp -= 8;
		memcpy(_if->rsp, &argv[i], 8);
	}

	_if->R.rdi = argc;
	_if->R.rsi = _if->rsp;

	// 스택에 fake return address 인 0 push
	_if->rsp -= 8;
	memset(_if->rsp, 0, 8);
}

int process_exec(void *f_name)
{
	bool success;
	char *not_used;
	/* We cannot use the intr_frame in the thread structure. This is because when current thread rescheduled,
	   it stores the execution information to the member. */

	/* We first kill the current context */
	process_cleanup();

	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	char *fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, f_name, PGSIZE); // filename을 fn_copy로 복사
	char *file_name = strtok_r(fn_copy, " ", &not_used);

	/* 실행 파일 로드 */
	success = load(file_name, &_if);
	if (!success)
		return -1;

	passing_argument(f_name, &_if);

	/* Start switched process. */
	do_iret(&_if);
	NOT_REACHED(); // 실행되면 panic이 발생하는 코드. 코드에 도달하게 하지 않도록 추가해 놓은 코드임
}

/* Waits for thread TID to die and returns its exit status.
 * If it was terminated by the kernel (i.e. killed due to an exception), returns -1.
 * If TID is invalid or if it was not a child of the calling process, or if process_wait()
 *  has already been successfully called for the given TID, returns -1 immediately, without waiting.
 * This function will be implemented in problem 2-2.  For now, it does nothing. */
int process_wait(tid_t child_tid)
{
	/* 이 함수가 호출되는 init.c의 main 함수를 보면, process_wait() 다음 thread_exit으로 쓰레드를 종료시킴.
	 따라서 이 함수가 child_tid가 종료되기를 기다리는 동안 무한루프를 써서 기다리게 한다. */

	struct list *child_list = &thread_current()->children_list;
	struct semaphore *sema;

	sema = &thread_current()->wait_sema;

	while ((search_children_list(child_tid))->exit_code == EXIT_CODE_DEFAULT)
	{
		wait_sema_down(sema);
	}

	return search_children_list(child_tid)->exit_code;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void)
{
	struct thread *curr = thread_current();
	struct thread *parent = thread_current()->parent_thread;

	update_child_exit_code();
	clear_children_list();
	clear_fd_list();

	if (curr->pml4 > KERN_BASE)
		printf("%s: exit(%d)\n", curr->name, curr->exit_code);

	if (thread_current()->exec_file != NULL)
	{
		file_close(thread_current()->exec_file);
		thread_current()->exec_file = NULL;
	}
	process_cleanup();
	sema_up(&parent->wait_sema);
}

/* Free the current process's resources. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next)
{
	/* Activate thread's page tables. */
	pml4_activate(next->pml4);
	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update(next);
}

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* Open executable file. */
	file_lock_acquire();
	file = filesys_open(file_name);
	file_lock_release();
	if (file == NULL)
	{

		printf("load: %s: open failed\n", file_name);
		goto done;
	}
	file_deny_write(file);

	/* Read and verify executable header. */
	file_lock_acquire();
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		file_lock_release();
		goto done;
	}
	file_lock_release();

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		file_lock_acquire();
		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
		{
			file_lock_release();
			goto done;
		}
		file_lock_release();
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
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
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	success = true;
	thread_current()->exec_file = file;
	file_deny_write(file);

done:
	/* We arrive here whether the load is successful or not. */
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
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
static bool install_page(void *upage, void *kpage, bool writable);

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
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable))
		{
			printf("fail\n");
			palloc_free_page(kpage);
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
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
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
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
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
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
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
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

void copy_fd_list(struct thread *parent, struct thread *child)
{
	struct list *p_fd_list, *c_fd_list;
	struct fd *find_fd;
	struct file *copy_file;

	p_fd_list = &parent->fd_list;
	c_fd_list = &child->fd_list;

	if (list_empty(p_fd_list))
	{
		return;
	}

	struct list_elem *cur;

	cur = list_begin(p_fd_list);
	while (cur != list_end(p_fd_list))
	{
		find_fd = list_entry(cur, struct fd, elem);
		copy_file = file_duplicate(find_fd->file);
		if (copy_file != NULL)
		{
			struct fd *new_fd = (struct fd *)malloc(sizeof(struct fd));
			new_fd->file = copy_file;
			new_fd->value = find_fd->value;
			child->fd_count = parent->fd_count;
			list_push_front(c_fd_list, &new_fd->elem);
		}
		cur = list_next(cur);
	}
}

//* 현재스레드의 fd_list clear
void clear_fd_list()
{

	struct list *fd_list;
	struct fd *delete_fd;

	fd_list = &thread_current()->fd_list;

	if (list_empty(fd_list))
		return;

	struct list_elem *cur;
	cur = list_begin(fd_list);
	while (cur != list_end(fd_list))
	{
		delete_fd = list_entry(cur, struct fd, elem);

		file_lock_acquire();
		file_close(delete_fd->file);
		file_lock_release();

		cur = list_remove(&delete_fd->elem);
		free(delete_fd);
	}
}

void del_child_info()
{

	struct child_info *tep;
	struct thread *parent = thread_current()->parent_thread;
	struct list *children_list = &parent->children_list;
	struct list_elem *elem_cur;
	struct thread *curr = thread_current();

	if (!list_empty(children_list))
	{
		elem_cur = list_begin(children_list);
		int curr_tid = curr->tid;
		while (elem_cur != list_end(children_list))
		{
			tep = list_entry(elem_cur, struct child_info, elem);
			if (tep->tid == curr->tid)
			{
				elem_cur = list_remove(&tep->elem);
				tep->exit_code = curr->exit_code;
				free(tep);
				break;
			}
			elem_cur = list_next(elem_cur);
		}
	}
}

//* 현재 스레드의 children_list 지움.
void clear_children_list()
{
	struct thread *curr = thread_current();
	struct child_info *child_info;
	struct list *children_list = &curr->children_list;
	struct list_elem *elem_cur;

	if (!list_empty(children_list))
	{
		elem_cur = list_begin(children_list);
		while (!list_empty(children_list))
		{
			child_info = list_entry(elem_cur, struct child_info, elem);
			elem_cur = list_remove(elem_cur);
			free(child_info);
		}
	}
}

//* 자식의 exit_code가 변경될 때 부모가 child의 exit_code를 알수 있도록 변경
void update_child_exit_code()
{

	struct thread *curr = thread_current();
	struct thread *parent = thread_current()->parent_thread;
	struct list_elem *elem_cur;
	struct child_info *child_info;
	struct list *children_list = &parent->children_list;

	if (!list_empty(children_list))
	{
		elem_cur = list_begin(children_list);
		int curr_tid = curr->tid;
		while (elem_cur != list_end(children_list))
		{
			child_info = list_entry(elem_cur, struct child_info, elem);
			if (child_info->tid == curr->tid)
			{
				child_info->exit_code = curr->exit_code;
				break;
			}
			elem_cur = list_next(elem_cur);
		}
	}
}