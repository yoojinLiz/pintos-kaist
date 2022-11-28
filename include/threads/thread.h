#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
// lock 구조체를 모르니까 선언해줘야 합니다 -bs-
#include "include/threads/synch.h"
#include "filesys/file.h"
#ifdef VM
#include "vm/vm.h"
#endif

#define USERPROG

#define EXIT_CODE_DEFAULT -2
#define EXIT_CODE_ERROR -1
/* States in a thread's life cycle. */
enum thread_status
{
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY,	/* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING	/* About to be destroyed. */
};

struct child_info
{
	uint32_t tid;
	int exit_code;
	struct list_elem elem;
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0	   /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63	   /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread
{
	/* Owned by thread.c. */
	tid_t tid;						/* Thread identifier. */
	enum thread_status status;		/* Thread state. */
	char name[16];					/* Name (for debugging purposes). */
	int priority;					/* Priority. */
	int init_priority;				//* 1주차 수정 (priority-donation) : 우선순위를 기부 받았을 때 원래의 우선순위를 기억하기 위해 사용
	int64_t wakeup_tick;			//* 1주차 수정 (alarm-clock)
	struct lock *wait_on_lock;		//* 1주차 수정 (priority-donation) : 이 쓰레드가 획득을 기다리고 있는 lock
	struct list donations;			//* 1주차 수정 (priority-donation): 이 쓰레드에게 우선순위를 기부한 쓰레드들의 리스트
	struct list_elem donation_elem; //* 1주차 수정 (priority-donation) : donation list를 사용하기 위한 list_elem


	int exit_code; //* 쓰레드가 종료할떄 상태인 exit_code

	struct thread *parent_thread; //* 2주차 수정 : 부모 프로레스(스레드)의 tid
	struct list children_list;	  //* 2주차 수정 : 자식 프로세스(스레드)들을 담고있는 list

	struct list_elem fork_elem;
	struct list_elem wait_elem;

	struct semaphore wait_sema;
	
	//* 나를 기다리는 tid
	tid_t wait_tid;
	// fork 성공적인지 확인
	bool make_child_success;


	int fd_count;

	//오픈된 파일 리스트
	struct list fd_list;

	//실행중인 파일 리스트
	struct file* exec_file;

	/* Shared between thread.c and synch.c. */
	struct list_elem elem; /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4; /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf; /* Information for switching */
	unsigned magic;		  /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

//* 1주차 프로젝트 동안 추가한 함수 (alarm-clock)
void thread_sleep(int64_t ticks);			   //실행 중인 스레드를 sleep 상태로 (block 상태로 만든다)
void thread_awake(int64_t ticks);			   // 슬립 큐에 잠들어있는 스레드를 깨워서 readylist로 보낸다
void update_next_tick_to_awake(int64_t ticks); // 가장 빨리 일어나야 하는 스레드를 저장 (?)
int64_t get_next_tick_to_awake(void);		   // next_tick_to_awake 를 리턴

//* 1주차 프로젝트 동안 추가한 함수 (priority changes)
void test_max_priority(void);
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux);

//* 1주차 프로젝트 동안 추가한 함수 (priority donation)
void donate_priority(void);

void remove_with_lock(struct lock *lock);
void refresh_priority(void);

void do_iret(struct intr_frame *tf);

//* 2주차 프로젝트 동안 추가한 함수
void process_fork_sema_down();
void process_fork_sema_up();
void thread_unblock_front(struct thread *t);

#endif /* threads/thread.h */
