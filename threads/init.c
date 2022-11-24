#include "threads/init.h"
#include <console.h>
#include <debug.h>
#include <limits.h>
#include <random.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "devices/kbd.h"
#include "devices/input.h"
#include "devices/serial.h"
#include "devices/timer.h"
#include "devices/vga.h"
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/thread.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "userprog/exception.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#endif
#include "tests/threads/tests.h"
#ifdef VM
#include "vm/vm.h"
#endif
#ifdef FILESYS
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "filesys/fsutil.h"
#endif

/* Page-map-level-4 with kernel mappings only. */
uint64_t *base_pml4;

#ifdef FILESYS
/* -f: Format the file system? */
static bool format_filesys;
#endif

/* -q: Power off after kernel tasks complete? */
bool power_off_when_done;

bool thread_tests;

static void bss_init (void);
static void paging_init (uint64_t mem_end);

static char **read_command_line (void);
static char **parse_options (char **argv);
static void run_actions (char **argv);
static void usage (void);

static void print_stats (void);


int main (void) NO_RETURN;

/* Pintos main program. */
int
main (void) {
	uint64_t mem_end;
	char **argv;

	/* Clear BSS and get machine's RAM size. */
	bss_init ();

	/* Break command line into arguments and parse options. */
	argv = read_command_line (); 
    // 현재 argv 만약 명령어가 run alarm-single 이었으면, argv[0] = run, argv[1] = alarm-single, argv[2]= NULL 인 상태 

	argv = parse_options (argv);
	// 명령어에 옵션들이 있으면, 옵션에 따라 필요한 flag들을 업데이트 

	/* Initialize ourselves as a thread so we can use locks,
	   then enable console locking.
	 * thread_init을 통해 main 쓰레드를 생성 
	 * cosole_init을 통해 console_lock을 init*/
	thread_init ();
	console_init ();

	/* Initialize memory system. */
	mem_end = palloc_init ();
	malloc_init ();
	paging_init (mem_end);

#ifdef USERPROG
	tss_init ();
	gdt_init ();
#endif

	/* Initialize interrupt handlers. */
	intr_init ();
	timer_init ();
	kbd_init ();
	input_init ();
#ifdef USERPROG
	exception_init ();
	syscall_init ();
#endif
	/* Start thread scheduler and enable interrupts. */
	thread_start ();
	serial_init_queue ();
	timer_calibrate ();

#ifdef FILESYS
	/* Initialize file system. */
	disk_init ();
	filesys_init (format_filesys);
#endif

#ifdef VM
	vm_init ();
#endif

	printf ("Boot complete.\n");

	/* Run actions specified on kernel command line. */
	run_actions (argv);

	/* Finish up. */
	if (power_off_when_done)
		power_off ();
	thread_exit ();
}

/* Clear BSS */
static void
bss_init (void) {
	/* The "BSS" is a segment that should be initialized to zeros.
	   It isn't actually stored on disk or zeroed by the kernel
	   loader, so we have to zero it ourselves.

	   The start and end of the BSS segment is recorded by the
	   linker as _start_bss and _end_bss.  See kernel.lds. */
	extern char _start_bss, _end_bss;
	memset (&_start_bss, 0, &_end_bss - &_start_bss);
}

/* Populates the page table with the kernel virtual mapping,
 * and then sets up the CPU to use the new page directory.
 * Points base_pml4 to the pml4 it creates. */
static void
paging_init (uint64_t mem_end) {
	uint64_t *pml4, *pte;
	int perm;
	pml4 = base_pml4 = palloc_get_page (PAL_ASSERT | PAL_ZERO); 

	extern char start, _end_kernel_text;
	// Maps physical address [0 ~ mem_end] to
	//   [LOADER_KERN_BASE ~ LOADER_KERN_BASE + mem_end].
	for (uint64_t pa = 0; pa < mem_end; pa += PGSIZE) {
		uint64_t va = (uint64_t) ptov(pa);

		perm = PTE_P | PTE_W;
		if ((uint64_t) &start <= va && va < (uint64_t) &_end_kernel_text)
			perm &= ~PTE_W;

		if ((pte = pml4e_walk (pml4, va, 1)) != NULL)
			*pte = pa | perm;
	}

	// reload cr3
	pml4_activate(0);
}

/* Breaks the kernel command line into words and returns them as an argv-like array. */
static char **
read_command_line (void) {
	static char *argv[LOADER_ARGS_LEN / 2 + 1];
	char *p, *end;
	int argc;
	int i;

	argc = *(uint32_t *) ptov (LOADER_ARG_CNT);
	p = ptov (LOADER_ARGS); // LOADER_ARGS의 가상 주소 
	end = p + LOADER_ARGS_LEN; // LOADER_ARGS의 가상 주소 + ARGS 길이 (128)
	for (i = 0; i < argc; i++) {
		if (p >= end)
			PANIC ("command line arguments overflow");

		argv[i] = p; 
		p += strnlen (p, end - p) + 1; 
		 // *string 이 maxlen보다 작으면 *string의 길이(\0 문자가 나올 때까지)를, maxlen 보다 크거나 같으면 maxlen을 반환
		 // *다음 p값은 공백이 나오기 전까지의 문자 길이 + 1 (공백) 를 더해서 계산됨. 
	}
	// 만약 명령어가 run alarm-single 이었으면, argv[0] = run, argv[1] = alarm-single 
	argv[argc] = NULL; // sentinal 역할의 NULL

	/* Print kernel command line. */
	printf ("Kernel command line:");
	for (i = 0; i < argc; i++)
		if (strchr (argv[i], ' ') == NULL)
			printf (" %s", argv[i]);
		else
			printf (" '%s'", argv[i]);
	printf ("\n");

	return argv;
}

/* Parses options in ARGV[] and returns the first non-option argument. 
* 입력받은 command line을 공백 기준으로 분리하여 argv 배열로 넣은 상태 */

static char **
parse_options (char **argv) {
	// *argr 이 존재하고(문자열이 있고) 해당 문자열이 - 인 동안 반복???????? 
	for (; *argv != NULL && **argv == '-'; argv++) {
		char *save_ptr;
		char *name = strtok_r (*argv, "=", &save_ptr);
		char *value = strtok_r (NULL, "", &save_ptr);

		if (!strcmp (name, "-h"))
			usage (); // 도움말 출력 및 poweroff
		else if (!strcmp (name, "-q")) // 작업 수행 후 poweroff
			power_off_when_done = true;
#ifdef FILESYS
		else if (!strcmp (name, "-f"))
			format_filesys = true;
#endif
		else if (!strcmp (name, "-rs"))
			random_init (atoi (value));
		else if (!strcmp (name, "-mlfqs"))
			thread_mlfqs = true;
#ifdef USERPROG
		else if (!strcmp (name, "-ul"))
			user_page_limit = atoi (value);
		else if (!strcmp (name, "-threads-tests"))
			thread_tests = true;
#endif
		else
			PANIC ("unknown option `%s' (use -h for help)", name);
	}

	return argv;
}

/* Runs the task specified in ARGV[1]. 
* run_task 같은 경우에 argc가 2이고, argv[0]는 run, argv[1]가 †ask (task 이름)
* 만약 명령어가 run 'args-single onearg' 였다면 
* 현재 이 task에는 파일명과 인자들이 함께 들어있는 args-single onearg 형태 . 
*/
static void
run_task (char **argv) {
	const char *task = argv[1]; 
	/* 
	 * 만약 명령어가 run 'args-multiple some arguments for you!'이라면
	 * argv[0]은 run 이고 
	 * argv[1]은 'args-multiple some arguments for you!' (실제로 출력하면 ''는 포함안됨 )
	*/

	printf ("Executing '%s':\n", task);
#ifdef USERPROG // 2주차 부터는 userprog 이 있으므로, 이곳에서 실행될 것 
	if (thread_tests){
		run_test (task);
	} else {
		process_wait (process_create_initd (task)); // parsing 되지 않은 task를 받아서 실행됨 
	}
#else
	run_test (task); // 프로젝트1에서는 userprog 이 없었으니까 여기서 바로 알람, 우선순위 스케쥴링 및 mlfqs 테스트를 돌렸음 
#endif
	printf ("Execution of '%s' complete.\n", task);
}

/* Executes all of the actions specified in ARGV[]
   up to the null pointer sentinel. */
static void
run_actions (char **argv) {
	/* An action. */
	struct action {
		char *name;                       /* Action name. */
		int argc;                         /* # of args, including action name. */
		void (*function) (char **argv);   /* Function to execute action. */
	};

	/* Table of supported actions. 
	 * action 구조체에 하나씩 값을 넣어, 구조체의 배열을 만든다
	 * 이름이 run, argc가 2, 함수명이 run_task이고 인자가 (**argv) 인 구조체를 만든다. 
	 * 파일 시스템이 있다면 파일 시스템과 관련된 명령어 이름들로 구성된 구조체도 만들어서 actions 배열에 추가*/
	static const struct action actions[] = {
		{"run", 2, run_task},
#ifdef FILESYS
		{"ls", 1, fsutil_ls},
		{"cat", 2, fsutil_cat},
		{"rm", 2, fsutil_rm},
		{"put", 2, fsutil_put},
		{"get", 2, fsutil_get},
#endif
		{NULL, 0, NULL},
	};

	while (*argv != NULL) {
		const struct action *a;
		int i;

		/* Find action name. */
		for (a = actions; ; a++)  // actions의 첫번째 구조체부터 순회 시작
			if (a->name == NULL)
				PANIC ("unknown action `%s' (use -h for help)", *argv);
			else if (!strcmp (*argv, a->name)) // strcmp는 argv 값과 a->name이 같으면 0, 다르면 1이나 -1 을 반환하므로, !연산 시, argv == name 이면 break
				break;

		/* Check for required arguments. */
		for (i = 1; i < a->argc; i++)
			if (argv[i] == NULL)
				PANIC ("action `%s' requires %d argument(s)", *argv, a->argc - 1);

		/* Invoke action and advance. */
		a->function (argv);
		argv += a->argc; // argv가 다음 인자를 가리키도록 포인터 업데이트 
	}

}

/* Prints a kernel command line help message and powers off the machine. */
static void
usage (void) {
	printf ("\nCommand line syntax: [OPTION...] [ACTION...]\n"
			"Options must precede actions.\n"
			"Actions are executed in the order specified.\n"
			"\nAvailable actions:\n"
#ifdef USERPROG
			"  run 'PROG [ARG...]' Run PROG and wait for it to complete.\n"
#else
			"  run TEST           Run TEST.\n"
#endif
#ifdef FILESYS
			"  ls                 List files in the root directory.\n"
			"  cat FILE           Print FILE to the console.\n"
			"  rm FILE            Delete FILE.\n"
			"Use these actions indirectly via `pintos' -g and -p options:\n"
			"  put FILE           Put FILE into file system from scratch disk.\n"
			"  get FILE           Get FILE from file system into scratch disk.\n"
#endif
			"\nOptions:\n"
			"  -h                 Print this help message and power off.\n"
			"  -q                 Power off VM after actions or on panic.\n"
			"  -f                 Format file system disk during startup.\n"
			"  -rs=SEED           Set random number seed to SEED.\n"
			"  -mlfqs             Use multi-level feedback queue scheduler.\n"
#ifdef USERPROG
			"  -ul=COUNT          Limit user memory to COUNT pages.\n"
#endif
			);
	power_off ();
}


/* Powers down the machine we're running on,
   as long as we're running on Bochs or QEMU. */
void
power_off (void) {
#ifdef FILESYS
	filesys_done ();
#endif

	print_stats ();

	printf ("Powering off...\n");
	outw (0x604, 0x2000);               /* Poweroff command for qemu */
	for (;;);
}

/* Print statistics about Pintos execution. */
static void
print_stats (void) {
	timer_print_stats ();
	thread_print_stats ();
#ifdef FILESYS
	disk_print_stats ();
#endif
	console_print_stats ();
	kbd_print_stats ();
#ifdef USERPROG
	exception_print_stats ();
#endif
}
