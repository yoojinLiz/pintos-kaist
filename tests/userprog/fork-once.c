/* Forks and waits for a single child process. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  int pid;

  if ((pid = fork("child"))){
    printf("fork는 뭘 반환하나?%d\n", pid);
    int status = wait (pid);
    printf("여기니...?\n");
    msg ("Parent: child exit status is %d", status);
  } else {
    msg ("child run");
    exit(81);
  }
}
