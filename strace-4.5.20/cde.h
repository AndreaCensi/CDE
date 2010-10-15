#ifndef _CDE_H
#define _CDE_H

// TODO: we probably don't need most of these #includes
#include <sys/user.h>
#include <sys/select.h>
#include <sys/time.h>
#include <string.h>
#include <utime.h>
//#include <sys/ptrace.h>
//#include <linux/ptrace.h>   /* For constants ORIG_EAX etc */
//#include <sys/syscall.h>   /* For constants SYS_write etc */
#include <linux/types.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <linux/ipc.h>
#include <linux/shm.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "defs.h"

// to shut up gcc warnings without causing nasty #include conflicts
// TODO: do we still need this?
int shmget(key_t key, size_t size, int shmflg);
void *shmat(int shmid, const void *shmaddr, int shmflg);
int shmdt(const void *shmaddr);
int shmctl(int shmid, int cmd, struct shmid_ds *buf);


// like an assert except that it always fires
#define EXITIF(x) do { \
  if (x) { \
    fprintf(stderr, "Fatal error in %s [%s:%d]\n", __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } \
} while(0)


// hooks into main strace
void CDE_begin_file_open(struct tcb* tcp);
void CDE_end_file_open(struct tcb* tcp);

void CDE_begin_execve(struct tcb* tcp);
void CDE_end_execve(struct tcb* tcp);


#endif // _CDE_H
