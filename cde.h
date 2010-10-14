// Lots of code adapted from Goanna project

#ifndef _CDE_H
#define _CDE_H

#include <sys/user.h>
#include <sys/select.h>
#include <sys/time.h>
#include <string.h>
#include <utime.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>   /* For constants ORIG_EAX etc */
#include <sys/syscall.h>   /* For constants SYS_write etc */
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

// to shut up gcc warnings without causing nasty #include conflicts
int shmget(key_t key, size_t size, int shmflg);
void *shmat(int shmid, const void *shmaddr, int shmflg);
int shmdt(const void *shmaddr);
int shmctl(int shmid, int cmd, struct shmid_ds *buf);

#define FILEBACK 8 /* It is OK to use a file backed region. */

#define PATH_MAX 4096


// like an assert except that it always fires
#define EXITIF(x) do { \
  if (x) { \
    fprintf(stderr, "Fatal error in %s [%s:%d]\n", __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } \
} while(0)


// abbreviated version of pcb from Goanna ... add more fields if necessary
struct pcb {
    int pid;
    int state;

    /* What are the fsuid and fsgid of this process. */
    int fsuid;
    int fsgid;

    /* The registers we are manipulating. */
    struct user_regs_struct regs;
    struct user_regs_struct orig_regs;
    /* The wait status. */
    int status;

    /* The prime file descriptor. */
    int prime_fd;

    /* FORCE RETURN VARIABLES. */
    /* What to force return. */
    int forcedret;
    /* What the system call we are doing should return (in forced ret). */
    int exreturn;
    /* Should we skip a force return? */
    int noforceret;

    /* These are not used at the same time. */
    union {
    /* This structure is used by shmat, but is general enough for everyone. */
      struct {
        long savedword;
        void *savedaddr;
      };
      /* This is used by mmap2. */
      struct mapped_region *curregion;
      /* This differentiates normal from not-normal execs. */
      int fakeexec;
      /* Our potentially opened fd_struct. */
    };

    /* This is a temporary holder for the file structure we want to open. */
    struct fd_struct *try_fd_struct;

    /* What is the child's umask? */
    int umask;

    /* Information about the shared segment. */
    int shmid;
    char *localshm; // address in our address space
    void *childshm; // address in CHILD's address space
    int shmat_nextstate;

    /* Status variable. */
    int exit_status;
};


/* Possible PCB states. */
#define INUSER 1	/* We are waiting for it to make a call */
#define INCALL 2	/* We are waiting to finish a call. */
#define INFORCERET 3	/* We are waiting to finish a forced return call. */
#define INOPEN 4	/* We are waiting to finish an open call. */
#define INCLONE 5	/* We are waiting to be notified after a clone call. */
#define INCLONE2 6	/* We are waiting to finish a clone call. */
#define INEXEC 7	/* We are waiting to finish an exec. */
#define INEXEC2 8	/* We should get one extra signal for an exec. */
#define DOCONT 9	/* Just continue. */
#define INCHDIR 10	/* We are waiting to finish a chdir. */
#define INSHMAT 11	/* We are attaching the shared memory segment in the victim. */
#define RESTOREREGS 12	/* The registers should be restored from orig_regs, bug the new value of eax (i.e. the return value) should be kept. */
#define INDUP 13	/* We are in a BDB dup call, should dup our fd afterwards. */
#define INMMAP 14	/* We are in a BDB mmap call. */
#define FORKCONT 15	/* We are the child of a fork. */
#define INFRCEXEC 16	/* We are waiting to finish a forced return call, but want to execute it. */
#define INMREMAP 17	/* We are in a BDB mremap call. */
#define INSLIPSTREAM 18	/* We are servicing a SLIPSTREAM request. */
#define INGETPID 19	/* We are in a getpid call that is getting monitored twice. */


// from cde_utils.c
void memcpy_from_child(struct pcb *pcb, void* dest, void* src, size_t n);
void* find_free_addr(int pid, int exec, unsigned long size);
struct pcb* new_pcb(int pid, int state);
void delete_pcb(struct pcb *pcb);


/* A structure to represent paths. */
struct namecomp {
  int len;
  char str[0];
};

struct path {
  int stacksize; // num elts in stack
  int depth;     // actual depth of path (smaller than stacksize)
  int is_abspath; // 1 if absolute path (starts with '/'), 0 if relative path
  struct namecomp **stack;
};

struct path* str2path(char* path);
char* path2str(struct path* path);
struct path* path_dup(struct path* path);
struct path *new_path();
void delete_path(struct path *path);


#endif // _CDE_H
