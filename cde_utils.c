#include "cde.h"

// copy up to n bytes from src (in child process) to dest (in this process)
// using PTRACE_PEEKDATA
//
// TODO: if this is too slow, we could implement Goanna's optimization
// of directly reading from the /proc/<pid>/mem pseudo-file, which can
// transfer one 4K page at a time rather than one word at a time
void memcpy_from_child(struct pcb *pcb, void* dest, void* src, size_t n) {
  // adapted from Goanna

  long w;
  long *ldest = (long *)dest;
  char *cdest;

  assert(pcb);

  while (n >= sizeof(int)) {
    errno = 0;
    w = ptrace(PTRACE_PEEKDATA, pcb->pid, src, NULL);
    if (errno) {
      // silently exit as soon as you get an error
      // (e.g., page fault in child process)
      return;
    }

    *ldest++ = w;
    n -= sizeof(int);
    src = (char *)src + sizeof(int);
    dest = (char *)dest + sizeof(int);
  }

  /* Cleanup the last little bit. */
  if (n) {
    cdest = (char *)ldest;

    errno = 0;
    w = ptrace(PTRACE_PEEKDATA, pcb->pid, src, NULL);
    if (errno) {
      // silently exit as soon as you get an error
      // (e.g., page fault in child process)
      return;
    }

    /* Little endian sucks. */
    *cdest++ = (w & 0x000000ff);
    if (n >= 2)
      *cdest++ = (w & 0x0000ff00) >> 8;
    if (n >= 3)
      *cdest++ = (w & 0x00ff0000) >> 16;
  }
}


void* find_free_addr(int pid, int prot, unsigned long size) {
  FILE *f;
  char filename[20];
  char s[80];
  char r, w, x, p;

  sprintf(filename, "/proc/%d/maps", pid);

  f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr, "Can not find a free address in pid %d: %s\n.", pid, strerror(errno));
  }
  while (fgets(s, sizeof(s), f) != NULL) {
    unsigned long cstart, cend;
    int major, minor;

    sscanf(s, "%lx-%lx %c%c%c%c %*x %d:%d", &cstart, &cend, &r, &w, &x, &p, &major, &minor);

    if (cend - cstart < size) {
      continue;
    }

    if (!(prot & FILEBACK) && (major || minor)) {
      continue;
    }

    if (p != 'p') {
      continue;
    }
    if ((prot & PROT_READ) && (r != 'r')) {
      continue;
    }
    if ((prot & PROT_EXEC) && (x != 'x')) {
      continue;
    }
    if ((prot & PROT_WRITE) && (w != 'w')) {
      continue;
    }
    fclose(f);

    return (void *)cstart;
  }
  fclose(f);

  return NULL;
}


struct pcb* new_pcb(int pid, int state) {
  key_t key;
  struct pcb* ret;

  ret = (struct pcb*)malloc(sizeof(*ret));
  if (!ret) {
    return NULL;
  }

  memset(ret, 0, sizeof(*ret));

  ret->pid = pid;
  ret->state = state;
  ret->prime_fd = -1;

  // randomly probe for a valid shm key
  do {
    errno = 0;
    key = rand();
    ret->shmid = shmget(key, PATH_MAX * 2, IPC_CREAT|IPC_EXCL|0600);
  } while (ret->shmid == -1 && errno == EEXIST);

  ret->localshm = (char*)shmat(ret->shmid, NULL, 0);
  if ((int)ret->localshm == -1) {
    perror("shmat");
    exit(1);
  }

  if (shmctl(ret->shmid, IPC_RMID, NULL) == -1) {
    perror("shmctl(IPC_RMID)");
    exit(1);
  }

  ret->victimshm = NULL;

  return ret;
}

void delete_pcb(struct pcb *pcb) {
  shmdt(pcb->localshm);
  free(pcb);
}

