#include "cde.h"


void CDE_begin_file_open(struct tcb* tcp) {

}

void CDE_end_file_open(struct tcb* tcp) {

}

void CDE_begin_execve(struct tcb* tcp) {

}

void CDE_end_execve(struct tcb* tcp) {

}


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


// TODO: this is probably Linux-specific ;)
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

  ret->childshm = NULL;

  return ret;
}

void delete_pcb(struct pcb *pcb) {
  shmdt(pcb->localshm);
  free(pcb);
}


// manipulating paths (courtesy of Goanna)

static void empty_path(struct path *path) {
  int pos = 0;
  path->depth = 0;
  if (path->stack) {
    while (path->stack[pos]) {
      free(path->stack[pos]);
      path->stack[pos] = NULL;
      pos++;
    }
  }
}

// mallocs a new path object, must free using delete_path(),
// NOT using ordinary free()
struct path* path_dup(struct path* path) {
  struct path* ret = (struct path *)malloc(sizeof(struct path));
  assert(ret);

  ret->stacksize = path->stacksize;
  ret->depth = path->depth;
  ret->is_abspath = path->is_abspath;
  ret->stack = (struct namecomp**)malloc(sizeof(struct namecomp*) * ret->stacksize);
  assert(ret->stack);

  int pos = 0;
  while (path->stack[pos]) {
    ret->stack[pos] =
      (struct namecomp*)malloc(sizeof(struct namecomp) +
                               strlen(path->stack[pos]->str) + 1);
    assert(ret->stack[pos]);
    ret->stack[pos]->len = path->stack[pos]->len;
    strcpy(ret->stack[pos]->str, path->stack[pos]->str);
    pos++;
  }
  ret->stack[pos] = NULL;
  return ret;
}

struct path *new_path() {
  struct path* ret = (struct path *)malloc(sizeof(struct path));
  assert(ret);

  ret->stacksize = 1;
  ret->depth = 0;
  ret->is_abspath = 0;
  ret->stack = (struct namecomp **)malloc(sizeof(struct namecomp *));
  assert(ret->stack);
  ret->stack[0] = NULL;
  return ret;
}

void delete_path(struct path *path) {
  assert(path);
  if (path->stack) {
    int pos = 0;
    while (path->stack[pos]) {
      free(path->stack[pos]);
      path->stack[pos] = NULL;
      pos++;
    }
    free(path->stack);
  }
  free(path);
}


// mallocs a new string and populates it with up to
// 'depth' path components (if depth is 0, uses entire path)
char* path2str(struct path* path, int depth) {
  int i;
  int destlen = 1;

  // simply use path->depth if depth is out of range
  if (depth <= 0 || depth > path->depth) {
    depth = path->depth;
  }

  for (i = 0; i < depth; i++) {
    destlen += path->stack[i]->len + 1;
  }

  char* dest = (char *)malloc(destlen);

  char* ret = dest;
  assert(destlen >= 2);

  if (path->is_abspath) {
    *dest++ = '/';
    destlen--;
  }

  for (i = 0; i < depth; i++) {
    assert(destlen >= path->stack[i]->len + 1);

    memcpy(dest, path->stack[i]->str, path->stack[i]->len);
    dest += path->stack[i]->len;
    destlen -= path->stack[i]->len;

    if (i < depth - 1) { // do we have a successor?
      assert(destlen >= 2);
      *dest++ = '/';
      destlen--;
    }
  }

  *dest = '\0';

  return ret;
}

// pop the last element of path
void path_pop(struct path* p) {
  if (p->depth == 0) {
    return;
  }

  free(p->stack[p->depth-1]);
  p->stack[p->depth-1] = NULL;
  p->depth--;
}

// mallocs a new path object, must free using delete_path(),
// NOT using ordinary free()
struct path* str2path(char* path) {
  int stackleft;

  path = strdup(path); // so that we don't clobber the original
  char* path_dup_base = path; // for free()

  struct path* base = new_path();

  if (*path == '/') { // absolute path?
    base->is_abspath = 1;
    empty_path(base);
    path++;
  }
  else {
    base->is_abspath = 0;
  }

  stackleft = base->stacksize - base->depth - 1;

  do {
    char *p;
    while (stackleft <= 1) {
      base->stacksize *= 2;
      stackleft = base->stacksize / 2;
      base->stacksize++;
      stackleft++;
      base->stack =
        (struct namecomp **)realloc(base->stack, base->stacksize * sizeof(struct namecomp*));
      assert(base->stack);
    }

    // Skip multiple adjoining slashes
    while (*path == '/') {
      path++;
    }

    p = strchr(path, '/');
    // put a temporary stop-gap ... uhhh, this assumes path isn't read-only
    if (p) {
      *p = '\0';
    }

    if (path[0] == '\0') {
      base->stack[base->depth] = NULL;
      // We are at the end (or root), do nothing.
    }
    else if (!strcmp(path, ".")) {
      base->stack[base->depth] = NULL;
      // This doesn't change anything.
    }
    else if (!strcmp(path, "..")) {
      if (base->depth > 0) {
        free(base->stack[--base->depth]);
        base->stack[base->depth] = NULL;
        stackleft++;
      }
    }
    else {
      base->stack[base->depth] =
        (struct namecomp *)malloc(sizeof(struct namecomp) + strlen(path) + 1);
      assert(base->stack[base->depth]);
      strcpy(base->stack[base->depth]->str, path);
      base->stack[base->depth]->len = strlen(path);
      base->depth++;
      base->stack[base->depth] = NULL;
      stackleft--;
    }

    // Put it back the way it was
    if (p) {
      *p++ = '/';
    }
    path = p;
  } while (path);

  free(path_dup_base);
  return base;
}


// primitive file copy
// TODO: could optimize by never clobbering dst_filename if its
// modification date is equal to or newer than that of src_filename
void copy_file(char* src_filename, char* dst_filename) {
  int inF;
  int outF;
  int bytes;
  char buf[4096]; // TODO: consider using BUFSIZ if it works better

  EXITIF((inF = open(src_filename, O_RDONLY)) < 0);
  // create with permissive perms
  EXITIF((outF = open(dst_filename, O_WRONLY | O_CREAT, 0777)) < 0);

  while ((bytes = read(inF, buf, sizeof(buf))) > 0) {
    write(outF, buf, bytes);
  }
    
  close(inF);
  close(outF);
}

