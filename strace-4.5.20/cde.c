#include "cde.h"

// 1 if we are executing code in a CDE package,
// 0 for tracing regular execution
char CDE_exec_mode;

static void begin_setup_shmat(struct tcb* tcp);
static void* find_free_addr(int pid, int exec, unsigned long size);
static void lazy_copy_file(char* src_filename, char* dst_filename);

// to shut up gcc without going through header hell
extern char* canonicalize_file_name(const char *name);

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
char* path2str(struct path* path, int depth);
struct path* path_dup(struct path* path);
struct path *new_path();
void delete_path(struct path *path);
void path_pop(struct path* p);


static void add_file_dependency(struct tcb* tcp) {
  char* filename = tcp->opened_filename;
  assert(filename);

  // this will NOT follow the symlink ...
  struct stat st;
  EXITIF(lstat(filename, &st));
  char is_symlink = S_ISLNK(st.st_mode);

  if (is_symlink) {
    // this will follow the symlink ...
    EXITIF(stat(filename, &st));
  }

  // check whether it's a REGULAR-ASS file
  if (S_ISREG(st.st_mode)) {
    // assume that relative paths are in working directory,
    // so no need to grab those files
    //
    // TODO: this isn't a perfect assumption since a
    // relative path could be something like '../data.txt',
    // which this won't pick up :)
    //   WOW, this libc function seems useful for
    //   canonicalizing filenames:
    //     char* canonicalize_file_name (const char *name)
    if (filename[0] == '/') {
      // modify filename so that it appears as a RELATIVE PATH
      // within a cde-root/ sub-directory
      char* rel_path = malloc(strlen(filename) + strlen("cde-root") + 1);
      strcpy(rel_path, "cde-root");
      strcat(rel_path, filename);

      struct path* p = str2path(rel_path);
      path_pop(p); // ignore filename portion to leave just the dirname

      // now mkdir all directories specified in rel_path
      int i;
      for (i = 1; i <= p->depth; i++) {
        char* dn = path2str(p, i);
        mkdir(dn, 0777);
        free(dn);
      }

      // finally, 'copy' filename over to rel_path
      // 1.) try a hard link for efficiency
      // 2.) if that fails, then do a straight-up copy
      //
      // don't hard link symlinks since they're simply textual
      // references to the real files; just straight-up copy them
      //
      // EEXIST means the file already exists, which isn't
      // really a hard link failure ...
      if (is_symlink || (link(filename, rel_path) && (errno != EEXIST))) {
        lazy_copy_file(filename, rel_path);
      }

      delete_path(p);
      free(rel_path);
    }
  }
}

// used as a temporary holding space for paths copied from child process
static char path[MAXPATHLEN + 1]; 

extern char* basename (const char *fname); // to shut up gcc warnings

// redirect request for opened_filename to a version within cde-root/
static void redirect_filename(struct tcb* tcp) {
  assert(CDE_exec_mode);
  assert(tcp->opened_filename);

  // don't redirect certain special paths
  // /dev and /proc are special system directories with fake files
  //
  // .Xauthority is used for X11 authentication via ssh, so we need to
  // use the REAL version and not the one in cde-root/
  if ((strncmp(tcp->opened_filename, "/dev/", 5) == 0) ||
      (strncmp(tcp->opened_filename, "/proc/", 6) == 0) ||
      (strcmp(basename(tcp->opened_filename), ".Xauthority") == 0)) {
    return;
  }

  if (!tcp->childshm) {
    begin_setup_shmat(tcp);
    // no more need for filename, so don't leak it
    free(tcp->opened_filename);
    tcp->opened_filename = NULL;

    return; // MUST punt early here!!!
  }

  // redirect all requests for absolute paths to version within cde-root/
  // if those files exist!
  // TODO: make this more accurate using canonicalize_file_name(),
  // since it currently doesn't handle cases like '../../hello.txt'
  if (tcp->opened_filename[0] == '/') {
    assert(tcp->childshm);

    // modify filename so that it appears as a RELATIVE PATH
    // within a cde-root/ sub-directory
    char* rel_path = malloc(strlen(tcp->opened_filename) + strlen("cde-root") + 1);
    strcpy(rel_path, "cde-root");
    strcat(rel_path, tcp->opened_filename);

    strcpy(tcp->localshm, rel_path); // hopefully this doesn't overflow :0

    //printf("redirect %s\n", tcp->localshm);
    //static char tmp[MAXPATHLEN + 1];
    //EXITIF(umovestr(tcp, (long)tcp->childshm, sizeof tmp, tmp) < 0);
    //printf("     %s\n", tmp);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
    cur_regs.ebx = (long)tcp->childshm;
    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);

    free(rel_path);
  }
}


void CDE_begin_file_open(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  tcp->opened_filename = strdup(path);

  // TODO: should we only track files opened in read-only or read-write
  // modes?  right now, we track files opened in ANY mode
  //
  // relevant code snippets:
  //   char open_mode = (tcp->u_arg[1] & 0x3);
  //   if (open_mode == O_RDONLY || open_mode == O_RDWR) { ... }

  if (CDE_exec_mode) {
    redirect_filename(tcp);
  }
}

void CDE_end_file_open(struct tcb* tcp) {
  assert(tcp->opened_filename);
 
  if (CDE_exec_mode) {
    // empty
  }
  else {
    // non-negative return value means that the call returned
    // successfully with a known file descriptor
    if (tcp->u_rval >= 0) {
      add_file_dependency(tcp);
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


void CDE_begin_execve(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  tcp->opened_filename = strdup(path);

  if (CDE_exec_mode) {
    redirect_filename(tcp);
  }
}

void CDE_end_execve(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // WOW, what a gross hack!  execve detaches all shared memory
    // segments, so childshm is no longer valid.  we must clear it so
    // that begin_setup_shmat() will be called again
    tcp->childshm = NULL;
  }
  else {
    // return value of 0 means a successful call
    if (tcp->u_rval == 0) {
      add_file_dependency(tcp);
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


void CDE_begin_file_stat(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  tcp->opened_filename = strdup(path);

  // redirect stat call to the version of the file within cde-root/ package
  if (CDE_exec_mode) {
    redirect_filename(tcp);
  }
}

void CDE_end_file_stat(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // empty
  }
  else {
    // return value of 0 means a successful call
    if (tcp->u_rval == 0) {
      // TODO: perhaps save an 'empty' file or directory if the real
      // file/dir exists?
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}

void CDE_begin_file_unlink(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  tcp->opened_filename = strdup(path);

  if (CDE_exec_mode) {
    redirect_filename(tcp);
  }
  else {
    // TODO: delete the copy of the file in cde-root/
    //       in addition to deleting it from its original location
  }

  // no need for this anymore
  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


// from Goanna
#define FILEBACK 8 /* It is OK to use a file backed region. */

// TODO: this is probably Linux-specific ;)
static void* find_free_addr(int pid, int prot, unsigned long size) {
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


// if modtime($dst_filename) < modtime($src_filename):
//   cp $src_filename $dst_filename
static void lazy_copy_file(char* src_filename, char* dst_filename) {
  int inF;
  int outF;
  int bytes;
  char buf[4096]; // TODO: consider using BUFSIZ if it works better

  // lazy optimization ... only do a copy if dst is older than src
  struct stat inF_stat;
  struct stat outF_stat;
  EXITIF(stat(src_filename, &inF_stat) < 0); // this had better exist

  // if dst file exists and is not older than src file, then punt
  if (stat(dst_filename, &outF_stat) == 0) {
    if (outF_stat.st_mtime >= inF_stat.st_mtime) {
      //printf("PUNTED on %s\n", dst_filename);
      return;
    }
  }

  //printf("COPY %s %s\n", src_filename, dst_filename);

  // do a full-on copy
  EXITIF((inF = open(src_filename, O_RDONLY)) < 0);
  // create with permissive perms
  EXITIF((outF = open(dst_filename, O_WRONLY | O_CREAT, 0777)) < 0);

  while ((bytes = read(inF, buf, sizeof(buf))) > 0) {
    write(outF, buf, bytes);
  }
    
  close(inF);
  close(outF);
}


void alloc_tcb_CDE_fields(struct tcb* tcp) {
  tcp->localshm = NULL;
  tcp->childshm = NULL;
  tcp->setting_up_shm = 0;

  if (CDE_exec_mode) {
    key_t key;
    // randomly probe for a valid shm key
    do {
      errno = 0;
      key = rand();
      tcp->shmid = shmget(key, MAXPATHLEN * 2, IPC_CREAT|IPC_EXCL|0600);
    } while (tcp->shmid == -1 && errno == EEXIST);

    tcp->localshm = (char*)shmat(tcp->shmid, NULL, 0);

    if ((int)tcp->localshm == -1) {
      perror("shmat");
      exit(1);
    }

    if (shmctl(tcp->shmid, IPC_RMID, NULL) == -1) {
      perror("shmctl(IPC_RMID)");
      exit(1);
    }

    assert(tcp->localshm);
  }
}

void free_tcb_CDE_fields(struct tcb* tcp) {
  if (tcp->localshm) {
    shmdt(tcp->localshm);
  }
  // need to null out elts in case table entries are recycled
  tcp->localshm = NULL;
  tcp->childshm = NULL;
  tcp->setting_up_shm = 0;
}


// inject a system call in the child process to tell it to attach our
// shared memory segment, so that it can read modified paths from there
//
// Setup a shared memory region within child process,
// then repeat current system call
static void begin_setup_shmat(struct tcb* tcp) {
  assert(tcp->localshm);
  assert(!tcp->childshm); // avoid duplicate calls

  // stash away original registers so that we can restore them later
  struct user_regs_struct cur_regs;
  EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
  memcpy(&tcp->saved_regs, &cur_regs, sizeof(cur_regs));

  // The return value of shmat (attached address) is actually stored in
  // the child's address space
  tcp->savedaddr = find_free_addr(tcp->pid, PROT_READ|PROT_WRITE, sizeof(int));
  tcp->savedword = ptrace(PTRACE_PEEKDATA, tcp->pid, tcp->savedaddr, 0);
  EXITIF(errno); // PTRACE_PEEKDATA reports error in errno

  /* The shmat call is implemented as a godawful sys_ipc. */
  cur_regs.orig_eax = __NR_ipc;
  /* The parameters are passed in ebx, ecx, edx, esi, edi, and ebp */
  cur_regs.ebx = SHMAT;
  /* The kernel names the rest of these, first, second, third, ptr,
   * and fifth. Only first, second and ptr are used as inputs.  Third
   * is a pointer to the output (unsigned long).
   */
  cur_regs.ecx = tcp->shmid;
  cur_regs.edx = 0; /* shmat flags */
  cur_regs.esi = (long)tcp->savedaddr; /* Pointer to the return value in the
                                          child's address space. */
  cur_regs.edi = (long)NULL; /* We don't use shmat's shmaddr */
  cur_regs.ebp = 0; /* The "fifth" argument is unused. */

  EXITIF(ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

  tcp->setting_up_shm = 1; // very importante!!!
}

void finish_setup_shmat(struct tcb* tcp) {
  struct user_regs_struct cur_regs;
  EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
  // setup had better been a success!
  assert(cur_regs.orig_eax == __NR_ipc);
  assert(cur_regs.eax == 0);

  errno = 0;
  tcp->childshm = (void*)ptrace(PTRACE_PEEKDATA, tcp->pid, tcp->savedaddr, 0);
  EXITIF(errno); // PTRACE_PEEKDATA reports error in errno

  // restore original data in child's address space
  EXITIF(ptrace(PTRACE_POKEDATA, tcp->pid, tcp->savedaddr, tcp->savedword));

  tcp->saved_regs.eax = tcp->saved_regs.orig_eax;

  // back up IP so that we can re-execute previous instruction
  // TODO: is the use of 2 specific to 32-bit machines???
  tcp->saved_regs.eip = tcp->saved_regs.eip - 2;
  EXITIF(ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&tcp->saved_regs) < 0);

  assert(tcp->childshm);

  tcp->setting_up_shm = 0; // very importante!!!
}

