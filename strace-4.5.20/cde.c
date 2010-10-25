#include "cde.h"

// This forces gcc to use an older version of realpath from glibc 2.0,
// to maximize backwards compatibility
// See: http://www.trevorpounds.com/blog/?p=103
__asm__(".symver realpath,realpath@GLIBC_2.0");

// 1 if we are executing code in a CDE package,
// 0 for tracing regular execution
char CDE_exec_mode;

static void begin_setup_shmat(struct tcb* tcp);
static void* find_free_addr(int pid, int exec, unsigned long size);
static void find_and_copy_possible_dynload_libs(char* filename);

#define SHARED_PAGE_SIZE (MAXPATHLEN * 2)

// quick check for whether a path is absolute
#define IS_ABSPATH(p) (p[0] == '/')

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

static char* redirect_filename(char* filename);
static void memcpy_to_child(int pid, char* dst_child, char* src, int size);

// used as temporary holding spaces for paths copied from child process
static char path[MAXPATHLEN + 1];

// to shut up gcc warnings without going thru #include hell
extern char* basename(const char *fname);
extern char *dirname(char *path);
extern ssize_t getline(char **lineptr, size_t *n, FILE *stream);

// maps relative paths to their locations within cde-root/
// (serialized as cde-root/cde.relpaths file)
static struct {
  char* src;
  char* tgt;
} relpath_map[50];
static int relpath_map_size = 0;


void CDE_init_relpaths(void) {
  FILE* relpath_f = fopen(CDE_ROOT "/cde.relpaths", "r");
  if (!relpath_f) {
    return;
  }

  size_t len = 0;
  ssize_t read;
  char* tmp = NULL; // getline() mallocs for us
  while ((read = getline(&tmp, &len, relpath_f)) != -1) {
    // gross string manipulation in C, ugh :(

    // strip off trailing newline
    assert(tmp[read-1] == '\n');
    tmp[read-1] = '\0';
    char* colon = strchr(tmp, ':');
    assert(colon);
    char* tgt = colon + 1;
    *colon = '\0';
    char* src = tmp;

    relpath_map[relpath_map_size].src = strdup(src);
    relpath_map[relpath_map_size].tgt = strdup(tgt);
    relpath_map_size++;
    assert(relpath_map_size < 50); // bound it for simplicity
  }
  free(tmp);
  fclose(relpath_f);
}


// useful utility function from ccache codebase
// http://ccache.samba.org/
/* Construct a string according to a format. Caller frees. */
char *
format(const char *format, ...)
{
  va_list ap;
  char *ptr = NULL;

  va_start(ap, format);
  EXITIF(vasprintf(&ptr, format, ap) == -1);
  va_end(ap);

  EXITIF(!*ptr);
  return ptr;
}

// prepend "cde-root" to the given path string, assumes that the string
// starts with '/' (i.e., it's an absolute path)
// mallocs a new string!
char* prepend_cderoot(char* path) {
  assert(IS_ABSPATH(path));
  char* ret = malloc(CDE_ROOT_LEN + strlen(path) + 1);
  strcpy(ret, CDE_ROOT);
  strcat(ret, path);
  return ret;
}


// emulate "mkdir -p" functionality
// if pop_one is non-zero, then pop last element first
static void mkdir_recursive(char* fullpath, int pop_one) {
  struct path* p = str2path(fullpath);

  if (pop_one) {
    path_pop(p); // ignore filename portion to leave just the dirname
  }

  int i;
  for (i = 1; i <= p->depth; i++) {
    char* dn = path2str(p, i);
    mkdir(dn, 0777);
    free(dn);
  }
  delete_path(p);
}


// ignore these special paths:
static int ignore_path(char* filename) {
  // /dev and /proc are special system directories with fake files
  //
  // .Xauthority is used for X11 authentication via ssh, so we need to
  // use the REAL version and not the one in cde-root/
  //
  // TODO: /proc/sys/kernel/osrelease is sometimes used instead of uname
  //       syscall, so perhaps don't ignore it
  if ((strncmp(filename, "/dev/", 5) == 0) ||
      (strncmp(filename, "/proc/", 6) == 0) ||
      (strcmp(basename(filename), ".Xauthority") == 0)) {
    return 1;
  }

  return 0;
}

// gets the absolute path of filename, WITHOUT following any symlinks
// mallocs a new string
static char* realpath_nofollow(char* filename) {
  // only call this function when NOT in CDE_exec_mode, since when we're
  // in CDE_exec_mode, we're likely on someone else's machine, so
  // relative paths will resolve to different absolute paths, eek!
  assert(!CDE_exec_mode);

  char* bn = basename(filename); // doesn't destroy its arg

  char* filename_copy = strdup(filename); // dirname() destroys its arg
  char* dir = dirname(filename_copy);
  path[0] = '\0';
  realpath(dir, path);
  assert(path[0] != '\0');

  char* ret = format("%s/%s", path, bn);

  free(filename_copy);
  return ret;
}


// return 1 iff the absolute path of filename is within pwd
static int file_is_within_pwd(char* filename) {

  if (IS_ABSPATH(filename)) {
    // grab the TRUE system's pwd
    getcwd(path, sizeof path);
    char* pwd = path;

    // just do a substring comparison
    char* filename_copy = strdup(filename);
    char* dn = dirname(filename_copy);

    int dn_len = strlen(dn);
    int pwd_len = strlen(pwd);

    // special case hack - if dn ends with '/.', then take its dirname
    // AGAIN to get rid of this annoyance :)
    while ((dn_len >= 2) && dn[dn_len - 2] == '/' && dn[dn_len - 1] == '.') {
      dn = dirname(dn);
      dn_len = strlen(dn);
    }

    char is_within_pwd = 0;

    //printf("file_is_within_pwd %s %s\n", dn, pwd);
    if ((pwd_len <= dn_len) && strncmp(dn, pwd, pwd_len) == 0) {
      is_within_pwd = 1;
    }

    free(filename_copy);
    return is_within_pwd;
  }
  else {
    // if you're given a relative path, then a super-simple check is if
    // it starts with '..' (or a bunch of '.' followed by a '..')
    // TODO: this probably doesn't handle all cases; after all, we're
    // not going for security here :)
    if (strncmp(filename, "..", 2) == 0) {
      return 0;
    }
    else {
      return 1;
    }
  }

  assert(0); // shouldn't reach here
  return 0;
}


// cp $src_filename $dst_filename
// note that this WILL follow symlinks
void copy_file(char* src_filename, char* dst_filename) {
  int inF;
  int outF;
  int bytes;
  char buf[4096]; // TODO: consider using BUFSIZ if it works better

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

// if filename is a symlink, then copy both it AND its target into cde-root
static void copy_file_into_cde_root(char* filename) {
  assert(filename);
  assert(!CDE_exec_mode);

  // don't copy filename that we're ignoring
  if (ignore_path(filename)) {
    return;
  }

  // don't do anything for files inside of pwd :)
  if (file_is_within_pwd(filename)) {
    return;
  }


  // this will NOT follow the symlink ...
  struct stat filename_stat;
  EXITIF(lstat(filename, &filename_stat));
  char is_symlink = S_ISLNK(filename_stat.st_mode);

  if (is_symlink) {
    // this will follow the symlink ...
    EXITIF(stat(filename, &filename_stat));
  }


  // by now, filename_stat contains the info for the actual target file,
  // NOT a symlink to it

  // resolve absolute path to get rid of '..', '.', and other weird symbols
  char* filename_abspath = realpath_nofollow(filename);

  char* dst_path = prepend_cderoot(filename_abspath);

  // Record an entry in cde-root/cde.relpaths to map the directory
  // names of relative path to the appropriate location within cde-root/.
  //
  // We need to do this because when we move the package to another
  // machine, relative paths will be resolved differently, so we need
  // to consult cde.relpaths to find out where files are located in
  // the package.
  if (!IS_ABSPATH(filename)) {
    char* rel_filename_copy = strdup(filename); // dirname() destroys its arg
    char* rel_dir = dirname(rel_filename_copy);

    char* dst_path_copy = strdup(dst_path); // dirname() destroys its arg
    char* dir_within_package = dirname(dst_path_copy);

    // don't insert duplicates
    int i;
    int found = 0;
    for (i = 0; i < relpath_map_size; i++) {
      if (strcmp(relpath_map[i].src, rel_dir) == 0) {
        assert(strcmp(relpath_map[i].tgt, dir_within_package) == 0);
        found = 1;
        break;
      }
    }

    if (!found) {
      relpath_map[relpath_map_size].src = strdup(rel_dir);
      relpath_map[relpath_map_size].tgt = strdup(dir_within_package);
      relpath_map_size++;
      assert(relpath_map_size < 50); // bound it for simplicity

      FILE* relpath_f = fopen(CDE_ROOT "/cde.relpaths", "a");
      assert(relpath_f);

      // colon-delimited to support paths with spaces in them
      fprintf(relpath_f, "%s:%s\n", rel_dir, dir_within_package);
      fclose(relpath_f);
    }

    free(dst_path_copy);
    free(rel_filename_copy);
  }


  if (S_ISREG(filename_stat.st_mode)) { // regular file

    // lazy optimization to avoid redundant copies ...
    struct stat dst_path_stat;
    if (stat(dst_path, &dst_path_stat) == 0) {
      // if the destination file exists and is newer than the original
      // filename, then don't do anything!
      if (dst_path_stat.st_mtime >= filename_stat.st_mtime) {
        //printf("PUNTED on %s\n", dst_path);
        goto done;
      }
    }

    mkdir_recursive(dst_path, 1);

    // finally, 'copy' filename over to dst_path

    // if it's a symlink, copy both it and its target
    if (is_symlink) {
      // target file must exist, so let's resolve its name
      int len = readlink(filename, path, sizeof path);
      EXITIF(len < 0);
      path[len] = '\0'; // wow, readlink doesn't put the cap on the end!
      char* orig_symlink_target = strdup(path);

      char* filename_copy = strdup(filename); // dirname() destroys its arg
      char* dir = dirname(filename_copy);

      // resolve the realpath() of dir
      path[0] = '\0';
      realpath(dir, path);
      assert(path[0] != '\0');

      // now path is the realpath() of dir
      assert(path[0] == '/');

      char* symlink_target_abspath = NULL;
      // ugh, remember that symlinks can point to both absolute AND
      // relative paths ...
      if (IS_ABSPATH(orig_symlink_target)) {
        symlink_target_abspath = strdup(orig_symlink_target);
      }
      else {
        symlink_target_abspath = format("%s/%s", path, orig_symlink_target);
      }
      assert(symlink_target_abspath);

      char* symlink_loc_in_package = prepend_cderoot(filename_abspath);

      // create a new identical symlink in cde-root/
      //printf("symlink(%s, %s)\n", orig_symlink_target, symlink_loc_in_package);
      EXITIF(symlink(orig_symlink_target, symlink_loc_in_package) < 0);

      char* tmp = prepend_cderoot(symlink_target_abspath);
      // ok, let's get the absolute path without any '..' or '.' funniness
      char* symlink_dst_abspath = realpath_nofollow(tmp);
      free(tmp);

      // ugh, this is getting really really gross, mkdir all dirs stated in
      // symlink_dst_abspath if they don't yet exist
      mkdir_recursive(symlink_dst_abspath, 1);

      //printf("  cp %s %s\n", symlink_target_abspath, symlink_dst_abspath);
      // copy the target file over to cde-root/
      if ((link(symlink_target_abspath, symlink_dst_abspath) != 0) && (errno != EEXIST)) {
        copy_file(symlink_target_abspath, symlink_dst_abspath);
      }

      free(symlink_loc_in_package);
      free(symlink_target_abspath);
      free(symlink_dst_abspath);
      free(orig_symlink_target);
      free(filename_copy);
    }
    else { // regular file, simple common case :)
      // 1.) try a hard link for efficiency
      // 2.) if that fails, then do a straight-up copy,
      //     but do NOT follow symlinks
      //
      // EEXIST means the file already exists, which isn't
      // really a hard link failure ...
      if ((link(filename, dst_path) != 0) && (errno != EEXIST)) {
        copy_file(filename, dst_path);
      }
    }


    // if it's a shared library, then heuristically try to grep
    // through it to find whether it might dynamically load any other
    // libraries (e.g., those for other CPU types that we can't pick
    // up via strace)
    find_and_copy_possible_dynload_libs(filename);

  }
  else if (S_ISDIR(filename_stat.st_mode)) { // directory
    // do a "mkdir -p filename" after redirecting it into cde-root/
    mkdir_recursive(dst_path, 0);
  }

done:
  free(dst_path);
  free(filename_abspath);
}


#define STRING_ISGRAPHIC(c) ( ((c) == '\t' || (isascii (c) && isprint (c))) )

/* If filename is an ELF binary file, then do a binary grep through it
   looking for strings that might be '.so' files, as well as dlopen*,
   which is a function call to dynamically load an .so file.  Find
   whether any of the .so files exist in the same directory as filename,
   and if so, COPY them into cde-root/ as well.

   The purpose of this hack is to pick up on libraries for alternative
   CPU types that weren't picked up when running on this machine.  When
   the package is ported to another machine, the program might load one
   of these alternative libraries.
  
   Note that this heuristic might lead to false positives (incidental
   matches) and false negatives (cannot find dynamically-generated
   strings).  
  
   code adapted from the string program (strings.c) in GNU binutils */
static void find_and_copy_possible_dynload_libs(char* filename) {
  FILE* f = fopen(filename, "rb"); // open in binary mode
  if (!f) {
    return;
  }

  char header[5];
  memset(header, 0, sizeof(header));
  fgets(header, 5, f); // 5 means 4 bytes + 1 null terminating byte

  // if it's not even an ELF binary, then punt early for efficiency
  if (strcmp(header, "\177ELF") != 0) {
    //printf("Sorry, not ELF %s\n", filename);
    fclose(f);
    return;
  }

  int i;
  int dlopen_found = 0; // did we find a symbol starting with 'dlopen'?

  static char cur_string[4096];
  cur_string[0] = '\0';
  int cur_ind = 0;

  // it's unrealistic to expect more than 50, right???
  char* libs_to_check[50];
  int libs_to_check_ind = 0;

  while (1) {

    while (1) {
      int c = getc(f);
      if (c == EOF)
        goto done;
      if (!STRING_ISGRAPHIC(c))
        break;

      // don't overflow ... just truncate off of end
      if (cur_ind < sizeof(cur_string) - 1) {
        cur_string[cur_ind++] = c;
      }
    }

    // done with a string
    cur_string[cur_ind] = '\0';

    int cur_strlen = strlen(cur_string);

    // don't even bother for short strings:
    if (cur_strlen >= 4) {
      // check that it ends with '.so'
      if ((cur_string[cur_strlen - 3] == '.') &&
          (cur_string[cur_strlen - 2] == 's') &&
          (cur_string[cur_strlen - 1] == 'o')) {

        libs_to_check[libs_to_check_ind++] = strdup(cur_string);
        assert(libs_to_check_ind < 50); // bounds check
      }

      if (strncmp(cur_string, "dlopen", 6) == 0) {
        dlopen_found = 1;
      }
    }

    // reset buffer
    cur_string[0] = '\0';
    cur_ind = 0;
  }


done:
  // for efficiency and to prevent false positives,
  // only do filesystem checks if dlopen has been found
  if (dlopen_found) {
    char* filename_copy = strdup(filename); // dirname() destroys its arg
    char* dn = dirname(filename_copy);

    for (i = 0; i < libs_to_check_ind; i++) {
      char* lib_fullpath = format("%s/%s", dn, libs_to_check[i]);
      // if the target library exists, then copy it into our package
      struct stat st;
      if (stat(lib_fullpath, &st) == 0) {
        //printf("%s %s\n", filename, lib_fullpath);
        copy_file_into_cde_root(lib_fullpath);
      }
      free(lib_fullpath);
    }

    free(filename_copy);
  }


  for (i = 0; i < libs_to_check_ind; i++) {
    free(libs_to_check[i]);
  }

  fclose(f);
}


// modify the first argument to the given system call to a path within
// cde-root/, if applicable
//
// assumes tcp->opened_filename has already been set
static void modify_syscall_first_arg(struct tcb* tcp) {
  assert(CDE_exec_mode);
  assert(tcp->opened_filename);

  char* redirected_filename = redirect_filename(tcp->opened_filename);

  // do nothing if redirect_filename returns NULL ...
  if (!redirected_filename) {
    return;
  }

  //printf("  attempt to modify %s => %s %d\n", tcp->opened_filename, redirected_filename, tcp->pid);

  if (!tcp->childshm) {
    begin_setup_shmat(tcp);

    // no more need for filename, so don't leak it
    free(redirected_filename);
    free(tcp->opened_filename);
    tcp->opened_filename = NULL;

    return; // MUST punt early here!!!
  }

  // redirect all requests for absolute paths to version within cde-root/
  // if those files exist!

  strcpy(tcp->localshm, redirected_filename); // hopefully this doesn't overflow :0

  //printf("  redirect %s\n", tcp->localshm);
  //static char tmp[MAXPATHLEN + 1];
  //EXITIF(umovestr(tcp, (long)tcp->childshm, sizeof tmp, tmp) < 0);
  //printf("     %s\n", tmp);

  struct user_regs_struct cur_regs;
  EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
  cur_regs.ebx = (long)tcp->childshm;
  ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);

  free(redirected_filename);
}

// copy and paste from modify_syscall_first_arg ;)
static void modify_syscall_two_args(struct tcb* tcp) {
  assert(CDE_exec_mode);

  if (!tcp->childshm) {
    begin_setup_shmat(tcp);
    return; // MUST punt early here!!!
  }

  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  char* redirected_filename1 = redirect_filename(path);

  EXITIF(umovestr(tcp, (long)tcp->u_arg[1], sizeof path, path) < 0);
  char* redirected_filename2 = redirect_filename(path);

  // gotta do both, yuck
  if (redirected_filename1 && redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename1);

    int len1 = strlen(redirected_filename1);
    char* redirect_file2_begin = ((char*)tcp->localshm) + len1 + 1;
    strcpy(redirect_file2_begin, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
    cur_regs.ebx = (long)tcp->childshm;
    cur_regs.ecx = (long)(((char*)tcp->childshm) + len1 + 1);
    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);

    //static char tmp[MAXPATHLEN + 1];
    //EXITIF(umovestr(tcp, (long)cur_regs.ebx, sizeof tmp, tmp) < 0);
    //printf("  ebx: %s\n", tmp);
    //EXITIF(umovestr(tcp, (long)cur_regs.ecx, sizeof tmp, tmp) < 0);
    //printf("  ecx: %s\n", tmp);
  }
  else if (redirected_filename1) {
    strcpy(tcp->localshm, redirected_filename1);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
    cur_regs.ebx = (long)tcp->childshm; // only set EBX
    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }
  else if (redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
    cur_regs.ecx = (long)tcp->childshm; // only set ECX
    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }

  if (redirected_filename1) free(redirected_filename1);
  if (redirected_filename2) free(redirected_filename2);
}


// create a malloc'ed filename that contains a version within cde-root/
// return NULL if the filename should NOT be redirected
static char* redirect_filename(char* filename) {
  assert(filename);

  // don't redirect certain special paths
  if (ignore_path(filename)) {
    return NULL;
  }

  if (!file_is_within_pwd(filename)) {
    if (IS_ABSPATH(filename)) {
      // easy case: absolute path, just do a plain redirect :)
      return prepend_cderoot(filename);
    }
    else {
      // hard case: relative path ... consult relpath_map to do redirection
      char* rel_filename_copy = strdup(filename); // dirname() destroys its arg
      char* rel_dir = dirname(rel_filename_copy);

      char* bn = basename(filename); // doesn't destroy its arg

      int i;
      int found = 0;
      char* dst_dir = NULL;
      for (i = 0; i < relpath_map_size; i++) {
        if (strcmp(relpath_map[i].src, rel_dir) == 0) {
          dst_dir = relpath_map[i].tgt;
          found = 1;
          break;
        }
      }

      // if we can't find the path in relpath_map, then we're screwed!!!
      assert(found && dst_dir);

      char* dst_path = format("%s/%s", dst_dir, bn);

      free(rel_filename_copy);
      return dst_path;
    }
  }

  return NULL;
}

/* standard functionality for syscalls that take a filename as first argument

  trace mode:
    - ONLY on success, if abspath(filename) is outside pwd, then copy it
      into cde-root/
      - also, if filename is a symlink, then copy the target into the
        proper location (maybe using readlink?)

  exec mode:
    - if abspath(filename) is outside pwd, then redirect it into cde-root/

sys_open(filename, flags, mode)
sys_creat(filename, mode)
sys_chmod(filename, ...)
sys_chown(filename, ...)
sys_chown16(filename, ...)
sys_lchown(filename, ...)
sys_lchown16(filename, ...)
sys_stat(filename, ...)
sys_stat64(filename, ...)
sys_lstat(filename, ...)
sys_lstat64(filename, ...)
sys_truncate(path, length)
sys_truncate64(path, length)
sys_access(filename, mode)
sys_utime(filename, ...)
sys_readlink(path, ...)

 */
void CDE_begin_standard_fileop(struct tcb* tcp, const char* syscall_name) {
  assert(!tcp->opened_filename);
  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  tcp->opened_filename = strdup(path);

  if (CDE_exec_mode) {
    //printf("begin %s %s\n", syscall_name, tcp->opened_filename);
    modify_syscall_first_arg(tcp);
  }
}

/* depending on value of success_type, do a different check for success

   success_type = 0 - zero return value is a success (e.g., for stat)
   success_type = 1 - non-negative return value is a success (e.g., for open or readlink)

 */
void CDE_end_standard_fileop(struct tcb* tcp, const char* syscall_name,
                             char success_type) {
  assert(tcp->opened_filename);
 
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (((success_type == 0) && (tcp->u_rval == 0)) ||
        ((success_type == 1) && (tcp->u_rval >= 0))) {
      copy_file_into_cde_root(tcp->opened_filename);
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


void CDE_begin_execve(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  tcp->opened_filename = strdup(path);

  // only attempt to do the ld-linux.so.2 trick if tcp->opened_filename
  // is a valid executable file WITHIN cde-root/ ... otherwise don't do
  // anything and simply let the execve fail just like it's supposed to
  struct stat filename_stat;

  //printf("%s CDE_begin_execve\n", tcp->opened_filename);

  char* redirected_path = redirect_filename(tcp->opened_filename);
  char* path_to_executable = NULL;
  if (redirected_path) {
    // TODO: we don't check whether it's a real executable file :/
    if (stat(redirected_path, &filename_stat) != 0) {
      free(redirected_path);
      return;
    }
    path_to_executable = redirected_path;
  }
  else {
    // just check the file itself
    // TODO: we don't check whether it's a real executable file :/
    if (stat(tcp->opened_filename, &filename_stat) != 0) {
      return;
    }
    path_to_executable = tcp->opened_filename;
  }
  assert(path_to_executable);

  // ld-linux.so.2 only works on dynamically-linked binary executable
  // files; it will fail if you invoke it on:
  //   - a textual script file
  //   - a statically-linked binary
  //
  // for a textual script file, we must invoke ld-linux.so.2 on the
  // target of the shebang #! (which can itself take arguments)
  //
  // e.g., #! /bin/sh
  // e.g., #! /usr/bin/env python
  //
  // TODO: for a statically-linked binary, don't do anything
  char is_textual_script = 0;
  char is_elf_binary = 0;
  char* script_command = NULL;

  FILE* f = fopen(path_to_executable, "rb"); // open in binary mode
  assert(f);
  char header[5];
  memset(header, 0, sizeof(header));
  fgets(header, 5, f); // 5 means 4 bytes + 1 null terminating byte
  if (strcmp(header, "\177ELF") == 0) {
    is_elf_binary = 1;
  }
  fclose(f);

  if (is_elf_binary) {
    // TODO: look for whether it's a statically-linked binary ...
    // if so, then there is NO need to call ld-linux.so.2 on it;
    // we can just execute it directly (in fact, ld-linux.so.2
    // will fail on static binaries!)
  }
  else {
    // find out whether it's a script file (starting with #! line)
    FILE* f = fopen(path_to_executable, "rb"); // open in binary mode

    size_t len = 0;
    ssize_t read;
    char* tmp = NULL; // getline() mallocs for us
    read = getline(&tmp, &len, f);
    if (read > 2) {
      assert(tmp[read-1] == '\n'); // strip of trailing newline
      tmp[read-1] = '\0'; // strip of trailing newline
      if (tmp[0] == '#' && tmp[1] == '!') {
        is_textual_script = 1;
        script_command = strdup(&tmp[2]);
      }
    }
    free(tmp);
  }


  if (CDE_exec_mode) {
    // set up shared memory segment if we haven't done so yet
    if (!tcp->childshm) {
      begin_setup_shmat(tcp);

      // no more need for filename, so don't leak it
      free(tcp->opened_filename);
      tcp->opened_filename = NULL;

      goto done; // MUST punt early here!!!
    }

    /* we're gonna do some craziness here to redirect the OS to call
       cde-root/ld-linux.so.2 rather than the real program, since
       ld-linux.so.2 is closely-tied with the version of libc in
       cde-root/. */
    if (is_textual_script) {
      /*  we're running a script with a shebang (#!), so
          let's set up the shared memory segment (tcp->localshm) like so:

    base -->       tcp->localshm : "cde-root/ld-linux.so.2"
          script_command token 0 : "/usr/bin/env"
          script_command token 1 : "python"
              ... (for as many tokens as available) ...
    new_argv -->   argv pointers : point to tcp->childshm ("cde-root/ld-linux.so.2")
                   argv pointers : point to script_command token 0
                   argv pointers : point to script_command token 1
              ... (for as many tokens as available) ...
                   argv pointers : point to tcp->u_arg[0] (original program name)
                   argv pointers : point to child program's argv[1]
                   argv pointers : point to child program's argv[2]
                   argv pointers : point to child program's argv[3]
                   argv pointers : [...]
                   argv pointers : NULL

        Note that we only need to do this if we're in CDE_exec_mode */

      //printf("script_command='%s', path_to_executable='%s'\n", script_command, path_to_executable);

      char* base = (char*)tcp->localshm;
      strcpy(base, CDE_ROOT "/ld-linux.so.2");
      int ld_linux_offset = strlen(CDE_ROOT "/ld-linux.so.2") + 1;

      char* cur_loc = (char*)(base + ld_linux_offset);
      char* script_command_token_starts[30]; // stores starting locations of each token

      int script_command_num_tokens = 0;

      // tokenize script_command into tokens, and insert them into argv
      char* p;
      for (p = strtok(script_command, " "); p; p = strtok(NULL, " ")) {
        //printf("  token = %s\n", p);
        strcpy(cur_loc, p);
        script_command_token_starts[script_command_num_tokens] = cur_loc;

        cur_loc += (strlen(p) + 1);
        script_command_num_tokens++;
      }

      char** new_argv = (char**)(cur_loc);

      // really subtle, these addresses should be in the CHILD's address space,
      // not the parent's

      // points to "cde-root/ld-linux.so.2"
      new_argv[0] = (char*)tcp->childshm;

      // points to all the tokens of script_command
      int i;
      for (i = 0; i < script_command_num_tokens; i++) {
        new_argv[i+1] = (char*)tcp->childshm + (script_command_token_starts[i] - base);
      }

      // now populate argv[script_command_num_tokens:] directly from child's original space
      // (original arguments)
      char** child_argv = (char**)tcp->u_arg[1]; // in child's address space
      char* cur_arg = NULL;
      i = 0; // start at argv[0]
      while (1) {
        EXITIF(umovestr(tcp, (long)(child_argv + i), sizeof cur_arg, (void*)&cur_arg) < 0);
        new_argv[i + script_command_num_tokens + 1] = cur_arg;
        if (cur_arg == NULL) {
          break;
        }
        i++;
      }

      i = 0;
      cur_arg = NULL;
      while (1) {
        cur_arg = new_argv[i];
        if (cur_arg) {
          EXITIF(umovestr(tcp, (long)cur_arg, sizeof path, path) < 0);
          //printf("  new_argv[%d] = %s\n", i, path);
          i++;
        }
        // argv is null-terminated
        else {
          break;
        }
      }

      // now set ebx to the new program name and ecx to the new argv array
      // to alter the arguments of the execv system call :0
      struct user_regs_struct cur_regs;
      EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
      cur_regs.ebx = (long)tcp->childshm;            // location of base
      cur_regs.ecx = ((long)tcp->childshm) + ((char*)new_argv - base); // location of new_argv
      ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
    }
    else {
      /* we're running a dynamically-linked binary executable, go
         let's set up the shared memory segment (tcp->localshm) like so:

    base -->       tcp->localshm : "cde-root/ld-linux.so.2"
    new_argv -->   argv pointers : point to tcp->childshm ("cde-root/ld-linux.so.2")
                   argv pointers : point to tcp->u_arg[0] (original program name)
                   argv pointers : point to child program's argv[1]
                   argv pointers : point to child program's argv[2]
                   argv pointers : point to child program's argv[3]
                   argv pointers : [...]
                   argv pointers : NULL

        Note that we only need to do this if we're in CDE_exec_mode */

      char* base = (char*)tcp->localshm;
      strcpy(base, CDE_ROOT "/ld-linux.so.2");
      int offset = strlen(CDE_ROOT "/ld-linux.so.2") + 1;
      char** new_argv = (char**)(base + offset);

      // really subtle, these addresses should be in the CHILD's address space,
      // not the parent's

      // points to "cde-root/ld-linux.so.2"
      new_argv[0] = (char*)tcp->childshm;
      // points to original program name (full path)
      new_argv[1] = (char*)tcp->u_arg[0];

      // now populate argv[1:] directly from child's original space
      // (original arguments)
   
      char** child_argv = (char**)tcp->u_arg[1]; // in child's address space
      char* cur_arg = NULL;
      int i = 1; // start at argv[1], since we're ignoring argv[0]
      while (1) {
        EXITIF(umovestr(tcp, (long)(child_argv + i), sizeof cur_arg, (void*)&cur_arg) < 0);
        new_argv[i + 1] = cur_arg;
        if (cur_arg == NULL) {
          break;
        }
        i++;
      }

      i = 0;
      cur_arg = NULL;
      while (1) {
        cur_arg = new_argv[i];
        if (cur_arg) {
          EXITIF(umovestr(tcp, (long)cur_arg, sizeof path, path) < 0);
          //printf("  new_argv[%d] = %s\n", i, path);
          i++;
        }
        // argv is null-terminated
        else {
          break;
        }
      }

      // now set ebx to the new program name and ecx to the new argv array
      // to alter the arguments of the execv system call :0
      struct user_regs_struct cur_regs;
      EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
      cur_regs.ebx = (long)tcp->childshm;            // location of base
      cur_regs.ecx = ((long)tcp->childshm) + offset; // location of new_argv
      ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
    }
  }
  else {
    // very subtle!  if we're executing a textual script with a #!, we
    // need to grab the name of the executable from the #! string into
    // cde-root, since strace doesn't normally pick it up as a dependency
    if (is_textual_script) {
      //printf("script_command='%s', path_to_executable='%s'\n", script_command, path_to_executable);
      char* p;
      for (p = strtok(script_command, " "); p; p = strtok(NULL, " ")) {
        struct stat p_stat;
        if (stat(p, &p_stat) == 0) {
          copy_file_into_cde_root(p);
        }
        break;
      }
    }
  }

done:
  free(redirected_path); // don't free until we no longer need path_to_executable
  if (script_command) {
    free(script_command);
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
      copy_file_into_cde_root(tcp->opened_filename);
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


#include <sys/utsname.h>

void CDE_end_uname(struct tcb* tcp) {
  struct utsname uname;

  if (CDE_exec_mode) {
    // if cde-root/cde.uname exists, read cached copy and override
    // return value with it; otherwise don't do anything
    int inF = open(CDE_ROOT "/cde.uname", O_RDONLY);
    if (inF >= 0) {
      read(inF, &uname, sizeof(uname));
      close(inF);

      //printf("saved uname.release='%s'\n", uname.release);
      //strcpy(uname.release, "ooga booga"); // for testing :)
      memcpy_to_child(tcp->pid, (char*)tcp->u_arg[0], (char*)&uname, sizeof uname);
    }
  }
  else {
    EXITIF(umove(tcp, tcp->u_arg[0], &uname) < 0);
    //printf("uname.release='%s'\n", uname.release);

    // serialize the bytes of uname LITERALLY to cde-root/cde.uname
    // (overriding previous contents).  we don't have to care about big
    // vs. little endian since CDE isn't portably across CPU
    // architectures anyways ;)
    int outF = open(CDE_ROOT "/cde.uname", O_WRONLY | O_CREAT, 0777);
    write(outF, &uname, sizeof(uname));
    close(outF);
  }
}


void CDE_begin_file_unlink(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
  tcp->opened_filename = strdup(path);
  //printf("CDE_begin_file_unlink %s\n", tcp->opened_filename);

  if (CDE_exec_mode) {
    modify_syscall_first_arg(tcp);
  }
  else {
    char* redirected_path = redirect_filename(tcp->opened_filename);
    if (redirected_path) {
      unlink(redirected_path);
      free(redirected_path);
    }
  }

  // no need for this anymore
  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


void CDE_begin_file_link(struct tcb* tcp) {
  //printf("CDE_begin_file_link\n");
  if (CDE_exec_mode) {
    modify_syscall_two_args(tcp);
  }
}

void CDE_end_file_link(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
      char* redirected_filename1 = redirect_filename(path);

      // first copy the origin file into cde-root/ before trying to link it
      char* filename_tmp = strdup(path);
      copy_file_into_cde_root(filename_tmp);
      free(filename_tmp);

      EXITIF(umovestr(tcp, (long)tcp->u_arg[1], sizeof path, path) < 0);
      char* redirected_filename2 = redirect_filename(path);

      link(redirected_filename1, redirected_filename2);

      free(redirected_filename1);
      free(redirected_filename2);
    }
  }
}

void CDE_begin_file_symlink(struct tcb* tcp) {
  //printf("CDE_begin_file_symlink\n");
  if (CDE_exec_mode) {
    modify_syscall_two_args(tcp);
  }
}

void CDE_end_file_symlink(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
      char* oldname = strdup(path);

      EXITIF(umovestr(tcp, (long)tcp->u_arg[1], sizeof path, path) < 0);
      char* newname_redirected = redirect_filename(path);

      symlink(oldname, newname_redirected);

      free(oldname);
      free(newname_redirected);
    }
  }
}


void CDE_begin_file_rename(struct tcb* tcp) {
  if (CDE_exec_mode) {
    modify_syscall_two_args(tcp);
  }
}

void CDE_end_file_rename(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
      char* redirected_filename1 = redirect_filename(path);
      // remove original file from cde-root/
      if (redirected_filename1) {
        unlink(redirected_filename1);
        free(redirected_filename1);
      }

      EXITIF(umovestr(tcp, (long)tcp->u_arg[1], sizeof path, path) < 0);
      // copy the destination file into cde-root/
      char* filename_tmp = strdup(path);
      copy_file_into_cde_root(filename_tmp);
      free(filename_tmp);
    }
  }
}

void CDE_begin_chdir(struct tcb* tcp) {
  CDE_begin_standard_fileop(tcp, "chdir");
}

void CDE_end_chdir(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* redirected_path = redirect_filename(tcp->opened_filename);
      if (redirected_path) {
        mkdir_recursive(redirected_path, 0);
        free(redirected_path);
      }
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}

void CDE_begin_mkdir(struct tcb* tcp) {
  CDE_begin_standard_fileop(tcp, "mkdir");
}

void CDE_end_mkdir(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* redirected_path = redirect_filename(tcp->opened_filename);
      if (redirected_path) {
        mkdir_recursive(redirected_path, 0);
        free(redirected_path);
      }
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}

void CDE_begin_rmdir(struct tcb* tcp) {
  CDE_begin_standard_fileop(tcp, "rmdir");
}

void CDE_end_rmdir(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* redirected_path = redirect_filename(tcp->opened_filename);
      if (redirected_path) {
        rmdir(redirected_path);
        free(redirected_path);
      }
    }
  }

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
      tcp->shmid = shmget(key, SHARED_PAGE_SIZE, IPC_CREAT|IPC_EXCL|0600);
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


// copy src into dst, redirecting it into cde-root/ if necessary
// dst should be big enough to hold a full path
void strcpy_redirected_cderoot(char* dst, char* src) {
  char* redirected_src = redirect_filename(src);
  if (redirected_src) {
    strcpy(dst, redirected_src);
    free(redirected_src);
  }
  else {
    strcpy(dst, src);
  }
}

// adapted from the Goanna project by Spillane et al.
// dst_in_child is a pointer in the child's address space
static void memcpy_to_child(int pid, char* dst_child, char* src, int size) {
  while (size >= sizeof(int)) {
    long w = *((long*)src);
    EXITIF(ptrace(PTRACE_POKEDATA, pid, dst_child, (long)w) < 0);
    size -= sizeof(int);
    dst_child = (char*)dst_child + sizeof(int);
    src = (char*)src + sizeof(int);
  }

  /* Cleanup the last little bit. */
  if (size) {
    union {
        long l;
        char c[4];
    } dw, sw;
    errno = 0;
    dw.l = ptrace(PTRACE_PEEKDATA, pid, dst_child, 0);
    EXITIF(errno);
    sw.l = *((long*)src);

    /* Little endian sucks. */
    dw.c[0] = sw.c[0];
    if (size >= 2)
      dw.c[1] = sw.c[1];
    if (size >= 3)
      dw.c[2] = sw.c[2];
	  assert(size < 4);

    EXITIF(ptrace(PTRACE_POKEDATA, pid, dst_child, dw.l) < 0);
  }
}

// hmmm, don't do any path spoofing yet
void CDE_end_getcwd(struct tcb* tcp) {
  /*
  if (!syserror(tcp)) {
    //char stuff[100];
    //strcpy(stuff, "/tmp/chttpd/obj-klee/src");
    //memcpy_to_child(tcp->pid, (char*)tcp->u_arg[0], stuff, 25);

    //EXITIF(umovestr(tcp, (long)tcp->u_arg[0], sizeof path, path) < 0);
    //printf("CDE_end_getcwd %s\n", path);
  }
  */
}

