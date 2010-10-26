// mini-library for manipulating file paths on UNIX-like systems
// by Philip Guo

#include "paths.h"

// This forces gcc to use an older version of realpath from glibc 2.0,
// to maximize backwards compatibility
// See: http://www.trevorpounds.com/blog/?p=103
__asm__(".symver realpath,realpath@GLIBC_2.0");

#include <stdarg.h>
extern char* format(const char *format, ...);

// mallocs a new string
char* realpath_strdup(char* filename) {
  char path[PATH_MAX];
  path[0] = '\0';
  realpath(filename, path);
  assert(path[0] == '/'); // must be an absolute path
  return strdup(path);
}

// mallocs a new string
char* readlink_strdup(char* filename) {
  char path[PATH_MAX];

  path[0] = '\0';
  int len = readlink(filename, path, sizeof path);
  assert(path[0] != '\0');

  assert(len >= 0);
  path[len] = '\0'; // wow, readlink doesn't put the cap on the end!
  return strdup(path);
}


// representing and manipulating path components (courtesy of Goanna)

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


// emulate "mkdir -p" functionality
// if pop_one is non-zero, then pop last element
// before doing "mkdir -p"
void mkdir_recursive(char* fullpath, int pop_one) {
  struct path* p = str2path(fullpath);

  if (pop_one) {
    path_pop(p); // e.g., ignore filename portion to leave just the dirname
  }

  int i;
  for (i = 1; i <= p->depth; i++) {
    char* dn = path2str(p, i);
    mkdir(dn, 0777);
    free(dn);
  }
  delete_path(p);
}


// gets the absolute path of filename, WITHOUT following any symlinks
// (for relative paths, calculate their locations relative to
//  relative_path_basedir)
//
// mallocs a new string
char* realpath_nofollow(char* filename, char* relative_path_basedir) {
  assert(IS_ABSPATH(relative_path_basedir));

  char* ret = NULL;
  if (IS_ABSPATH(filename)) {
    char* bn = basename(filename); // doesn't destroy its arg

    char* filename_copy = strdup(filename); // dirname() destroys its arg
    char* dir = dirname(filename_copy);

    char* dir_realpath = realpath_strdup(dir);
    ret = format("%s/%s", dir_realpath, bn);
    free(dir_realpath);
    free(filename_copy);
  }
  else {
    // for relative links, find them with respect to relative_path_basedir
    char* tmp = format("%s/%s", relative_path_basedir, filename);
    char* bn = basename(tmp); // doesn't destroy its arg

    char* tmp_copy = strdup(tmp); // dirname() destroys its arg
    char* dir = dirname(tmp_copy);

    char* dir_realpath = realpath_strdup(dir);
    ret = format("%s/%s", dir_realpath, bn);
    free(dir_realpath);
    free(tmp_copy);
    free(tmp);
  }

  assert(ret);
  return ret;
}


// return 1 iff the absolute path of filename is within target_dir
// (for relative paths, calculate their locations relative to
//  relative_path_basedir)
int file_is_within_dir(char* filename, char* target_dir, char* relative_path_basedir) {
  assert(IS_ABSPATH(relative_path_basedir));

  char* path_to_check = NULL;
  if (IS_ABSPATH(filename)) {
    path_to_check = strdup(filename);
  }
  else {
    // note that the target program might have done a chdir, so we need to handle that ;)
    path_to_check = format("%s/%s", relative_path_basedir, filename);
  }
  assert(path_to_check);

  // just do a substring comparison against target_dir
  char* path_to_check_copy = strdup(path_to_check);
  char* dn = dirname(path_to_check_copy);

  char* dn_realpath = realpath_strdup(dn);
  int dn_len = strlen(dn_realpath);

  char* targetdir_realpath = realpath_strdup(target_dir);
  int targetdir_len = strlen(targetdir_realpath);

  // special case hack - if dn_realpath ends with '/.', then take its dirname
  // AGAIN to get rid of this annoyance :)
  while ((dn_len >= 2) &&
          dn_realpath[dn_len - 2] == '/' &&
          dn_realpath[dn_len - 1] == '.') {
    dn_realpath = dirname(dn_realpath);
    dn_len = strlen(dn_realpath);
  }

  char is_within_pwd = 0;
  if ((targetdir_len <= dn_len) && strncmp(dn_realpath, targetdir_realpath, targetdir_len) == 0) {
    is_within_pwd = 1;
  }

  free(path_to_check);
  free(path_to_check_copy);
  free(dn_realpath);
  free(targetdir_realpath);

  return is_within_pwd;
}

