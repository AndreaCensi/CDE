// mini-library for manipulating file paths on UNIX-like systems
// by Philip Guo

#include "paths.h"


// This forces gcc to use an older version of realpath from glibc 2.0,
// to maximize backwards compatibility
// See: http://www.trevorpounds.com/blog/?p=103
__asm__(".symver realpath,realpath@GLIBC_2.0");


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

