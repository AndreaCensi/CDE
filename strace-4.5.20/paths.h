// mini-library for manipulating file paths on UNIX-like systems
// by Philip Guo

#ifndef _PATHS_H
#define _PATHS_H

#include <limits.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>

//#define _GNU_SOURCE // for vasprintf (now we include _GNU_SOURCE in Makefile)
#include <stdio.h>


// quick check for whether a path is absolute
#define IS_ABSPATH(p) ((p) && p[0] == '/')

// to shut up gcc warnings without going thru #include hell
extern char* basename(const char *fname);
extern char *dirname(char *path);

char* format(const char *format, ...);


char* realpath_strdup(char* filename);
char* readlink_strdup(char* filename);

char* realpath_nofollow_DEPRECATED(char* filename, char* relative_path_basedir);

int file_is_within_dir(char* filename, char* target_dir, char* relative_path_basedir);

void mkdir_recursive(char* fullpath, int pop_one);

// adapted from Goanna project

/* A structure to represent paths. */
struct namecomp {
  int len;
  char str[0];
};

struct path {
  int stacksize; // num elts in stack
  int depth;     // actual depth of path (smaller than stacksize)
  int is_abspath; // 1 if this represents an absolute path, 0 otherwise
  struct namecomp **stack;
};


char* canonicalize_abspath(char* abspath);
char* canonicalize_relpath(char* relpath, char* base);
char* canonicalize_path(char* path, char* relpath_base);

struct path* new_path_from_abspath(char* path);
struct path* new_path_from_relpath(char* relpath, char* base);

char* path2str(struct path* path, int depth);
void delete_path(struct path *path);


#endif // _PATHS_H
