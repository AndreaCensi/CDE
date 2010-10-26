// mini-library for manipulating file paths on UNIX-like systems
// by Philip Guo

#ifndef _PATHS_H
#define _PATHS_H

#include <limits.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


char* realpath_strdup(char* filename);
char* readlink_strdup(char* filename);

#endif // _PATHS_H
