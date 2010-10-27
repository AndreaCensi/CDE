#include "paths.h"

#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#define assert_EQ(x, y) do { \
  char* _x = x; \
  char* _y = y; \
  if (strcmp(_x, _y) != 0) { \
    printf("DIFF: '%s' '%s'\n", x, y); \
    assert(0); \
  } \
} while (0);


char CDE_exec_mode = 0;

int main(int argc, char** argv) {
  //test_realpath_nofollow();

  char* tmp;

  tmp = canonicalize_abspath("/");
  assert_EQ(tmp, "/");
  free(tmp);

  tmp = canonicalize_abspath("/home////pgbovine/.///../joeblow/hello/world/test.txt");
  assert_EQ(tmp, "/home/joeblow/hello/world/test.txt");
  free(tmp);

  tmp = canonicalize_abspath("/home////pgbovine/.///../joeblow/hello/world/.");
  assert_EQ(tmp, "/home/joeblow/hello/world");
  free(tmp);

  tmp = canonicalize_relpath("CDE/tests", "/home/pgbovine");
  assert_EQ(tmp, "/home/pgbovine/CDE/tests");
  free(tmp);

  tmp = canonicalize_relpath("CDE/tests//poo.txt", "/home/pgbovine");
  assert_EQ(tmp, "/home/pgbovine/CDE/tests/poo.txt");
  free(tmp);

  tmp = canonicalize_relpath("CDE/tests//poo.txt", "/home/pgbovine//../boo");
  assert_EQ(tmp, "/home/boo/CDE/tests/poo.txt");
  free(tmp);

  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/home", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/home/", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/home/boo", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/home/pgbovine/../boo", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/home/boo//CDE/", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/home/boo//CDE/tests", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/poo.txt", "/home/boo//CDE/tests/", NULL));
  assert(file_is_within_dir("/home/boo/CDE/tests/hello/world.txt", "/home/boo/CDE/tests/", NULL));

  assert(!file_is_within_dir("/home/boo/CDE", "/home/boo/CDE/tests/", NULL));
  assert(!file_is_within_dir("/home/boo/CDE", "/home/pgbovine/", NULL));

  assert(file_is_within_dir("CDE", "/home/boo/", "/home/boo/"));
  assert(!file_is_within_dir("CDE", "/home/pgbovine/", "/home/boo/"));
  assert(!file_is_within_dir("CDE.txt", "/home/pgbovine/CDE", "/home/pgbovine/"));
  assert(file_is_within_dir("CDE//hello.txt", "/home/pgbovine/CDE", "/home/pgbovine/"));

  // subtle ... if you do a simple substring comparison, you will get these wrong!
  assert(!file_is_within_dir("/home/pgbovine/hello.txt", "/home/pgbovine/hello", NULL));
  assert(!file_is_within_dir("CDE//hello.txt", "/home/pgbovine/CDE/hello", "/home/pgbovine/"));

  return 0;
}

