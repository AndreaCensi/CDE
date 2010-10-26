#include "paths.h"

#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#define assert_EQ(x, y) assert(strcmp(x, y) == 0)

#define USER "philly"
//#define USER "pgbovine"

void test_realpath_nofollow() {
  assert_EQ(realpath_nofollow("CDE", "/home/" USER "/"), "/home/" USER "/CDE");
  assert_EQ(realpath_nofollow("CDE/tests/path-library-test/Makefile", "/home/" USER),
                              "/home/" USER "/CDE/tests/path-library-test/Makefile");
  assert_EQ(realpath_nofollow(".", "/home/" USER "/CDE/tests/"),
                              "/home/" USER "/CDE/tests/.");
}

int main(int argc, char** argv) {
  test_realpath_nofollow();
  return 0;
}

