// run with Valgrind to confirm no memory leaks

#include "cde.h"

char* paths[] = {
  "/home/pgbovine/CDE/tests/ad-hoc/infile.txt",
  "tests/ad-hoc/infile.txt",
  "infile.txt",
  "file_io.py",
  "/etc/ld.so.cache",
  "/usr/lib/libpython2.5.so.1.0",
  "/lib/libpthread.so.0",
  "/lib/libdl.so.2",
  "/lib/libutil.so.1",
  "/lib/libm.so.6",
  "/lib/libc.so.6",
  "/proc/meminfo",
  "/usr/lib/python2.5/site.py",
  "/usr/lib/python2.5/site.pyc",
  "/usr/lib/python2.5/os.py",
  "/usr/lib/python2.5/os.pyc",
  "/usr/lib/python2.5/posixpath.py",
  "/usr/lib/python2.5/posixpath.pyc",
  "/usr/lib/python2.5/stat.py",
  "/usr/lib/python2.5/stat.pyc",
  "/usr/lib/python2.5/UserDict.py",
  "/usr/lib/python2.5/UserDict.pyc",
  "/usr/lib/python2.5/copy_reg.py",
  "/usr/lib/python2.5/copy_reg.pyc",
  "/usr/lib/python2.5/types.py",
  "/usr/lib/python2.5/types.pyc",
  "/usr/lib/python2.5/site-packages/Numeric.pth",
  "/usr/lib/python2.5/site-packages/PIL.pth",
  "/usr/lib/python2.5/site-packages/Paste-1.6-py2.5-nspkg.pth",
  "/usr/lib/python2.5/new.py",
  "/usr/lib/python2.5/new.pyc",
  "/usr/lib/python2.5/site-packages/pygst.pth",
  "/usr/lib/python2.5/site-packages/pygtk.pth",
  "/usr/lib/python2.5/warnings.py",
  "/usr/lib/python2.5/warnings.pyc",
  "/usr/lib/python2.5/linecache.py",
  "/usr/lib/python2.5/linecache.pyc",
  "/usr/lib/locale/locale-archive",
  "/usr/lib/python2.5/encodings/__init__.py",
  "/usr/lib/python2.5/encodings/__init__.pyc",
  "/usr/lib/python2.5/codecs.py",
  "/usr/lib/python2.5/codecs.pyc",
  "/usr/lib/python2.5/encodings/aliases.py",
  "/usr/lib/python2.5/encodings/aliases.pyc",
  "/usr/lib/python2.5/encodings/utf_8.py",
  "/usr/lib/python2.5/encodings/utf_8.pyc",
  "/usr/lib/dirname with spaces/filename with spaces",
  "/usr/lib/dirname with spaces/and we@#$@# ird chars/utf_8.pyc",
  NULL
};

int main(int argc, char* argv[]) {
  char** p_s = paths;
  while (*p_s) {
    struct path* p = str2path(*p_s);
    char* s_dup = path2str(p);

    printf("%s (%d)\n", s_dup, p->depth);
    assert(strcmp(*p_s, s_dup) == 0);

    free(s_dup);
    delete_path(p);
    p_s++;
  }

  return 0;
}

