# common utilities for all CDE tests
import os, time
from subprocess import *

CDE_BIN  = "/home/pgbovine/CDE/cde"
CDE_EXEC = "/home/pgbovine/CDE/cde-exec"

CDE_ROOT_DIR = 'cde-package/cde-root'

# careful!!!
def clear_cde_root():
  os.system('rm -rf cde-package')
  time.sleep(0.3) # to give os.system some time to work :)

def generic_lib_checks():
  assert os.path.islink('cde-package/cde-root/lib/libc.so.6')
  assert os.readlink('cde-package/cde-root/lib/libc.so.6') == 'libc-2.8.so'
  assert os.path.isfile('cde-package/cde-root/lib/ld-linux.so.2')

def run_cde(argv, silent=False):
  (stdout, stderr) = Popen([CDE_BIN] + argv, stdout=PIPE, stderr=PIPE).communicate()
  if not silent:
    if stderr: 
      print "stderr:", stderr
  return (stdout, stderr)

def run_and_cmp_cde_exec(argv, prev_stdout, prev_stderr):
  # to make for a tougher test, move the entire cde-package directory to /tmp
  # and try to do a cde-exec run
  full_pwd = os.getcwd()
  full_pwd_renamed = full_pwd + '-renamed'
  cur_dirname = os.path.basename(full_pwd)

  tmp_test_rootdir = "/tmp/" + cur_dirname
  tmp_test_dir = tmp_test_rootdir + '/cde-package/cde-root/' + full_pwd

  # careful with these commands! use 'finally' to clean up even after
  # exceptions!
  try:
    (stdout, stderr) = Popen(["rm", "-rf", tmp_test_rootdir], stdout=PIPE, stderr=PIPE).communicate()
    assert not stdout and not stderr
    (stdout, stderr) = Popen(["cp", "-aR", full_pwd, "/tmp"], stdout=PIPE, stderr=PIPE).communicate()
    assert not stdout and not stderr

    # rename full_pwd to make it impossible for the new version in /tmp
    # to reference already-existing files in full_pwd (a harsher test!)
    try:
      os.rename(full_pwd, full_pwd_renamed)

      # run the cde-exec test in tmp_test_dir
      os.chdir(tmp_test_dir)
      (stdout, stderr) = Popen([CDE_EXEC] + argv, stdout=PIPE, stderr=PIPE).communicate()
      assert stdout == prev_stdout
      assert stderr == prev_stderr

    finally:
      # rename it back to be nice :)
      os.rename(full_pwd_renamed, full_pwd)
      os.chdir(full_pwd) # make sure to chdir back!!!

  finally:
    # remove the version in tmp
    (stdout, stderr) = Popen(["rm", "-rf", tmp_test_rootdir], stdout=PIPE, stderr=PIPE).communicate()


def generic_test_runner(argv, checker_func, skip_generic_lib_checks=False):
  clear_cde_root()
  (stdout, stderr) = run_cde(argv)

  checker_func()

  if not skip_generic_lib_checks:
    generic_lib_checks()

  run_and_cmp_cde_exec(argv, stdout, stderr)

