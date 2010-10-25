# common utilities for all CDE tests
import os, time
from subprocess import *

CDE_BIN = "/home/pgbovine/CDE/strace-4.5.20/cde"
CDE_EXEC = "./cde-exec"

# careful!!!
def clear_cde_root():
  os.system('rm -rf cde*')
  time.sleep(0.3) # to give os.system some time to work :)

def generic_lib_checks():
  assert os.path.islink('cde-root/lib/libc.so.6')
  assert os.readlink('cde-root/lib/libc.so.6') == 'libc-2.8.so'

def run_cde(argv):
  (stdout, stderr) = Popen([CDE_BIN] + argv, stdout=PIPE, stderr=PIPE).communicate()
  if stderr: 
    print "stderr:", stderr
  return (stdout, stderr)

def run_and_cmp_cde_exec(argv, prev_stdout, prev_stderr):
  (stdout, stderr) = Popen([CDE_EXEC] + argv, stdout=PIPE, stderr=PIPE).communicate()
  assert stdout == prev_stdout
  assert stderr == prev_stderr


def generic_test_runner(argv, checker_func):
  clear_cde_root()
  (stdout, stderr) = run_cde(argv)

  checker_func()

  generic_lib_checks()

  run_and_cmp_cde_exec(argv, stdout, stderr)

