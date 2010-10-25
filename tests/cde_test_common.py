# common utilities for all CDE tests
import os, time
from subprocess import *

CDE_BIN = "/home/pgbovine/CDE/strace-4.5.20/cde"

# careful!!!
def clear_cde_root():
  os.system('rm -rf cde*')
  time.sleep(0.3) # to give os.system some time to work :)

def generic_lib_checks():
  assert os.path.islink('cde-root/lib/libc.so.6')
  assert os.readlink('cde-root/lib/libc.so.6') == 'libc-2.8.so'

