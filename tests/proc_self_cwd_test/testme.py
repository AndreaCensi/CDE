# Make sure /proc/self/cwd returns the same program path on both the
# original and subsequent runs

import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  pass

generic_test_runner(["./proc_self_cwd_test.sh"], checker_func)
