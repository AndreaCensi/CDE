# Test to make sure the coreutils pwd program prints out the right thing
# even when we move the CDE package to another directory

# weird that pwd doesn't do the right thing when you move directories
# ... it seems to truncate the buffer to near the ACTUAL pwd size

# coreutils pwd doesn't actually use the getcwd syscall ... instead it
# does its own thang so we might be hosed
# http://www.google.com/codesearch/p?hl=en#g6W0qk4jBZE/src/bin/coreutils/src/pwd.c&q=pwd.c%20coreutils&sa=N&cd=1&ct=rc

import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/bin/pwd')

generic_test_runner(["pwd"], checker_func)
