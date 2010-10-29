# Test to make sure the coreutils pwd program prints out the right thing
# even when we move the CDE package to another directory

# weird that pwd doesn't do the right thing when you move directories
# ... it seems to truncate the buffer to near the ACTUAL pwd size

import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/bin/pwd')

generic_test_runner(["pwd"], checker_func)
