# Make sure /proc/self/exe returns the actual program name and NOT the
# dynamic linker's name

import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/usr/bin/readlink')

generic_test_runner(["readlink", "/proc/self/exe"], checker_func)
