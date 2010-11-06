import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/bin/uname')

generic_test_runner(["./uname_test.sh"], checker_func)
