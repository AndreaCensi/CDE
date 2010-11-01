import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/cde.environment')

generic_test_runner(["./hello-world-static"], checker_func, skip_generic_lib_checks=True)
