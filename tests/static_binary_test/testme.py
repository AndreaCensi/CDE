import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/static_binary_test/hello-world-static')

generic_test_runner(["./hello-world-static"], checker_func, skip_generic_lib_checks=True)

# run with an ABSOLUTE PATH to make for a harsher test
generic_test_runner(["/home/pgbovine/CDE/tests/static_binary_test/hello-world-static"], checker_func, skip_generic_lib_checks=True)

