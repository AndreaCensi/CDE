import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isdir(CDE_ROOT_DIR + '/home/pgbovine/testdir/')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/mkdir_test/mkdir_test.py')

generic_test_runner(["python", "mkdir_test.py"], checker_func)
