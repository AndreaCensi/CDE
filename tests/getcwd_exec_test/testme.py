import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/test_file.txt')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/getcwd_exec_test/getcwd_exec_test.py')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/getcwd_exec_test/hello.txt')

generic_test_runner(["python", "getcwd_exec_test.py"], checker_func)
