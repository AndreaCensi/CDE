import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/tmp/hello.txt')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/chdir_test/chdir_test.py')

generic_test_runner(["python", "chdir_test.py"], checker_func)
