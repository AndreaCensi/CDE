import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/pwd_readfile_test/my-file.txt')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/pwd_readfile_test/pwd_readfile_test.py')

generic_test_runner(["python", "pwd_readfile_test.py"], checker_func)
