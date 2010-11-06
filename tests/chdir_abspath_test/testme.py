import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/tmp.txt')

generic_test_runner(["python", "chdir_abspath_test.py"], checker_func)
