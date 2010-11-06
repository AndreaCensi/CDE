import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/test_file.txt')
  assert os.path.islink(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/absolute-symlink.test_file.txt')
  assert os.readlink(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/absolute-symlink.test_file.txt') == \
                     '../../../../home/pgbovine/CDE/tests/test_file.txt'

generic_test_runner(["python", "symlink_absolute_test.py"], checker_func)
