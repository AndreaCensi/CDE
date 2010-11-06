import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/test_file.txt')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/test_file.hardlink')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/link_test/link.py')

generic_test_runner(["python", "link.py"], checker_func)
