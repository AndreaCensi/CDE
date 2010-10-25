import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/test_file.txt')
  assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/test_file.hardlink')

generic_test_runner(["python", "link.py"], checker_func)
