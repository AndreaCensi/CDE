import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/guinea-pig2.txt')

generic_test_runner(["python", "rename.py"], checker_func)
