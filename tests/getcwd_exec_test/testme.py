import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/test_file.txt')

generic_test_runner(["python", "getcwd_exec_test.py"], checker_func)
