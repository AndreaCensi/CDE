import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  #assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/test_file.hardlink')
  pass

generic_test_runner(["python", "pwd_readfile_test.py"], checker_func)
