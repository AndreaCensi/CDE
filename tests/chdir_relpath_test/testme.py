import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  pass

generic_test_runner(["python", "chdir_relpath_test.py"], checker_func)
