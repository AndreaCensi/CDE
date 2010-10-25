import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/tmp/hello.txt')

generic_test_runner(["python", "chdir_test.py"], checker_func)
