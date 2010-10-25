import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isdir('cde-root/tmp/testdir/')

generic_test_runner(["python", "mkdir_test.py"], checker_func)
