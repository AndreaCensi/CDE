import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/hello-world-parent-dir')

generic_test_runner(["../hello-world-parent-dir"], checker_func)
