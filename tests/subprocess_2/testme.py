import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/hello-world-parent-dir')

generic_test_runner(["python", "subprocess_2.py"], checker_func)
