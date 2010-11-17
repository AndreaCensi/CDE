import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/script_exe_test_3/hello-world')

generic_test_runner(["./run_script.py"], checker_func)
