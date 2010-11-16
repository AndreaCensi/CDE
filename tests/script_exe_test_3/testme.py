import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/epd-6.2-2-rh5-x86/bin/python')

generic_test_runner(["./run_python_script.py"], checker_func)
