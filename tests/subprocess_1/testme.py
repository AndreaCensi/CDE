import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isdir(CDE_ROOT_DIR + '/home/pgbovine/epd-6.2-2-rh5-x86/lib/python2.6/site-packages/numpy')
  assert os.path.isdir(CDE_ROOT_DIR + '/home/pgbovine/epd-6.2-2-rh5-x86/lib/python2.6/site-packages/scipy')

generic_test_runner(["python", "subprocess_test.py"], checker_func)
