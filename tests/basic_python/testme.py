import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/home/pgbovine/epd-6.2-2-rh5-x86/bin/python')

generic_test_runner(["python", "file_io.py"], checker_func)
