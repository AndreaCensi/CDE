import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/epd-6.2-2-rh5-x86/bin/python')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/basic_python/file_io.py')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/basic_python/infile.txt')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/basic_python/outfile.txt')

generic_test_runner(["python", "file_io.py"], checker_func)
