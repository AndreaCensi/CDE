import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/test_file.txt')
  assert os.path.islink('cde-root/home/pgbovine/CDE/tests/test_file.link')
  assert os.readlink('cde-root/home/pgbovine/CDE/tests/test_file.link') == 'test_file.txt'

generic_test_runner(["python", "relative_paths.py"], checker_func)
