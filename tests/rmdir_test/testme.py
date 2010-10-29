import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isdir('cde-root/home/pgbovine/guinea-pig-dir')
  assert not os.path.isdir('cde-root/home/pgbovine/guinea-pig-dir/guinea-pig-subdir')

generic_test_runner(["python", "rmdir_test.py"], checker_func)
