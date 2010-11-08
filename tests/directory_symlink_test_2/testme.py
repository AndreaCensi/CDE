import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isdir(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/fake-root-dir/usr/lib/gcc/')

generic_test_runner(["./directory_symlink_test_2.sh"], checker_func)
