# 4.4.1 is a symlink to the 4.4 directory, so make sure CDE properly
# handles that case

import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/fake-root-dir/usr/lib/gcc/i486-linux-gnu/4.4.1/infile.txt')
  assert os.path.islink('cde-root/home/pgbovine/CDE/tests/fake-root-dir/usr/lib/gcc/i486-linux-gnu/4.4.1')
  assert os.readlink('cde-root/home/pgbovine/CDE/tests/fake-root-dir/usr/lib/gcc/i486-linux-gnu/4.4.1') == '4.4'

generic_test_runner(["./directory_symlink_test.sh"], checker_func)
