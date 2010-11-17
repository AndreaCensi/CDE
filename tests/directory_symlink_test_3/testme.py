import sys
sys.path.insert(0, '..')
from cde_test_common import *

# make sure to preserve existing symlink structure
# test inspired by bug report from Andrea Censi <andrea@cds.caltech.edu>

def checker_func():
  assert os.path.islink(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/directory_symlink_test_3/svn/snp_env')
  assert os.path.isdir(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/directory_symlink_test_3/media/tera/snp_env/deploy/lib/python2.6')

generic_test_runner(["./directory_symlink_test_3.sh"], checker_func)

