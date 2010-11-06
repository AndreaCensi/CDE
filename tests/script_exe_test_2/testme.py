import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile(CDE_ROOT_DIR + '/bin/env')
  assert os.path.islink(CDE_ROOT_DIR + '/usr/bin/env')
  assert os.readlink(CDE_ROOT_DIR + '/usr/bin/env') == '../../bin/env' # make sure it's a RELATIVE PATH symlink!

generic_test_runner(["./run_python_script.py"], checker_func)
