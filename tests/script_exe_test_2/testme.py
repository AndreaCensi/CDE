import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.isfile('cde-root/bin/env')
  assert os.path.islink('cde-root/usr/bin/env')
  assert os.readlink('cde-root/usr/bin/env') == '../../bin/env' # make sure it's a RELATIVE PATH symlink!

generic_test_runner(["./run_python_script.py"], checker_func)
