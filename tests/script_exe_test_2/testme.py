import sys
sys.path.insert(0, '..')
from cde_test_common import *

clear_cde_root()

(stdout, stderr) = Popen([CDE_BIN, "./run_python_script.py"], stdout=PIPE, stderr=PIPE).communicate()
if stderr: print "stderr:", stderr

assert os.path.isfile('cde-root/bin/env')
assert os.path.islink('cde-root/usr/bin/env')
assert os.readlink('cde-root/usr/bin/env') == '../../bin/env' # make sure it's a RELATIVE PATH symlink!
generic_lib_checks()
