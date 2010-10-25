import sys
sys.path.insert(0, '..')
from cde_test_common import *

clear_cde_root()

(stdout, stderr) = Popen([CDE_BIN, "./script_exe_test.sh"], stdout=PIPE, stderr=PIPE).communicate()
if stderr: print "stderr:", stderr

assert os.path.isfile('cde-root/bin/sh')
generic_lib_checks()
