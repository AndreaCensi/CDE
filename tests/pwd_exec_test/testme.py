import sys
sys.path.insert(0, '..')
from cde_test_common import *

clear_cde_root()

(stdout, stderr) = Popen([CDE_BIN, "./hello-world"], stdout=PIPE, stderr=PIPE).communicate()
if stderr: print "stderr:", stderr
(stdout, stderr) = Popen([CDE_BIN, "../hello-world-parent-dir"], stdout=PIPE, stderr=PIPE).communicate()
if stderr: print "stderr:", stderr

assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/hello-world-parent-dir')
generic_lib_checks()
