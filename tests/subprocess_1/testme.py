import sys
sys.path.insert(0, '..')
from cde_test_common import *

clear_cde_root()

(stdout, stderr) = Popen([CDE_BIN, "python", "subprocess_test.py"], stdout=PIPE, stderr=PIPE).communicate()
if stderr: print "stderr:", stderr

assert os.path.isdir('cde-root/home/pgbovine/epd-6.2-2-rh5-x86/lib/python2.6/site-packages/numpy')
assert os.path.isdir('cde-root/home/pgbovine/epd-6.2-2-rh5-x86/lib/python2.6/site-packages/scipy')
generic_lib_checks()
