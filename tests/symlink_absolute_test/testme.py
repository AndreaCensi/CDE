import sys
sys.path.insert(0, '..')
from cde_test_common import *

clear_cde_root()

(stdout, stderr) = Popen([CDE_BIN, "python", "symlink_absolute_test.py"], stdout=PIPE, stderr=PIPE).communicate()
if stderr: print "stderr:", stderr

assert os.path.isfile('cde-root/home/pgbovine/CDE/tests/test_file.txt')
assert os.path.islink('cde-root/home/pgbovine/CDE/tests/absolute-symlink.test_file.txt')
assert os.readlink('cde-root/home/pgbovine/CDE/tests/absolute-symlink.test_file.txt') == \
                   '../../../../home/pgbovine/CDE/tests/test_file.txt'

