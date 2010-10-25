import sys
sys.path.insert(0, '..')
from cde_test_common import *

clear_cde_root()

(stdout, stderr) = Popen([CDE_BIN, "python", "rmdir_test.py"], stdout=PIPE, stderr=PIPE).communicate()
if stderr: print "stderr:", stderr

assert os.path.isdir('cde-root/tmp/guinea-pig-dir')
assert not os.path.isdir('cde-root/tmp/guinea-pig-dir/guinea-pig-subdir')

