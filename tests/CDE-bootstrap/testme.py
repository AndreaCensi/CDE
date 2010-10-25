import sys
sys.path.insert(0, '..')
from cde_test_common import *

# customize this test due to special circumstances

CDE_EXEC_SPECIAL = "/home/pgbovine/CDE/strace-4.5.20/cde-exec"

os.system('rm -rf cde-root')
time.sleep(0.3) # to give os.system some time to work :)

Popen(["make", "clean"], stdout=PIPE, stderr=PIPE).communicate()

(stdout, stderr) = run_cde(["make"])

generic_lib_checks()

# TODO: insert more specific checks
assert os.path.isfile('cde-root/usr/bin/gcc')

Popen(["make", "clean"], stdout=PIPE, stderr=PIPE).communicate()

(stdout2, stderr2) = Popen([CDE_EXEC_SPECIAL, "make"], stdout=PIPE, stderr=PIPE).communicate()

assert stdout == stdout2
assert stderr == stderr2
