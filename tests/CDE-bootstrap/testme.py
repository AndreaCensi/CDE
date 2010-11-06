# copy in all the CDE source code in this directory first before running this test
import sys
sys.path.insert(0, '..')
from cde_test_common import *

# customize this test due to special circumstances

os.system('rm -rf cde-package')
time.sleep(0.3) # to give os.system some time to work :)

Popen(["make", "clean"], stdout=PIPE, stderr=PIPE).communicate()
(first_run_stdout, first_run_stderr) = run_cde(["make"], True)

generic_lib_checks()

# TODO: insert more specific checks
assert os.path.isfile(CDE_ROOT_DIR + '/usr/bin/gcc')
assert os.path.isfile(CDE_ROOT_DIR + '/usr/bin/make')


# to make for a tougher test, move the entire directory to /tmp
# and try to do a cde-exec run
full_pwd = os.getcwd()
cur_dirname = os.path.basename(full_pwd)

tmp_test_rootdir = "/tmp/" + cur_dirname
tmp_test_dir = tmp_test_rootdir + '/cde-package/cde-root/' + full_pwd

try:
  # careful with these commands!
  (stdout, stderr) = Popen(["rm", "-rf", tmp_test_rootdir], stdout=PIPE, stderr=PIPE).communicate()
  assert not stdout and not stderr
  (stdout, stderr) = Popen(["cp", "-aR", full_pwd, "/tmp"], stdout=PIPE, stderr=PIPE).communicate()
  assert not stdout and not stderr

  # run the cde-exec test in tmp_test_dir
  os.chdir(tmp_test_dir)

  Popen(["make", "clean"], stdout=PIPE, stderr=PIPE).communicate()
  (stdout2, stderr2) = Popen([CDE_EXEC, "make"], stdout=PIPE, stderr=PIPE).communicate()

  #print "=== stdout:"
  #print stdout
  #print "=== stdout2:"
  #print stdout2

  #assert first_run_stdout == stdout2
  assert first_run_stderr == stderr2

  os.chdir(full_pwd) # make sure to chdir back!!!

finally:
  #(stdout, stderr) = Popen(["rm", "-rf", tmp_test_rootdir], stdout=PIPE, stderr=PIPE).communicate()
  pass

