'''

some programs like java are really picky about the EXACT directory
structure being replicated within cde-package.  e.g., java will refuse
to start unless the directory structure is perfectly mimicked (since it
uses its true path to load start-up libraries).  this means that CDE
Needs to be able to potentially traverse through multiple levels of
symlinks and faithfully recreate them within cde-package.

For example, on chongzi (Fedora Core 9):

/usr/bin/java is a symlink to /etc/alternatives/java

but /etc/alternatives/java is itself a symlink to /usr/lib/jvm/jre-1.6.0-openjdk/bin/java

this example involves 2 levels of symlinks, and java requires that the
TRUE binary to be found here in the package in order to run properly:

  /usr/lib/jvm/jre-1.6.0-openjdk/bin/java

'''

import sys
sys.path.insert(0, '..')
from cde_test_common import *

def checker_func():
  assert os.path.islink(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/multiple_symlink_levels/fake-root/usr/bin/java')
  assert os.path.islink(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/multiple_symlink_levels/fake-root/etc/alternatives/java')
  assert os.path.isfile(CDE_ROOT_DIR + '/home/pgbovine/CDE/tests/multiple_symlink_levels/fake-root/usr/lib/jvm/jre-1.6.0-openjdk/bin/java')

generic_test_runner(["cat", "fake-root/usr/bin/java"], checker_func)

