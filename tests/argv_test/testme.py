import sys
sys.path.insert(0, '..')
from cde_test_common import *

cde_log_golden = '''cd 'cde-root/home/pgbovine/CDE/tests/argv_test'
'./python.cde' 'print_argv.py' 'one' 'two three' 'four' '5 6'
'''

def checker_func():
  log_contents = open('cde-package/cde.log').read()
  assert log_contents == cde_log_golden

generic_test_runner(["python", "print_argv.py", "one", "two three", "four", "5 6"], checker_func)
