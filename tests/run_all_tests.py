# really crappy test runner

import os
from subprocess import *

for e in os.listdir('.'):
  if os.path.isdir(e):
    if os.path.exists(os.path.join(e, 'testme.py')):
      os.chdir(e)
      print "Testing:", os.getcwd()
      (stdout, stderr) = Popen(["python", "testme.py"], stdout=PIPE, stderr=PIPE).communicate()
      if stdout: print "stdout: {", stdout, "}"
      if stderr: print "stderr: {", stderr, "}"

      os.chdir('..')

