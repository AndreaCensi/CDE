import os

try:
  os.mkdir('/tmp/testdir')
except OSError:
  pass

