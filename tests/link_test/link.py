import os

if os.path.exists('../test_file.hardlink'):
  os.remove('../test_file.hardlink')
os.link('../test_file.txt', '../test_file.hardlink')

