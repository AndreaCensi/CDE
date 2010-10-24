import os

if os.path.exists('../test_file.symlink'):
  os.remove('../test_file.symlink')
os.symlink('test_file.txt', '../test_file.symlink')

