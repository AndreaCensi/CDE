import os

if os.path.isdir('/tmp/guinea-pig-dir/guinea-pig-subdir'):
  os.rmdir('/tmp/guinea-pig-dir/guinea-pig-subdir')

if os.path.isdir('/tmp/guinea-pig-dir'):
  os.rmdir('/tmp/guinea-pig-dir')

os.mkdir('/tmp/guinea-pig-dir')
os.mkdir('/tmp/guinea-pig-dir/guinea-pig-subdir')
os.rmdir('/tmp/guinea-pig-dir/guinea-pig-subdir')

