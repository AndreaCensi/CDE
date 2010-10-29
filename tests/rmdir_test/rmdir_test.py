import os

if os.path.isdir('/home/pgbovine/guinea-pig-dir/guinea-pig-subdir'):
  os.rmdir('/home/pgbovine/guinea-pig-dir/guinea-pig-subdir')

if os.path.isdir('/home/pgbovine/guinea-pig-dir'):
  os.rmdir('/home/pgbovine/guinea-pig-dir')

os.mkdir('/home/pgbovine/guinea-pig-dir')
os.mkdir('/home/pgbovine/guinea-pig-dir/guinea-pig-subdir')
os.rmdir('/home/pgbovine/guinea-pig-dir/guinea-pig-subdir')

