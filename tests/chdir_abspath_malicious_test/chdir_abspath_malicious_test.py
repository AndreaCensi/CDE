# make sure we can't escape out of the sandbox with a bunch of '../../'
# relative path references

import os

os.chdir('/..')
print os.getcwd()

os.chdir('/home/pgbovine/../../../../')
print os.getcwd()

