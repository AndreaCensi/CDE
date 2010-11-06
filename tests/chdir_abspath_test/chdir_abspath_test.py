# do a chdir into an absolute path and also getcwd

import os

os.chdir('/home/pgbovine')
f = open('tmp.txt', 'w')
f.close()
print 'getcwd:', os.getcwd()

