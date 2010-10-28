import os

os.chdir('../')
print 'getcwd:', os.getcwd()
os.system('./hello-world-parent-dir')

os.chdir('../../')
print 'getcwd:', os.getcwd()
os.system('echo hello')

os.chdir('/home/pgbovine')
print 'getcwd:', os.getcwd()
os.system('echo hello')

