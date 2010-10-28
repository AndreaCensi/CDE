import os

print os.getcwd()

os.chdir('../')
os.system('./hello-world-parent-dir')

os.chdir('../../')
os.system('echo hello')

os.chdir('/home/pgbovine')
os.system('echo hello')
