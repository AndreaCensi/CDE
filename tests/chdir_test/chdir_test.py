import os

os.chdir('/tmp/')
f = open('hello.txt', 'w')
f.write('hello')
f.close()

print 'pwd is', os.getcwd()
