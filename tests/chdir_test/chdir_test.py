import os

os.chdir('/tmp/')
f = open('hello.txt', 'w')
f.write('hello')
f.close()

f = open('hello.txt', 'r')
print f.read()
f.close()

