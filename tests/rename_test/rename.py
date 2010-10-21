import os

f = open('../guinea-pig.txt', 'w')
f.write('hello world\n')
f.close()

os.rename('../guinea-pig.txt', '../guinea-pig2.txt')

