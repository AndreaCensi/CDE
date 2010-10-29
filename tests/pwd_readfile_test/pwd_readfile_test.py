import os

# generate an ABSOLUTE PATH to my-file.txt
f = os.getcwd() + '/my-file.txt'

for line in open(f):
  print line,

