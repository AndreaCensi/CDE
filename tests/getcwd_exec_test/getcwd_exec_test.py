# also, if you try to MOVE this test to another directory to re-run it,
# does it still work properly?
import os

# create an absolute path that's actually WITHIN our root dir
pwd = os.getcwd()
path = pwd + '/./hello.txt'

for line in open(path):
  print line,


# a harder test, go OUTSIDE of pwd with an ABSOLUTE PATH!!!
# TODO: currently this case does NOT work when you move across machines :(
path2 = pwd + '/../test_file.txt'

for line in open(path2):
  print line,

