print "Executing file_io.py"
of = open('outfile.txt', 'w')
for line in open('infile.txt'):
  print line,
  of.write(line)

