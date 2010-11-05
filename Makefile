# really crappy Makefile, which will do for now
#
# make sure to first run ./configure within strace-4.5.20

all:
	cd readelf-mini && make
	cd strace-4.5.20 && make
	cp strace-4.5.20/cde .
	cp strace-4.5.20/cde-exec .
