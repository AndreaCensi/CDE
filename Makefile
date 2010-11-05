# really crappy Makefile, which will do for now

all: strace-4.5.20/Makefile
	cd readelf-mini && make
	cd strace-4.5.20 && make
	mv strace-4.5.20/cde .
	mv strace-4.5.20/cde-exec .

strace-4.5.20/Makefile:
	cd strace-4.5.20 && ./configure

