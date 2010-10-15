CC=gcc -O0 -g -Wall

all: cde cde-exec paths-test

cde-exec: cde-exec.c cde_utils.c cde.h
	$(CC) cde-exec.c cde_utils.c -o cde-exec

cde: cde.c cde_utils.c cde.h
	$(CC) -g cde.c cde_utils.c -o cde

paths-test: paths-test.c cde_utils.c cde.h
	$(CC) -g paths-test.c cde_utils.c -o paths-test

