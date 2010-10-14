CC=gcc -O0 -g

all: cde cde-exec

cde-exec: cde-exec.c cde_utils.c cde.h
	$(CC) cde-exec.c cde_utils.c -o cde-exec

cde: cde.c cde_utils.c cde.h
	$(CC) -g cde.c cde_utils.c -o cde

