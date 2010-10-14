all: cde cde-exec

cde-exec:
	gcc -O0 -g cde-exec.c cde_utils.c -o cde-exec

cde:
	gcc -O0 -g cde.c cde_utils.c -o cde

