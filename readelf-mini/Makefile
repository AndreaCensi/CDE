%.o : %.c	
	gcc -c -Iinclude -Wall -g -O2 $< -o $@

libreadelf-mini.a: readelf-mini.o version.o unwind-ia64.o dwarf.o
	ar rcs libreadelf-mini.a readelf-mini.o version.o unwind-ia64.o dwarf.o

all: libreadelf-mini.a

clean:
	rm libreadelf-mini.a *.o
