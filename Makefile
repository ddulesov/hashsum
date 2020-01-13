all: hashsum

#DEFINES=-D_DEBUG 
DEFINES=
CXXFLAGS= -g0 -Wall -Wl,--gc-sections  -O2 -std=c++17 
CFLAGS= -g0 -Wall -Wl,--gc-sections  -O2 -std=c11 
#-fsanitize=address -g3 -fno-omit-frame-pointer
#  valgrind --tool=drd --show-stack-usage=yes ./hashsum -c check.gost 
hashsum: hashsum.cpp Makefile
	g++ -c -DENABLE_SIMD -DL_ENDIAN $(DEFINES) -march=native $(CXXFLAGS) hashsum.cpp -o hashsum.o
	gcc -c -DENABLE_SIMD -DL_ENDIAN $(DEFINES) -march=native $(CFLAGS) gosthash/gosthash2012.c -o gosthash2012.o	
	gcc -c $(CFLAGS) -march=native  ansi_terminal.c -o ansi_terminal.o	
	gcc -c $(CFLAGS) -march=native  blake3/blake3.c -o blake3.o
	gcc -c $(CFLAGS) -march=native blake3/blake3_portable.c -o blake3_portable.o
	gcc -c $(CFLAGS) -march=native blake3/blake3_dispatch.c -o blake3_dispatch.o	
	gcc -c $(CFLAGS) -mavx2 blake3/blake3_avx2.c -o blake3_avx2.o
	gcc -c $(CFLAGS) -msse4.1 blake3/blake3_sse41.c -o blake3_sse41.o
	gcc -c $(CFLAGS) -mavx512f -mavx512vl blake3/blake3_avx512.c -o blake3_avx512.o

	g++  -pthread  hashsum.o gosthash2012.o ansi_terminal.o blake3_dispatch.o blake3_portable.o blake3.o blake3_avx2.o blake3_sse41.o blake3_avx512.o -o hashsum

gostsum_win: hashsum.cpp
	cl.exe /DENABLE_SIMD /DL_ENDIAN /O2 /EHsc ...
