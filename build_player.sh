#!/bin/sh

[ -x ./kavsshwsplayer ] && rm ./kavsshwsplayer
#GDB="-ggdb"
GDB="-s -O2"
#VG="valgrind --leak-check=full --show-leak-kinds=all"
VG=""
#LIBPATH="/usr/local/lib"
LIBPATH="/usr/local/lib64"

gcc -Wall $GDB -pthread -pedantic -I/usr/local/include \
	-o ./kavsshwsplayer kavsshwsplayer.c \
	-levent -levent_openssl -L$LIBPATH -lz -lcrypto -lssl -ljson-c

#[ -x ./kavsshwsplayer ] && $VG ./kavsshwsplayer -f
