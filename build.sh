#!/bin/sh

[ -x ./kavsshwsproxy ] && rm ./kavsshwsproxy
#LIBSSH2=$(pkg-config libssh2 --cflags --libs)
LIBSSH2="-lssh2 -lcrypto -lssl"
#GDB="-ggdb"
GDB="-s -O2"
#LIBPATH="/usr/local/lib"
LIBPATH="/usr/local/lib64"

gcc -Wall $GDB -pthread -pedantic -I/usr/local/include \
	-o ./kavsshwsproxy kavsshwsproxy.c \
	-L$LIBPATH -lz -levent -levent_openssl $LIBSSH2

#[ -x ./kavsshwsproxy ] && ./kavsshwsproxy
