#!/bin/sh

set -xe

CWD=$(pwd)
RP=$(realpath $0)
DIR=$(dirname $RP)
[ -x ./kavsshwsproxy ] && rm ./kavsshwsproxy

# build libevent
LED="$DIR/libevent/build/lib"
LE1="libevent.a"
LE2="libevent_openssl.a"
if [ ! -r $LED/$LE1 ]; then
	rm -rf $DIR/libevent
	cd $DIR
	git clone https://github.com/libevent/libevent \
		&& cd libevent \
		&& mkdir build \
		&& cd build \
		&& cmake .. \
		&& make
	[ ! -r $LED/$LE1 ] && echo "Can't build libevent" && exit 1
fi

# build libssh2
SSHD="$DIR/libssh2/build/src"
SSH1="libssh2.a"
if [ ! -r $SSHD/$SSH1 ]; then
	rm -rf $DIR/libssh2
	cd $DIR
	git clone https://github.com/libssh2/libssh2 \
		&& cd libssh2 \
		&& mkdir build \
		&& cd build \
		&& cmake .. \
		&& make
	[ ! -r $SSHD/$SSH1 ] && echo "Can't build libssh2" && exit 1
fi
cd $DIR

#GDB="-ggdb"
GDB="-s -O2"

gcc -Wall $GDB -pthread -pedantic \
	-I./libevent/include \
	-I./libssh2/include \
	-o ./kavsshwsproxy kavsshwsproxy.c \
	$LED/$LE1 $LED/$LE2 \
	$SSHD/$SSH1 \
	-lz -lcrypto -lssl

#[ -x ./kavsshwsproxy ] && ./kavsshwsproxy
