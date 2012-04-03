#!/bin/sh

export CLASSPATH=../lib/bcprov-jdk15on-147.jar:.
export USAGE="Usage: $0 [install | atm <atm#> <host> | bank]"

if [ "$1" = "install" ]; then
    cd ./src
    make
    mv *class ../bin
elif [ "$1" = "atm" ]; then
    if [ 3 -eq $# ]; then
	cd ./bin
	java ATMClient $2 $3
    else
	echo $USAGE
    fi
elif [ "$1" = "bank" ]; then
    cd ./bin
    java BankServer
else
    echo $USAGE
fi