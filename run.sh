#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <ins|rm>"
    exit 1
fi

if [ "$1" == "ins" ]; then
    make
    sudo insmod build/packet_filter.ko
elif [ "$1" == "rm" ]; then
    sudo rmmod packet_filter
    make clean
elif [ "$1" == "ap" ]; then
    ./build/userapp
elif [ "$1" == "dm" ]; then
    dmesg | tail
else
    echo "Invalid argument, check script contents"
    exit 1
fi

