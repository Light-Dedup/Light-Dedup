#!/bin/sh

if [ ! $1 ]; then
    timing=0
else
    timing=$1
fi

sleep 5

echo umounting...
umount /mnt/pmem0
echo Removing the old kernel module...
rmmod nova
echo Inserting the new kernel module...
insmod nova.ko measure_timing=$timing

sleep 1

echo mounting...
mount -t NOVA -o init -o wprotect,data_cow /dev/pmem0 /mnt/pmem0
#mount -t NOVA -o init -o wprotect /dev/pmem0 /mnt/pmem0
#mount -t NOVA -o init /dev/pmem0 /mnt/pmem0
