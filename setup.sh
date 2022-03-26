#!/bin/sh

echo umounting...
umount /mnt/pmem
echo Removing the old kernel module...
rmmod nova
echo Inserting the new kernel module...
insmod nova.ko measure_timing=0

sleep 1

echo mounting...
mount -t NOVA -o init -o wprotect,data_cow /dev/pmem0 /mnt/pmem
#mount -t NOVA -o init -o wprotect /dev/pmem0 /mnt/pmem
#mount -t NOVA -o init /dev/pmem0 /mnt/pmem