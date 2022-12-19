#!/bin/sh

if [ ! $1 ]; then
    timing=0
else
    timing=$1
fi
make -j$(nproc)
echo umounting...
sudo umount /mnt/pmem
echo Removing the old kernel module...
sudo rmmod nova
echo Inserting the new kernel module...
sudo insmod nova.ko measure_timing=$timing

sleep 1

echo mounting...
sudo mount -t NOVA -o init -o data_cow /dev/pmem0 /mnt/pmem
#sudo mount -t NOVA -o init /dev/pmem0 /mnt/pmem
