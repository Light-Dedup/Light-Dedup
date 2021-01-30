#!/bin/sh

echo umounting...
time umount /mnt/pmem

echo remounting...
#mount -t NOVA -o wprotect,data_cow /dev/pmem0 /mnt/pmem
time mount -t NOVA -o wprotect /dev/pmem0 /mnt/pmem
# ./ioctl_test
