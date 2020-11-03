#!/bin/sh

umount /mnt/pmem
rmmod nova
insmod nova.ko measure_timing=0

sleep 1

mount -t NOVA -o init -o wprotect /dev/pmem0 /mnt/pmem