set -e
make
sudo bash setup.sh
sudo fio -filename=/mnt/pmem/test1 -direct=1 -iodepth 1 -rw=write -ioengine=sync -bs=4K -thread -numjobs=1 -size=3G -name=randrw --dedupe_percentage=0 -group_reporting

#sudo gcc ioctl_test.c -o ioctl_test && sudo ./ioctl_test
#sudo gcc ioctl_table_stat.c -o ioctl_table_stat && sudo ./ioctl_table_stat

#time sudo rm /mnt/pmem/test1

#sudo gcc ioctl_test.c -o ioctl_test && sudo ./ioctl_test
#sudo dmesg | tail -n 50

#sudo umount /mnt/pmem
#sudo rmmod nova
#sudo dmesg | tail -n 50

