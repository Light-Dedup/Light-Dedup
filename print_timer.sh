set -e
make
sudo bash setup.sh
cd /mnt/pmem
#sudo fio -filename=./test1 -direct=1 -iodepth 1 -rw=write -ioengine=psync -bs=4K -thread -numjobs=1 -size=2G -name=randrw --dedupe_percentage=100 -group_reporting
sudo fio -filename=./test1 -direct=1 -iodepth 1 -rw=write -ioengine=psync -bs=4K -thread -numjobs=1 -size=4K -name=randrw --dedupe_percentage=80 -group_reporting
#sudo fio -filename=./test1 -direct=1 -iodepth 1 -rw=write -ioengine=psync -bs=4K -thread -numjobs=1 -size=2G -name=randrw --dedupe_percentage=50 -group_reporting
#sudo fio -filename=./test1 -direct=1 -iodepth 1 -rw=write -ioengine=psync -bs=4K -thread -numjobs=1 -size=2G -name=randrw --dedupe_percentage=0 -group_reporting
cd -
#sudo gcc ioctl_test.c -o ioctl_test && sudo ./ioctl_test
#sudo dmesg | tail -n 50
cd -
time sudo rm test1
cd -
sudo umount /mnt/pmem
sudo rmmod nova
