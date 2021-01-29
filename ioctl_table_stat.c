// ioctl-test.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define NOVA_TABLE_STATS 0xBCD00012

int main(int argc, char **argv)
{

	int fd;
	int ret;

	fd = open("/mnt/pmem/test1", O_RDWR | O_CREAT);
	if (fd < 0)
	{
		perror("open");
		exit(-2);
	}

	/* 初始化设备 */
	ret = ioctl(fd, NOVA_TABLE_STATS, NULL);
	if (ret)
	{
		perror("nova table stats");
		exit(-3);
	}

	printf("ended\n");

	return 0;
}
