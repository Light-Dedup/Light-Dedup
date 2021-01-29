// ioctl-test.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define NOVA_PRINT_TIMING 0xBCD00010

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
	ret = ioctl(fd, NOVA_PRINT_TIMING, NULL);
	if (ret)
	{
		perror("nova print:");
		exit(-3);
	}

	printf("ended\n");

	return 0;
}
