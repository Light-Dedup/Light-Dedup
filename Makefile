#
# Makefile for the linux NOVA filesystem routines.
#

obj-m += nova.o

nova-y := balloc.o bbuild.o checksum.o dax.o dir.o file.o gc.o inode.o ioctl.o \
	journal.o log.o mprotect.o namei.o parity.o rebuild.o snapshot.o stats.o \
	super.o symlink.o sysfs.o perf.o nova_def.o meta.o table.o entry.o faststr.o \
	multithread.o xatable.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=`pwd` clean