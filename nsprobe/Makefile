obj-m += nsprobe2.o

KDIR ?= /opt/ddk/kdir/android17-6.18

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
