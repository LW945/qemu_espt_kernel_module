obj-m += module_test.o
SYMBOLA=/lib/modules/5.4.0-1025-aws/build/Module.symvers
KBUILD_EXTRA_SYMBOLS= $(SYMBOLA)

all:
	make -C /lib/modules/$(shell uname -r)/build $(KBUILD_EXTRA_SYMBOLS) M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
