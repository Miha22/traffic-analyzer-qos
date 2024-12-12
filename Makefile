MODULE_NAME := packet_filter
BUILD_DIR := build

obj-m += ../packet_filter.o
all:
	mkdir -p $(BUILD_DIR)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
