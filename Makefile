MODULE_NAME := packet_filter
BUILD_DIR := build

obj-m += $(MODULE_NAME).o
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
USER_APP_SRC := userapp.c
USER_APP_BIN := $(BUILD_DIR)/userapp
CC ?= gcc

all: build_dir kernel_module user_app

build_dir:
	mkdir -p $(BUILD_DIR)

kernel_module:
	make -C $(KERNEL_DIR) M=$(PWD) modules

user_app:
	$(CC) $(USER_APP_SRC) -o $(USER_APP_BIN) -Wall -Wextra

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm -rf $(BUILD_DIR)
