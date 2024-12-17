MODULE_NAME := packet_filter
BUILD_DIR := build

KERNEL_SRC := src/packet_filter.c
KERNEL_OBJ := $(MODULE_NAME).o

USER_APP_SRC := src/userapp.c
USER_APP_BIN := $(BUILD_DIR)/userapp

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
CC ?= gcc

EXTRA_CFLAGS := -I$(PWD)/include

USERAPP_CFLAGS := -Iinclude -Wall -Wextra $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
LIBNL_LIBS := $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)

obj-m += $(MODULE_NAME).o

all: build_dir kernel_module user_app

build_dir:
	mkdir -p $(BUILD_DIR)

kernel_module:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules
	mv $(MODULE_NAME).ko $(BUILD_DIR)/

user_app:
	$(CC) $(USER_APP_SRC) -o $(USER_APP_BIN) $(USERAPP_CFLAGS) $(LIBNL_LIBS)

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -rf $(BUILD_DIR)