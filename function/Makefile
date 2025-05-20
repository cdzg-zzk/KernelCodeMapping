obj-m += test_fun.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNELDIR) M=$(PWD) modules
clean:
	sudo rmmod test_fun
	make -C $(KERNELDIR) M=$(PWD) clean
update:
	@echo "Checking if 'test_fun' module is loaded..."
	@if sudo lsmod | grep -q test_fun; then \
		echo "Module 'test_fun' is loaded, removing test_fun..."; \
		sudo rmmod test_fun; \
	fi
	@echo "Running make..."
	make
	@echo "Inserting test_fun module..."
	sudo insmod test_fun.ko
	# sudo ./gdb_disasseble.sh kmalloc_mapping
	# sudo objdump -d -r  kmalloc_mapping.ko > disassemble.txt