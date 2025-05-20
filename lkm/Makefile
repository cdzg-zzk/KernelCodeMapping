obj-m += kmalloc_mapping.o

all:
	make -C  /lib/modules/$(shell uname -r)/build M=$(PWD) modules CFLAGS="-fno-inline -g"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
#!/bin/bash
update:
	@echo "Checking if 'mapping' module is loaded..."
	@if sudo lsmod | grep -q mapping; then \
		echo "Module 'mapping' is loaded, removing kmalloc_mapping..."; \
		sudo rmmod kmalloc_mapping; \
	fi
	@echo "Running make..."
	make
	@echo "Inserting kmalloc_mapping module..."
	sudo insmod kmalloc_mapping.ko
	sudo ../disassemble/gdb_disasseble.sh kmalloc_mapping
	sudo objdump -d -r  kmalloc_mapping.ko > ../disassemble/disassemble.txt