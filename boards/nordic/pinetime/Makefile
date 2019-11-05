# Makefile for building the tock kernel for the nRF52 development kit

TOCK_ARCH=cortex-m4
TARGET=thumbv7em-none-eabi
PLATFORM=nrf52dk

include ../../Makefile.common

# TOCKLOADER=tockloader
#
# # Where in the nrf52 flash to load the kernel with `tockloader`
# KERNEL_ADDRESS=0x00000
#
# # Upload programs over uart with tockloader
# ifdef PORT
#   TOCKLOADER_GENERAL_FLAGS += --port $(PORT)
# endif
#
# TOCKLOADER_JTAG_FLAGS = --jlink --board nrf52dk
#
# # Upload the kernel over JTAG
# .PHONY: flash
# flash: target/$(TARGET)/release/$(PLATFORM).bin
# 	$(TOCKLOADER) $(TOCKLOADER_GENERAL_FLAGS) flash --address $(KERNEL_ADDRESS) $(TOCKLOADER_JTAG_FLAGS) $<
#
# # Upload the kernel over serial/bootloader
# .PHONY: program
# program: target/$(TARGET)/release/$(PLATFORM).hex
# 	$(error Cannot program nRF52DK over USB. Use \`make flash\` and JTAG)

OPENOCD=openocd
OPENOCD_OPTIONS=-f openocd.cfg

# OpenOCD requires fullpath
CWD=$(shell pwd)

# sudo is needed for libusb access to work properly

.PHONY: flash-debug
flash-debug: target/$(TARGET)/debug/$(PLATFORM).elf
	sudo $(OPENOCD) $(OPENOCD_OPTIONS) -c "init; reset halt; flash write_image erase $(CWD)/$<; verify_image $(CWD)/$<; reset; shutdown"

.PHONY: flash
flash: target/$(TARGET)/release/$(PLATFORM).elf
	sudo $(OPENOCD) $(OPENOCD_OPTIONS) -c "init; reset halt; flash write_image erase $(CWD)/$<; verify_image $(CWD)/$<; reset; shutdown"

.PHONY: program
program: target/$(TARGET)/debug/$(PLATFORM).elf
	$(error See README.md and update this section accordingly)
