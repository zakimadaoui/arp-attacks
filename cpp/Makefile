
all: build
	cmake -B build && make -C build

run: all
	sudo build/arp_attack

build:
	mkdir -p build


.PHONY: all run