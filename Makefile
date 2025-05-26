.PHONY: all clean

all:
	mkdir -p build
	cd build && cmake .. && make all_bpf clgctl

clean:
	rm -rf build
