init: 
	git submodule update --init --recursive
	bash -c "vcpkg/bootstrap-vcpkg.sh" 
rs:
	cd rs && cargo run

cpp:
	cd cpp && make run

.PHONY: rs cpp init