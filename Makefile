# sudo apt-get install libpcap-dev

BUILD_DIR := build

update:
	@ make -C ${BUILD_DIR}

all: clean
	@ mkdir -p $(BUILD_DIR)
	@ cd $(BUILD_DIR) && cmake .. && make

clean:
	@ rm $(BUILD_DIR) -rf
