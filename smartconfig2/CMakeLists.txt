add_definitions(-Wall -g -O2)
include_directories(include)
add_executable(smartconfig
	src/smartconfig.c
	src/eloop.c
	src/iface.c
	src/cpack.c
	src/crc32.c
	src/pcap.c)
