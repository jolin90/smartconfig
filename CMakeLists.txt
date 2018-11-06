aux_source_directory(${PROJECT_SOURCE_DIR}/src SRC_DIR)
set(SRC_LIST  ${SRC_DIR})

include_directories(include)
add_definitions(-Wall -g -O2)
add_executable(smartconfig ${SRC_LIST})

#apt-get install libpcap-dev
target_link_libraries(smartconfig pcap)
target_link_libraries(smartconfig rt)
target_link_libraries(smartconfig pthread)
